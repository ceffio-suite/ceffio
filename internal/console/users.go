package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KCUser est un utilisateur Keycloak (champs utiles à la console).
type KCUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
	// Protege marque le compte d'administration de la plateforme. L'interface
	// s'en sert pour le SORTIR de la liste des comptes ordinaires : il ne se
	// gère pas comme un utilisateur, il administre.
	Protege bool `json:"protege,omitempty"`
}

// estCompteProtege dit si un identifiant désigne le compte d'administration de
// la plateforme — celui qu'on ne désactive pas et qu'on ne supprime pas.
//
// LA COMPARAISON IGNORE LA CASSE : Keycloak traite « AdminCeffio » et
// « adminceffio » comme le même compte. Comparer à l'identique laisserait
// passer une variante de casse, et la protection serait contournable en
// changeant une majuscule.
func estCompteProtege(identifiant string) bool {
	return strings.EqualFold(strings.TrimSpace(identifiant), compteAdmin)
}

// ---------------------------------------------------------------------------
// Client REST Keycloak Admin (realm master → token ; admin/realms/ceffio).

var (
	kcTokMu   sync.Mutex
	kcToken   string
	kcExpires time.Time
)

// kcToken renvoie un token d'admin valide (realm master, grant password).
func (s *Server) kcToken(r *http.Request) (string, error) {
	kcTokMu.Lock()
	defer kcTokMu.Unlock()
	if kcToken != "" && time.Now().Before(kcExpires.Add(-10*time.Second)) {
		return kcToken, nil
	}
	if s.kcAdmin == "" || s.kcPass == "" {
		return "", fmt.Errorf("credentials admin Keycloak absents (KC_ADMIN/KC_ADMIN_PASSWORD)")
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {s.kcAdmin},
		"password":   {s.kcPass},
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.kcBase+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		Access  string `json:"access_token"`
		Expires int    `json:"expires_in"`
		Error   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Access == "" {
		return "", fmt.Errorf("token Keycloak: %s", tok.Error)
	}
	kcToken, kcExpires = tok.Access, time.Now().Add(time.Duration(tok.Expires)*time.Second)
	return kcToken, nil
}

// kcReq exécute une requête authentifiée vers l'API Keycloak Admin.
func (s *Server) kcReq(r *http.Request, method, path, body string) (*http.Response, error) {
	tok, err := s.kcToken(r)
	if err != nil {
		return nil, err
	}
	var br *strings.Reader
	if body != "" {
		br = strings.NewReader(body)
	} else {
		br = strings.NewReader("")
	}
	req, _ := http.NewRequestWithContext(r.Context(), method, s.kcBase+path, br)
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized { // token expiré → on réessaie une fois
		resp.Body.Close()
		kcTokMu.Lock()
		kcToken = ""
		kcTokMu.Unlock()
		return s.kcReq(r, method, path, body)
	}
	return resp, nil
}

// ListUsers renvoie les comptes du realm, le compte d'administration marqué.
//
// POURQUOI LE MARQUAGE SE FAIT ICI ET PAS DANS L'INTERFACE : le nom du compte
// d'administration est une règle du SERVEUR (c'est lui qui refuse de le
// désactiver). La laisser à la page obligerait à la connaître des deux côtés,
// et le jour où l'une des deux change, l'autre protège un compte qui n'existe
// plus — en silence.
func (s *Server) listUsers(r *http.Request) ([]KCUser, error) {
	resp, err := s.kcReq(r, http.MethodGet, "/admin/realms/"+realm+"/users", "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var users []KCUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Protege = estCompteProtege(users[i].Username)
	}
	return users, nil
}

// ---------------------------------------------------------------------------
// GET /api/users → liste ; POST /api/users → création (mot de passe non-temporaire).

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.listUsers(r)
		if err != nil {
			apiErr(w, 502, "list users: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"users": users})

	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Username) == "" {
			apiErr(w, 400, "username requis")
			return
		}
		id, err := s.createUser(r, body.Username, body.Email, body.Password)
		if err != nil {
			apiErr(w, 502, "création utilisateur: "+err.Error())
			return
		}
		writeJSON(w, 201, map[string]any{"id": id, "username": body.Username, "created": true})

	default:
		apiErr(w, 405, "méthode non supportée")
	}
}

// estUtilisateurProtege dit si l'identifiant envoyé par le client désigne le
// compte d'administration de la plateforme.
//
// ON ACCEPTE DEUX FORMES : le nom (« adminceffio ») et l'id Keycloak (un UUID).
// L'interface envoie l'id, un appel direct pourrait envoyer l'un ou l'autre —
// ne vérifier que le nom laisserait passer l'id, et inversement.
//
// En cas de doute — identifiant inconnu, Keycloak injoignable — on répond NON
// protégé : refuser une action légitime parce qu'une vérification a échoué
// serait aussi gênant que l'inverse, et le contrôle porte sur un compte dont
// l'identifiant se lit d'abord dans la réponse de Keycloak.
func (s *Server) estUtilisateurProtege(r *http.Request, idOuNom string) bool {
	if estCompteProtege(idOuNom) {
		return true
	}
	users, err := s.listUsers(r)
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.ID == idOuNom {
			return estCompteProtege(u.Username)
		}
	}
	return false
}

func (s *Server) createUser(r *http.Request, username, email, password string) (string, error) {
	// ON NE FABRIQUE PAS UN SECOND COMPTE D'ADMINISTRATION par mégarde : le nom
	// est réservé, et une création qui le reprend échouerait sur un conflit peu
	// lisible. Le refus est explicite.
	if estCompteProtege(username) {
		return "", fmt.Errorf("« %s » est réservé au compte d'administration de la plateforme", compteAdmin)
	}
	payload := map[string]any{"username": username, "enabled": true}
	if email != "" {
		payload["email"] = email
		payload["emailVerified"] = true
	}
	b, _ := json.Marshal(payload)
	resp, err := s.kcReq(r, http.MethodPost, "/admin/realms/"+realm+"/users", string(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("l'utilisateur %q existe déjà", username)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Keycloak a répondu %d", resp.StatusCode)
	}
	// L'id est dans l'en-tête Location.
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if password != "" {
		if err := s.setPassword(r, id, password); err != nil {
			return id, err
		}
	}
	return id, nil
}

// setPassword pose un mot de passe non-temporaire à l'utilisateur.
func (s *Server) setPassword(r *http.Request, id, password string) error {
	payload, _ := json.Marshal(map[string]any{"type": "password", "value": password, "temporary": false})
	resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id+"/reset-password", string(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("reset mdp: HTTP %d", resp.StatusCode)
	}
	return nil
}

// POST /api/users/{id}/deactivate|password
func (s *Server) handleUsersByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		apiErr(w, 400, "chemin attendu: /api/users/{id}/{action}")
		return
	}
	id, action := parts[0], parts[1]
	if r.Method != http.MethodPost {
		apiErr(w, 405, "méthode non supportée")
		return
	}

	// LE COMPTE D'ADMINISTRATION N'EST PAS UN UTILISATEUR : on refuse AVANT
	// d'agir, et on le dit. Sans ce contrôle, l'interface pourrait cacher les
	// boutons sans que l'API cesse d'obéir — un appel direct désactiverait le
	// compte administrateur de la plateforme, et plus personne n'administrerait
	// Nextcloud ni le mail.
	//
	// On résout le nom par l'IDENTIFIANT : le client pourrait envoyer l'id
	// Keycloak seul, et comparer l'action au nom n'aurait alors aucun effet.
	if s.estUtilisateurProtege(r, id) {
		apiErr(w, 403, "« "+compteAdmin+" » est le compte d'administration de la plateforme : "+
			"il ne peut être ni désactivé, ni modifié ici. Utilisez la page Administration.")
		return
	}

	switch action {
	case "deactivate":
		payload, _ := json.Marshal(map[string]any{"enabled": false})
		resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id, string(payload))
		if err != nil {
			apiErr(w, 502, "désactivation: "+err.Error())
			return
		}
		resp.Body.Close()
		writeJSON(w, 200, map[string]any{"deactivated": true, "id": id})
	// RÉACTIVER est l'INVERSE de désactiver, et n'existait pas : désactiver un
	// compte par erreur laissait sans recours depuis l'interface, alors que
	// Keycloak n'oublie rien. Une action sans son inverse est une impasse.
	case "reactivate":
		payload, _ := json.Marshal(map[string]any{"enabled": true})
		resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id, string(payload))
		if err != nil {
			apiErr(w, 502, "réactivation: "+err.Error())
			return
		}
		resp.Body.Close()
		writeJSON(w, 200, map[string]any{"reactivated": true, "id": id})
	case "password":
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password == "" {
			apiErr(w, 400, "password requis")
			return
		}
		if err := s.setPassword(r, id, body.Password); err != nil {
			apiErr(w, 502, "reset mot de passe: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"passwordUpdated": true, "id": id})
	default:
		apiErr(w, 405, "action inconnue")
	}
}
