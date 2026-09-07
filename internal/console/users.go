package console

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// KCUser est un utilisateur Keycloak (champs utiles à la console).
type KCUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

var uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// GET /api/users → liste des utilisateurs du realm.
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out, err := runKcadm(r.Context(), "get", "users")
		if err != nil {
			apiErr(w, 502, "kcadm get users: "+err.Error())
			return
		}
		var users []KCUser
		_ = json.Unmarshal([]byte(out), &users)
		writeJSON(w, 200, map[string]any{"users": users})
	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
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

// createUser crée l'utilisateur Keycloak et (si mot de passe fourni) le fige non-temporaire.
func (s *Server) createUser(r *http.Request, username, email, password string) (string, error) {
	args := []string{"create", "users", "-s", "username=" + username, "-s", "enabled=true"}
	if email != "" {
		args = append(args, "-s", "email="+email, "-s", "emailVerified=true")
	}
	out, err := runKcadm(r.Context(), args...)
	if err != nil {
		return "", err
	}
	id := uuidRe.FindString(out)
	if id == "" {
		return "", errUserNoID(out)
	}
	if password != "" {
		cred := `credentials=[{"type":"password","value":"` + password + `","temporary":false}]`
		if _, err := runKcadm(r.Context(), "update", "users/"+id, "-s", cred); err != nil {
			return id, err
		}
	}
	return id, nil
}

// POST /api/users/{id}/deactivate|password
func (s *Server) handleUsersByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/users/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		apiErr(w, 400, "chemin attendu: /api/users/{id}/{action}")
		return
	}
	id, action := parts[0], parts[1]
	if action == "deactivate" && r.Method == http.MethodPost {
		if _, err := runKcadm(r.Context(), "update", "users/"+id, "-s", "enabled=false"); err != nil {
			apiErr(w, 502, "désactivation: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"deactivated": true, "id": id})
		return
	}
	if action == "password" && r.Method == http.MethodPost {
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password == "" {
			apiErr(w, 400, "password requis")
			return
		}
		cred := `credentials=[{"type":"password","value":"` + body.Password + `","temporary":false}]`
		if _, err := runKcadm(r.Context(), "update", "users/"+id, "-s", cred); err != nil {
			apiErr(w, 502, "reset mot de passe: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"passwordUpdated": true, "id": id})
		return
	}
	apiErr(w, 405, "action inconnue")
}

type errWithMsg struct{ msg string }

func (e errWithMsg) Error() string { return e.msg }

func errUserNoID(out string) error {
	return errWithMsg{"création sans id (kcadm ne retourne pas d'uuid): " + out}
}
