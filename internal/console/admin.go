// Compte administrateur unique de la plateforme.
//
// POURQUOI CE FICHIER : un seul compte doit administrer Nextcloud (applications),
// Stalwart (mail) et cette console. Il vit dans KEYCLOAK, donc l'authentification
// passe par le SSO et l'identité est la même partout.
//
// CE QUE LA ROTATION PEUT VRAIMENT FAIRE :
// Keycloak ne stocke qu'un HACHAGE du mot de passe — définitif, irréversible.
// Aucune API ne peut donc le « relire ». La console en GÉNÈRE un nouveau et le
// pousse dans chaque système. Il est ensuite affiché UNE SEULE FOIS, puis
// oublié : c'est le seul instant où il existe en clair, et c'est voulu — c'est
// la seule façon de te le communiquer.
//
// L'ORDRE COMPTE : Keycloak d'abord. Si une étape suivante échoue, le mot de
// passe SSO est déjà à jour et tu peux te connecter ; l'inverse te laisserait
// avec un compte dont tu ignores le mot de passe.
package console

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/kubernetes/scheme"
)

const (
	// Compte administrateur de la plateforme : présent dans Keycloak (realm
	// ceffio) et dans Nextcloud, où il est membre du groupe admin.
	compteAdmin = "adminceffio"
)

// EtatAdmin décrit le compte administrateur, SANS jamais exposer son mot de passe.
type EtatAdmin struct {
	Identifiant       string `json:"identifiant"`
	Email             string `json:"email,omitempty"`
	Actif             bool   `json:"actif"`
	DansGroupeAdmin   bool   `json:"dans_groupe_admin"`
	ExisteKeycloak    bool   `json:"existe_keycloak"`
	ExisteNextcloud   bool   `json:"existe_nextcloud"`
	StalwartPresent   bool   `json:"stalwart_present"`
	UrlAdminNextcloud string `json:"url_admin_nextcloud"`
	UrlAdminStalwart  string `json:"url_admin_stalwart,omitempty"`
	Note              string `json:"note,omitempty"`
}

// handleAdmin renvoie l'état du compte administrateur.
//
//	GET /api/admin
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiErr(w, 405, "méthode non autorisée")
		return
	}
	etat := EtatAdmin{Identifiant: compteAdmin}
	// La console ne réimplémente PAS ces interfaces : elle y conduit.
	// L'UI des apps de Nextcloud connaît son catalogue (catégories, compatibilité,
	// avis) mieux qu'une page reconstruite ici.
	etat.UrlAdminNextcloud = "https://cloud." + s.Domain + "/settings/apps"

	// Keycloak
	if resp, err := s.kcReq(r, http.MethodGet,
		"/admin/realms/"+realm+"/users?username="+url.QueryEscape(compteAdmin)+"&exact=true", ""); err == nil {
		defer resp.Body.Close()
		var users []map[string]any
		if json.NewDecoder(resp.Body).Decode(&users) == nil && len(users) > 0 {
			etat.ExisteKeycloak = true
			etat.Email, _ = users[0]["email"].(string)
			etat.Actif, _ = users[0]["enabled"].(bool)
		}
	}

	// Nextcloud : présence + appartenance au groupe admin
	if resp, err := s.ncReq(r, http.MethodGet,
		"/ocs/v2.php/cloud/users/"+url.PathEscape(compteAdmin)+"/groups?format=json", ""); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			etat.ExisteNextcloud = true
			var r struct {
				OCS struct {
					Data struct {
						Groups []string `json:"groups"`
					} `json:"data"`
				} `json:"ocs"`
			}
			if json.NewDecoder(resp.Body).Decode(&r) == nil {
				for _, g := range r.OCS.Data.Groups {
					if g == "admin" {
						etat.DansGroupeAdmin = true
					}
				}
			}
		}
	}

	// Stalwart : admin SÉPARÉE, on se contente d'y conduire — et seulement si
	// le service répond, sinon on enverrait vers une page morte.
	etat.StalwartPresent = s.stalwartJoignable(r)
	if etat.StalwartPresent {
		etat.UrlAdminStalwart = "https://mail." + s.Domain + "/admin"
	} else {
		etat.Note = "Stalwart n'est pas déployé : la rotation ne concerne que Keycloak et Nextcloud."
	}

	writeJSON(w, 200, etat)
}

// handleAdminRotate génère un nouveau mot de passe et le pose PARTOUT.
//
//	POST /api/admin/rotate
//
// Le mot de passe n'est renvoyé qu'ici, une seule fois. Il n'est stocké en clair
// nulle part. S'il est perdu, il suffit de refaire une rotation.
func (s *Server) handleAdminRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "méthode non autorisée")
		return
	}

	mdp, err := motDePasseAleatoire(24)
	if err != nil {
		apiErr(w, 500, "génération du mot de passe : "+err.Error())
		return
	}

	type etape struct {
		Systeme string `json:"systeme"`
		Reussi  bool   `json:"reussi"`
		Message string `json:"message,omitempty"`
	}
	var etapes []etape
	ajouter := func(sys string, err error) bool {
		if err != nil {
			etapes = append(etapes, etape{sys, false, err.Error()})
			return false
		}
		etapes = append(etapes, etape{sys, true, ""})
		return true
	}

	// 1. KEYCLOAK EN PREMIER : c'est la source d'identité. Une fois cette étape
	//    passée, le mot de passe SSO est valide même si la suite échoue.
	okKC := ajouter("Keycloak (SSO)", s.rotKeycloak(r, mdp))

	// 2. Nextcloud : le compte local doit accepter le même mot de passe, sinon
	//    la connexion directe (secours si le SSO tombe) échoue.
	if okKC {
		ajouter("Nextcloud", s.rotNextcloud(r, mdp))
	}

	// 3. Stalwart seulement s'il est déployé : sinon on rapporterait un échec là
	//    où il n'y a simplement rien à faire.
	if okKC && s.stalwartJoignable(r) {
		ajouter("Stalwart (mail)", s.rotStalwart(r, mdp))
	}

	rep := map[string]any{"etapes": etapes, "ok": okKC}
	if okKC {
		rep["mot_de_passe"] = mdp
		rep["message"] = "Mot de passe régénéré. Notez-le maintenant : il ne sera plus affiché."
	} else {
		rep["message"] = "Échec : le mot de passe de Keycloak n'a pas pu être changé."
	}
	writeJSON(w, 200, rep)
}

// ---------------------------------------------------------------------------
// Keycloak
// ---------------------------------------------------------------------------

// rotKeycloak change le mot de passe via l'API admin du realm.
//
// temporary=false : l'utilisateur n'aura pas à le changer à la première
// connexion — il vient de le noter, le lui redemander serait absurde.
func (s *Server) rotKeycloak(r *http.Request, mdp string) error {
	resp, err := s.kcReq(r, http.MethodGet,
		"/admin/realms/"+realm+"/users?username="+url.QueryEscape(compteAdmin)+"&exact=true", "")
	if err != nil {
		return err
	}
	var users []KCUser
	json.NewDecoder(resp.Body).Decode(&users)
	resp.Body.Close()
	if len(users) == 0 {
		return fmt.Errorf("utilisateur %q introuvable dans Keycloak", compteAdmin)
	}

	corps, _ := json.Marshal(map[string]any{
		"type": "password", "value": mdp, "temporary": false,
	})
	resp2, err := s.kcReq(r, http.MethodPut,
		"/admin/realms/"+realm+"/users/"+users[0].ID+"/reset-password", string(corps))
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode >= 300 {
		b, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("Keycloak a refusé (%d) : %s", resp2.StatusCode, tronquer(string(b), 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Nextcloud
// ---------------------------------------------------------------------------

// rotNextcloud change le mot de passe du compte local via occ.
//
// occ plutôt que l'API OCS : occ fixe un mot de passe SANS connaître l'ancien,
// ce que l'API n'autorise pas aussi directement. Le droit pods/exec est déjà
// acquis (Role ceffio-console-occ dans ceffio-files).
//
// Le mot de passe passe par l'ENVIRONNEMENT du processus, pas par la ligne de
// commande : les arguments sont lisibles dans la table des processus, pas
// l'environnement.
func (s *Server) rotNextcloud(r *http.Request, mdp string) error {
	// occ lit OC_PASS quand --password-from-env est fourni. On injecte donc la
	// variable dans la commande exécutée dans le pod.
	script := "OC_PASS=" + shellQuote(mdp) + " php occ user:resetpassword --password-from-env " + shellQuote(compteAdmin)
	sortie, err := s.occScript(r.Context(), script)
	if err != nil {
		return fmt.Errorf("occ user:resetpassword : %w: %s", err, tronquer(sortie, 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Stalwart
// ---------------------------------------------------------------------------

// stalwartJoignable indique si l'admin de Stalwart répond.
//
// On interroge /healthz/live : c'est l'endpoint que Stalwart expose sans
// authentification, et celui que son propre Dockerfile déclare comme sonde.
// /api/healthz n'existe pas (404) et /api/account exige des identifiants
// (401) — les deux feraient croire à un service absent alors qu'il est sain.
func (s *Server) stalwartJoignable(r *http.Request) bool {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		"https://mail."+s.Domain+"/healthz/live", nil)
	if err != nil {
		return false
	}
	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer rep.Body.Close()
	return rep.StatusCode < 500
}

// rotStalwart change le mot de passe de l'administrateur du mail.
//
// Stalwart expose une API REST d'administration. L'appel n'est fait que si le
// service répond : sinon on dégraderait la rotation pour un service inexistant.
func (s *Server) rotStalwart(r *http.Request, mdp string) error {
	corps, _ := json.Marshal(map[string]any{"password": mdp})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPatch,
		"https://mail."+s.Domain+"/api/principal/"+compteAdmin, strings.NewReader(string(corps)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer rep.Body.Close()
	if rep.StatusCode >= 300 {
		b, _ := io.ReadAll(rep.Body)
		return fmt.Errorf("Stalwart a refusé (%d) : %s", rep.StatusCode, tronquer(string(b), 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

// motDePasseAleatoire produit un mot de passe sans caractère ambigu.
//
// On écarte 0/O, 1/l/I, +/ : recopier un mot de passe à la main depuis un écran
// est une source d'erreur classique, et la rotation est justement le moment où
// on le note. L'alphabet restant garde largement assez d'entropie.
func motDePasseAleatoire(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"
	out := make([]byte, 0, n)
	for len(out) < n {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		out = append(out, alphabet[int(b[0])%len(alphabet)])
	}
	return string(out), nil
}

// occScript exécute un SCRIPT shell dans le pod Nextcloud.
//
// POURQUOI UN SCRIPT PLUTÔT QUE des arguments : occ exige le mot de passe par
// l'environnement (--password-from-env), et PodExecOptions ne permet pas de
// poser une variable d'environnement. On passe donc par « sh -c » avec la
// variable posée à la volée. Les arguments de occ, eux, restent échappés par
// shellQuote — sans quoi un mot de passe contenant !@#$%&* serait interprété
// par le shell et le mot de passe appliqué ne serait pas celui qu'on affiche.
func (s *Server) occScript(ctx context.Context, script string) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("client Kubernetes indisponible")
	}
	pod, err := s.podNextcloud(ctx)
	if err != nil {
		return "", err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("configuration du cluster illisible : %w", err)
	}
	req := s.kube.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace("ceffio-files").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "nextcloud",
			Command:   []string{"sh", "-c", script},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executeur, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("exécuteur indisponible : %w", err)
	}
	var sortie, errs strings.Builder
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &sortie, Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(), err
	}
	return sortie.String() + errs.String(), nil
}

// ncReq exécute une requête authentifiée vers l'API OCS de Nextcloud.
//
// L'authentification utilise le compte de service « ceffio-console » (mot de
// passe d'application révocable), jamais le compte admin : un changement du
// mot de passe admin casserait la console.
func (s *Server) ncReq(r *http.Request, method, chemin, corps string) (*http.Response, error) {
	if s.ncUser == "" || s.ncPass == "" {
		return nil, fmt.Errorf("compte de service Nextcloud non configuré")
	}
	var lecteur io.Reader
	if corps != "" {
		lecteur = strings.NewReader(corps)
	}
	req, err := http.NewRequestWithContext(r.Context(), method,
		"http://nextcloud.ceffio-files.svc"+chemin, lecteur)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.ncUser, s.ncPass)
	req.Header.Set("OCS-APIRequest", "true")
	if corps != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// shellQuote met une valeur entre apostrophes pour un shell POSIX.
//
// Nécessaire pour transmettre un mot de passe contenant !@#$%&* ou des
// apostrophes : sans échappement, le shell les interpréterait et le mot de
// passe envoyé ne serait pas celui généré.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}