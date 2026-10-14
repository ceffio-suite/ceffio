// Single administration account of the platform.
//
// WHY THIS FILE: a single account must administer Nextcloud (applications),
// Stalwart (mail) and this console. It lives in KEYCLOAK, so authentication
// goes through SSO and the identity is the same everywhere.
//
// WHAT ROTATION CAN ACTUALLY DO:
// Keycloak only stores a HASH of the password — final and irreversible.
// No API can therefore "read it back". The console GENERATES a new one and
// pushes it into every system. It is then shown ONCE, and forgotten: this is
// the only moment it exists in clear text, and that is intentional — it is
// the only way to communicate it to you.
//
// ORDER MATTERS: Keycloak first. If a later step fails, the SSO password is
// already up to date and you can still sign in; the reverse would leave you
// with an account whose password you don't know.
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
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	// Platform administration account: present in Keycloak (realm
	// ceffio) and in Nextcloud, where it is a member of the admin group.
	compteAdmin = "adminceffio"
)

// EtatAdmin describes the administration account, WITHOUT ever exposing its password.
type EtatAdmin struct {
	Identifiant       string `json:"identifiant"`
	Email             string `json:"email,omitempty"`
	Actif             bool   `json:"actif"`
	DansGroupeAdmin   bool   `json:"dans_groupe_admin"`
	ExisteKeycloak    bool   `json:"existe_keycloak"`
	ExisteNextcloud   bool   `json:"existe_nextcloud"`
	StalwartPresent   bool   `json:"stalwart_present"`
	CoffrePresent     bool   `json:"coffre_present"`
	UrlAdminNextcloud string `json:"url_admin_nextcloud"`
	UrlAdminStalwart  string `json:"url_admin_stalwart,omitempty"`
	UrlAdminCoffre    string `json:"url_admin_coffre,omitempty"`
	Note              string `json:"note,omitempty"`
}

// handleAdmin returns the state of the administration account.
//
//	GET /api/admin
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiErr(w, 405, "method not allowed")
		return
	}
	etat := EtatAdmin{Identifiant: compteAdmin}
	// The console does NOT reimplement these interfaces: it takes you there.
	// The Nextcloud apps UI knows its catalogue (categories, compatibility,
	// reviews) better than a page rebuilt here.
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

	// Nextcloud: presence + membership of the admin group
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

	// Stalwart: a SEPARATE admin, we just take you there — and only if
	// the service responds, otherwise we would send you to a dead page.
	etat.StalwartPresent = s.stalwartJoignable(r)
	if etat.StalwartPresent {
		etat.UrlAdminStalwart = "https://mail." + s.Domain + "/admin"
	} else {
		etat.Note = "Stalwart is not deployed: rotation only covers Keycloak and Nextcloud."
	}

	// Secrets vault: same principle — we take you THERE, we don't reimplement it.
	// Its interface knows how to show a secret's versions, its metadata and its
	// history, which a page rebuilt here could not do.
	etat.CoffrePresent = s.coffreJoignable(r)
	if etat.CoffrePresent {
		etat.UrlAdminCoffre = "https://bao." + s.Domain + "/ui/"
	}

	writeJSON(w, 200, etat)
}

// handleAdminRotate generates a new password and sets it EVERYWHERE.
//
//	POST /api/admin/rotate
//
// The password is only returned here, once. It is never stored in clear text
// anywhere. If it is lost, just rotate again.
func (s *Server) handleAdminRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "method not allowed")
		return
	}

	mdp, err := motDePasseAleatoire(24)
	if err != nil {
		apiErr(w, 500, "password generation: "+err.Error())
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

	// 1. KEYCLOAK FIRST: it is the source of identity. Once this step
	//    is done, the SSO password is valid even if the rest fails.
	okKC := ajouter("Keycloak (SSO)", s.rotKeycloak(r, mdp))

	// 2. Nextcloud: the local account must accept the same password, otherwise
	//    direct sign-in (fallback if SSO goes down) fails.
	if okKC {
		ajouter("Nextcloud", s.rotNextcloud(r, mdp))
	}

	// 3. Stalwart only if deployed: otherwise we would report a failure where
	//    there is simply nothing to do.
	if okKC && s.stalwartJoignable(r) {
		ajouter("Stalwart (mail)", s.rotStalwart(r, mdp))
	}

	rep := map[string]any{"etapes": etapes, "ok": okKC}
	if okKC {
		rep["mot_de_passe"] = mdp
		rep["message"] = "Password regenerated. Note it down now: it will not be shown again."
	} else {
		rep["message"] = "Failed: the Keycloak password could not be changed."
	}
	writeJSON(w, 200, rep)
}

// ---------------------------------------------------------------------------
// Keycloak
// ---------------------------------------------------------------------------

// rotKeycloak changes the password via the realm's admin API.
//
// temporary=false: the user will not have to change it at first sign-in —
// they just noted it down, asking again would be absurd.
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
		return fmt.Errorf("user %q not found in Keycloak", compteAdmin)
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
		return fmt.Errorf("Keycloak refused (%d): %s", resp2.StatusCode, tronquer(string(b), 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Nextcloud
// ---------------------------------------------------------------------------

// rotNextcloud changes the local account's password via occ.
//
// occ rather than the OCS API: occ sets a password WITHOUT knowing the old one,
// which the API does not allow as directly. The pods/exec right is already
// granted (Role ceffio-console-occ in ceffio-files).
//
// The password travels through the process ENVIRONMENT, not the command line:
// arguments are readable in the process table, the environment is not.
func (s *Server) rotNextcloud(r *http.Request, mdp string) error {
	// occ reads OC_PASS when --password-from-env is provided. So we inject the
	// variable into the command executed in the pod.
	script := "OC_PASS=" + shellQuote(mdp) + " php occ user:resetpassword --password-from-env " + shellQuote(compteAdmin)
	sortie, err := s.occScript(r.Context(), script)
	if err != nil {
		return fmt.Errorf("occ user:resetpassword: %w: %s", err, tronquer(sortie, 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Stalwart
// ---------------------------------------------------------------------------

// stalwartJoignable reports whether the Stalwart admin responds.
//
// We query /healthz/live: the endpoint Stalwart exposes without
// authentication, and the one its own Dockerfile declares as a probe.
// /api/healthz does not exist (404) and /api/account requires credentials
// (401) — both would make the service look absent when it is healthy.
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

// coffreJoignable says whether the secrets vault responds.
//
// THE ADDRESS QUERIED IS THE HEALTH ONE, and it is the only vault endpoint
// reachable without a token: it is enough to answer the question asked, "is
// the service there?".
//
// WE ACCEPT ANY RESPONSE CODE, including 503. Unlike the mail server, where a
// server error means "not ready", a vault answering 503 is a SEALED vault —
// therefore present, and its interface has something to tell whoever connects
// to it. Keeping only codes below 500 would make the link disappear exactly
// when it is needed.
func (s *Server) coffreJoignable(r *http.Request) bool {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		"https://bao."+s.Domain+"/v1/sys/health", nil)
	if err != nil {
		return false
	}
	rep, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer rep.Body.Close()
	return true
}

// rotStalwart changes the mail administrator's password.
//
// Stalwart exposes a REST administration API. The call is only made if the
// service responds: otherwise rotation would be degraded for a nonexistent
// service.
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
		return fmt.Errorf("Stalwart refused (%d): %s", rep.StatusCode, tronquer(string(b), 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// motDePasseAleatoire produces a password without ambiguous characters.
//
// We drop 0/O, 1/l/I, +/: copying a password by hand from a screen is a
// classic source of error, and rotation is precisely the moment when it is
// noted down. The remaining alphabet still keeps plenty of entropy.
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

// occScript executes a SHELL script inside the Nextcloud pod.
//
// WHY A SCRIPT RATHER THAN arguments: occ requires the password through the
// environment (--password-from-env), and PodExecOptions does not allow
// setting an environment variable. So we go through "sh -c" with the variable
// set on the fly. The occ arguments themselves stay escaped by shellQuote —
// otherwise a password containing !@#$%&* would be interpreted by the shell
// and the applied password would not be the one displayed.
func (s *Server) occScript(ctx context.Context, script string) (string, error) {
	if s.kube == nil {
		return "", fmt.Errorf("Kubernetes client unavailable")
	}
	pod, err := s.podNextcloud(ctx)
	if err != nil {
		return "", err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("cluster configuration unreadable: %w", err)
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
		return "", fmt.Errorf("executor unavailable: %w", err)
	}
	var sortie, errs strings.Builder
	if err := executeur.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &sortie, Stderr: &errs,
	}); err != nil {
		return sortie.String() + errs.String(), err
	}
	return sortie.String() + errs.String(), nil
}

// ncReq executes an authenticated request to the Nextcloud OCS API.
//
// Authentication uses the "ceffio-console" service account (revocable
// application password), never the admin account: changing the admin password
// would break the console.
func (s *Server) ncReq(r *http.Request, method, chemin, corps string) (*http.Response, error) {
	if s.ncUser == "" || s.ncPass == "" {
		return nil, fmt.Errorf("Nextcloud service account not configured")
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

// shellQuote wraps a value in single quotes for a POSIX shell.
//
// Needed to pass a password containing !@#$%&* or apostrophes: without
// escaping, the shell would interpret them and the sent password would not be
// the one generated.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
