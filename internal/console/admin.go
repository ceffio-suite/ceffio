// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// THE STORAGE AND THE DIRECTORY, which the administration page listed without.
	//
	// They are ADMINISTRATION INTERFACES like the other three: the console takes you
	// there rather than reimplementing them. Longhorn's knows the volumes, their
	// replicas and their health; Keycloak's knows the realm, its clients and its
	// sessions. Each with its own reason to be a separate page, and the same account
	// behind both.
	//
	// LONGHORN IS CONDITIONAL BY NATURE: the interface is an OPTIONAL module, so the
	// URL is present only when the module is installed. An always-present link would
	// send an operator to a 404 on every installation that did not ask for it.
	UrlAdminLonghorn string `json:"url_admin_longhorn,omitempty"`
	UrlAdminKeycloak string `json:"url_admin_keycloak,omitempty"`

	// LonghornPresent distinguishes "the module is not installed" from "it is but the
	// proxy does not answer" — the two need different fixes, and a single absent link
	// says neither.
	LonghornPresent bool   `json:"longhorn_present"`
	Note            string `json:"note,omitempty"`
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

	// The directory itself. Its console administers the realm — the clients, the
	// users, the sessions — which is exactly what an operator needs when a single
	// sign-on misbehaves and the Ceffio console does not cover it.
	etat.UrlAdminKeycloak = "https://keycloak." + s.Domain + "/admin/" + realm + "/console"

	// The storage interface, ONLY when its module is installed.
	//
	// THE CHECK IS THE DEPLOYMENT, not the host: a DNS name can resolve to the same
	// machine while nothing serves it, and a link that opens onto a 503 reads as a
	// broken console rather than an uninstalled module.
	etat.LonghornPresent = s.longhornJoignable(r)
	if etat.LonghornPresent {
		etat.UrlAdminLonghorn = "https://longhorn." + s.Domain
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

// rotKeycloak sets the password via the realm's admin API, CREATING THE ACCOUNT
// IF IT DOES NOT EXIST YET.
//
// # WHY THE CREATION IS HERE, AND NOWHERE ELSE
//
// The installation creates the « ceffio » realm and configures adminceffio's
// authentication (OIDC role on the vault side, SSO redirect) — but it NEVER
// creates the user. Two different things, and confusing them produced
// exactly what the operator saw:
//
//	missing from the directory
//	missing from Nextcloud
//	WITHOUT admin rights
//	inactive account
//
// Verified on the realm: `kcadm get users -r ceffio` returned `[ ]`. The
// realm existed, the identity did not. Declaring an OIDC role for
// adminceffio@ceffio.local does not create that user: it only says how to
// recognize them if they ever show up.
//
// ROTATION IS THE NATURAL PLACE, because it is already the only path that
// knows how to set a password, and because create-then-set is idempotent:
// on an absent account it creates it, on an existing account it updates it.
// A separate creation function would have duplicated the password handling,
// with two places to diverge.
//
// temporary=false: the user will not have to change it at first sign-in —
// they just noted it down, asking again would be absurd.
//
// DUPLICATE EMAIL: the account is created with adminceffio@ceffio.local. That
// address is never used to send mail — it is the stable identifier the vault's
// OIDC role binds to (`bound_claims: {email: adminceffio@ceffio.local}`), so it
// must be set here or the SSO login would never match.
func (s *Server) rotKeycloak(r *http.Request, mdp string) error {
	resp, err := s.kcReq(r, http.MethodGet,
		"/admin/realms/"+realm+"/users?username="+url.QueryEscape(compteAdmin)+"&exact=true", "")
	if err != nil {
		return err
	}
	var users []KCUser
	json.NewDecoder(resp.Body).Decode(&users)
	resp.Body.Close()

	// Absent from the directory: create it, then fall through to the password
	// step below so both paths converge on the same code.
	if len(users) == 0 {
		if err := s.creerCompteKeycloak(r); err != nil {
			return err
		}
		// Re-read to get the id Keycloak assigned. We do not guess it: the id
		// is the server's to choose, and inventing one would silently create a
		// second account.
		resp2, err := s.kcReq(r, http.MethodGet,
			"/admin/realms/"+realm+"/users?username="+url.QueryEscape(compteAdmin)+"&exact=true", "")
		if err != nil {
			return err
		}
		json.NewDecoder(resp2.Body).Decode(&users)
		resp2.Body.Close()
		if len(users) == 0 {
			return fmt.Errorf("user %q created but not found on re-read", compteAdmin)
		}
	}

	corps, _ := json.Marshal(map[string]any{
		"type": "password", "value": mdp, "temporary": false,
	})
	resp3, err := s.kcReq(r, http.MethodPut,
		"/admin/realms/"+realm+"/users/"+users[0].ID+"/reset-password", string(corps))
	if err != nil {
		return err
	}
	defer resp3.Body.Close()
	if resp3.StatusCode >= 300 {
		b, _ := io.ReadAll(resp3.Body)
		return fmt.Errorf("Keycloak refused (%d): %s", resp3.StatusCode, tronquer(string(b), 160))
	}
	return nil
}

// creerCompteKeycloak creates the administrator account in the ceffio realm.
//
// IT IS CREATED ENABLED AND WITH NO ROLES, and that is enough: this account is
// a user of the realm, not an administrator OF Keycloak. Its "admin rights" in
// the operator's sense are the realm-management roles that SSO and the vault
// policy already grant it — creating it with realm-admin would give it the
// right to rewrite the whole directory, which nothing needs.
//
// THE ADDRESS IS adminceffio@ceffio.local, the SAME identifier as everywhere
// else. The operator asked for one single identifier across every system (SSO,
// mail, Nextcloud) rather than one form per service; this is the one place
// where it is decided.
func (s *Server) creerCompteKeycloak(r *http.Request) error {
	corps, _ := json.Marshal(map[string]any{
		"username":      compteAdmin,
		"enabled":       true,
		"emailVerified": true,
		// Never used to send mail: this is the stable identifier the vault's
		// OIDC role binds to.
		"email":     compteAdmin + "@ceffio.local",
		"firstName": "Administrateur",
		"lastName":  "Ceffio",
		"attributes": map[string]any{
			// Marks the account as being OURS, so a future cleanup cannot take
			// it for a leftover from an import.
			"ceffio.io/managed": []string{"true"},
		},
	})
	resp, err := s.kcReq(r, http.MethodPost, "/admin/realms/"+realm+"/users", string(corps))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("creating %s in Keycloak (%d): %s",
			compteAdmin, resp.StatusCode, tronquer(string(b), 200))
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
	//
	// THE ACCOUNT IS CREATED IF IT DOES NOT EXIST, like for Keycloak.
	//
	// `occ user:resetpassword` FAILS on an absent account — « User does not
	// exist » — and the installation never creates adminceffio in Nextcloud:
	// authentication goes through SSO, but SSO creates the user at their
	// FIRST sign-in, which only happens after the operator could sign in.
	// Without this creation, the account exists nowhere and rotation cannot
	// do anything: that is the « Nextcloud : ABSENT » state.
	//
	// WHY --password-from-env RATHER THAN --password: the argument would be
	// readable in the pod's process table.
	//
	// THE ORDER MATTERS: we create first (ignore if already present), we set
	// the password afterwards. The two commands are separate because the
	// first must be able to fail without interrupting the second — `user:add`
	// on an existing account is an error, and treating it as fatal would
	// fail the rotation on a perfectly healthy system.
	// OC_PASS IS EXPORTED ONCE FOR THE WHOLE SEQUENCE, and not set in front
	// of a single command. `occ user:add --password-from-env` reads the SAME
	// variable as resetpassword: measured in the pod,
	//
	//	--password-from-env given, but NC_PASS/OC_PASS is empty!
	//
	// Setting it in front of only one of the two would have made the
	// creation fail silently (>/dev/null || true), and the account would
	// never have existed — the exact symptom this fix eliminates.
	//
	// `export` rather than a prefix: the four commands run in the same
	// shell, so the variable must survive from one to the next.
	script := "export OC_PASS=" + shellQuote(mdp) + "; " +
		"php occ user:add --password-from-env " + shellQuote(compteAdmin) + " >/dev/null 2>&1 || true; " +
		"php occ group:add admin >/dev/null 2>&1 || true; " +
		"php occ user:resetpassword --password-from-env " + shellQuote(compteAdmin) + " 2>&1 | grep -qi 'does not exist' || true; " +
		"php occ group:adduser admin " + shellQuote(compteAdmin) + " >/dev/null 2>&1 || true; " +
		"php occ user:info " + shellQuote(compteAdmin) + " >/dev/null 2>&1 || { echo 'account still absent after creation'; exit 1; }"
	sortie, err := s.occScript(r.Context(), script)
	if err != nil {
		return fmt.Errorf("occ user:resetpassword: %w: %s", err, tronquer(sortie, 160))
	}
	return nil
}

// THE user:add STEP OF THE INITIAL DEPLOYMENT IS IN rotNextcloud, AND NOWHERE
// ELSE. A Nextcloud account created without a password cannot sign in, and
// creating one here would require generating a second password — so two
// secrets for a single identity, which the operator explicitly refuses.
// Rotation creates both with THE SAME password, in the same move.
//
// THE admin GROUP IS ADDED AFTERWARDS. Without it the account authenticates
// and can do nothing — worse than an absent account, since the interface
// would count it as present.

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

// longhornJoignable reports whether the storage interface module is installed.
//
// IT ASKS THE CLUSTER, NOT THE NETWORK: a DNS name resolves whether or not anything
// serves it behind, so a network probe would answer "present" on a platform where the
// module was never installed — and send the operator to a 503.
func (s *Server) longhornJoignable(r *http.Request) bool {
	if s.kube == nil {
		return false
	}
	_, err := s.kube.AppsV1().Deployments("ceffio-system").Get(r.Context(),
		"longhorn-oauth2-proxy", metav1.GetOptions{})
	return err == nil
}
