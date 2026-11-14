// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KCUser is a Keycloak user (fields useful to the console).
type KCUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
	// Protege marks the platform administration account. The interface uses it
	// to TAKE it OUT of the list of ordinary accounts: it is not managed like
	// a user, it administers.
	Protege bool `json:"protege,omitempty"`
	// Attributes carries the Keycloak user attributes, so a module can
	// recognize its own users (the mail module writes ceffio_kind=internal and
	// reads it back to tell an internal user from an external one).
	//
	// They are read WITH the list (briefRepresentation=false) rather than in
	// one request per user: the Users page lists every account, and a module
	// asking "is this one of mine?" must not cost a round trip each.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// estCompteProtege says whether an identifier designates the platform
// administration account — the one that is never deactivated and never
// deleted.
//
// THE COMPARISON IGNORES CASE: Keycloak treats "AdminCeffio" and
// "adminceffio" as the same account. Comparing identically would let a case
// variant through, and the protection would be bypassable by changing one
// uppercase letter.
func estCompteProtege(identifiant string) bool {
	return strings.EqualFold(strings.TrimSpace(identifiant), compteAdmin)
}

// ---------------------------------------------------------------------------
// Keycloak Admin REST client (master realm → token ; admin/realms/ceffio).

var (
	kcTokMu   sync.Mutex
	kcToken   string
	kcExpires time.Time
)

// kcToken returns a valid admin token (master realm, password grant).
func (s *Server) kcToken(r *http.Request) (string, error) {
	kcTokMu.Lock()
	defer kcTokMu.Unlock()
	if kcToken != "" && time.Now().Before(kcExpires.Add(-10*time.Second)) {
		return kcToken, nil
	}
	if s.kcAdmin == "" || s.kcPass == "" {
		return "", fmt.Errorf("Keycloak admin credentials missing (KC_ADMIN/KC_ADMIN_PASSWORD)")
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

// kcReq executes an authenticated request to the Keycloak Admin API.
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
	if resp.StatusCode == http.StatusUnauthorized { // expired token → retry once
		resp.Body.Close()
		kcTokMu.Lock()
		kcToken = ""
		kcTokMu.Unlock()
		return s.kcReq(r, method, path, body)
	}
	return resp, nil
}

// listUsers returns the realm accounts, the administration account marked.
//
// WHY THE MARKING HAPPENS HERE AND NOT IN THE INTERFACE: the name of the
// administration account is a SERVER rule (it is what refuses to deactivate
// it). Leaving it to the page would force both sides to know it, and the day
// one of the two changes, the other protects an account that no longer
// exists — silently.
func (s *Server) listUsers(r *http.Request) ([]KCUser, error) {
	// briefRepresentation=false: the attributes a module needs are not part of
	// the brief form, and asking per user would make the page load O(users).
	resp, err := s.kcReq(r, http.MethodGet, "/admin/realms/"+realm+"/users?briefRepresentation=false", "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var bruts []kcUserComplet
	if err := json.NewDecoder(resp.Body).Decode(&bruts); err != nil {
		return nil, err
	}
	users := make([]KCUser, 0, len(bruts))
	for _, b := range bruts {
		users = append(users, KCUser{
			ID: b.ID, Username: b.Username, Email: b.Email, Enabled: b.Enabled,
			Protege:    estCompteProtege(b.Username),
			Attributes: premierAttribut(b.Attributes),
		})
	}
	return users, nil
}

// ---------------------------------------------------------------------------
// GET /api/users → list; POST /api/users → creation (non-temporary password).

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.listUsers(r)
		if err != nil {
			apiErr(w, 502, "list users: "+err.Error())
			return
		}
		// THE PAGE IS SERVED WHAT THE INSTALLED MODULES DECLARE, never a list
		// the console wrote down: a module installed tomorrow adds its fields
		// and its account column without this handler changing.
		champs, comptes, errs := s.comptesPourPage(r.Context(), users)
		reponse := map[string]any{"users": users, "fields": champs, "accounts": comptes}
		if len(errs) > 0 {
			reponse["account_errors"] = errs
		}
		writeJSON(w, 200, reponse)

	case http.MethodPost:
		var body creationUtilisateur
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Username) == "" {
			apiErr(w, 400, "username required")
			return
		}
		// The whole creation, module objects included, lives in
		// users_accounts.go: this handler only decodes and refuses an empty
		// username, so the console keeps ONE creation path whatever the number
		// of modules taking part.
		s.creerUtilisateurCompte(w, r, body)

	default:
		apiErr(w, 405, "method not supported")
	}
}

// estUtilisateurProtege says whether the identifier sent by the client
// designates the platform administration account.
//
// WE ACCEPT TWO FORMS: the name ("adminceffio") and the Keycloak id (a UUID).
// The interface sends the id, a direct call could send either one — checking
// only the name would let the id through, and conversely.
//
// In case of doubt — unknown identifier, unreachable Keycloak — we answer NOT
// protected: refusing a legitimate action because a check failed would be as
// annoying as the opposite, and the check bears on an account whose
// identifier is first read from the Keycloak response.
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
	// WE DO NOT MAKE A SECOND ADMINISTRATION ACCOUNT by mistake: the name is
	// reserved, and a creation reusing it would fail on a conflict that is
	// hard to read. The refusal is explicit.
	if estCompteProtege(username) {
		return "", fmt.Errorf("%q is reserved for the platform administration account", compteAdmin)
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
		// A RETRY OF A CREATION THAT FAILED LATER must finish, not stop on a
		// conflict: the Keycloak account is the FIRST step, so the page's retry
		// after a mailbox failure always finds it. Adopting the account and
		// re-running the idempotent steps is what makes the retry converge —
		// reporting "already exists" would leave the operator with a user and
		// no way to finish it from the page.
		id, err := s.idParNom(r, username)
		if err != nil {
			return "", fmt.Errorf("user %q already exists", username)
		}
		if err := s.creerCompteNextcloud(r.Context(), username, password); err != nil {
			fmt.Printf("  ⚠ %s exists in Keycloak but not in Nextcloud: %v\n", username, err)
		}
		return id, nil
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("Keycloak responded %d", resp.StatusCode)
	}
	// The id is in the Location header.
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if password != "" {
		if err := s.setPassword(r, id, password); err != nil {
			return id, err
		}
	}

	// THE ACCOUNT ALSO EXISTS IN NEXTCLOUD, otherwise it cannot sign in.
	//
	// This function used to create the user ONLY in Keycloak. The operator
	// saw their account on the Users page, SSO authenticated them — then
	// Nextcloud refused, because it had no matching local account.
	//
	// The fallback path follows the same reasoning as for the administrator:
	// SSO is the main door, the local account lets you in when Keycloak is
	// unavailable. An account that only exists on the directory side depends
	// entirely on the directory's availability.
	//
	// NON-BLOCKING, AND REPORTED: the Keycloak account is already created at
	// this stage, and an error on the Nextcloud side must not look like a
	// total failure — the console can retry.
	if err := s.creerCompteNextcloud(r.Context(), username, password); err != nil {
		fmt.Printf("  ⚠ %s created in Keycloak but not in Nextcloud: %v\n", username, err)
	}

	return id, nil
}

// creerCompteNextcloud creates the local account, so it can sign in directly
// when Keycloak is unavailable.
//
// THE IDENTIFIER IS THE SAME AS IN KEYCLOAK, and that is not a detail: the
// Nextcloud SSO is configured to map `preferred_username`, so that is the
// form under which the user will show up. A local account named differently
// would be one account too many, with distinct rights, and the user would
// sign in to one or the other depending on the door taken.
//
// Idempotent: `user:add` on an existing account fails, and that error is
// ignored — it is the desired state on the second call.
func (s *Server) creerCompteNextcloud(ctx context.Context, identifiant, mdp string) error {
	script := "export OC_PASS=" + shellQuote(mdp) + "; " +
		"php occ user:add --password-from-env " + shellQuote(identifiant) + " >/dev/null 2>&1 || true; " +
		"php occ user:info " + shellQuote(identifiant) + " >/dev/null 2>&1 || { echo 'account absent after creation'; exit 1; }"
	sortie, err := executerOcc(s, ctx, script)
	if err != nil {
		return fmt.Errorf("creating %s in Nextcloud: %w: %s", identifiant, err, tronquer(sortie, 160))
	}
	return nil
}

// setPassword sets a non-temporary password to the user.
func (s *Server) setPassword(r *http.Request, id, password string) error {
	payload, _ := json.Marshal(map[string]any{"type": "password", "value": password, "temporary": false})
	resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id+"/reset-password", string(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("password reset: HTTP %d", resp.StatusCode)
	}
	return nil
}

// POST /api/users/{id}/{action} and POST /api/users/{id}/accounts/{module}/{action}
//
// THE ROUTE LIST DOES NOT GROW: every user gesture is served under
// /api/users/, which keeps the closed set of endpoints the console exposes
// unchanged from the operator's point of view. The module actions are nested
// because the module id is part of them, and a flat route
// /api/users/{id}/{module}/{action} would collide with the lifecycle verbs.
func (s *Server) handleUsersByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 4 && parts[1] == "accounts" && parts[0] != "" && parts[2] != "" && parts[3] != "" {
		if r.Method != http.MethodPost {
			apiErr(w, 405, "method not supported")
			return
		}
		// The administration account is protected for the module actions too:
		// suspending its mailbox would be a way around the refusal below.
		if s.estUtilisateurProtege(r, parts[0]) {
			apiErr(w, 403, "\""+compteAdmin+"\" is the platform administration account: "+
				"its accounts cannot be modified here.")
			return
		}
		s.handleActionCompte(w, r, parts[0], parts[2], parts[3])
		return
	}
	if len(parts) != 2 || parts[0] == "" {
		apiErr(w, 400, "expected path: /api/users/{id}/{action}")
		return
	}
	id, action := parts[0], parts[1]
	if r.Method != http.MethodPost {
		apiErr(w, 405, "method not supported")
		return
	}

	// THE ADMINISTRATION ACCOUNT IS NOT A USER: we refuse BEFORE acting, and
	// we say it. Without this check, the interface could hide the buttons
	// without the API stopping to obey — a direct call would deactivate the
	// platform administration account, and no one would administer Nextcloud
	// or mail anymore.
	//
	// We resolve the name BY THE IDENTIFIER: the client could send the
	// Keycloak id alone, and comparing the action to the name would then have
	// no effect.
	if s.estUtilisateurProtege(r, id) {
		apiErr(w, 403, "\""+compteAdmin+"\" is the platform administration account: "+
			"it can be neither deactivated nor modified here. Use the Administration page.")
		return
	}

	switch action {
	case "deactivate":
		payload, _ := json.Marshal(map[string]any{"enabled": false})
		resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id, string(payload))
		if err != nil {
			apiErr(w, 502, "deactivation: "+err.Error())
			return
		}
		resp.Body.Close()
		// THE MODULES FOLLOW: a deactivated user whose mailbox still receives
		// mail is the exact hole this order closes — Keycloak first (no new
		// sessions), then the objects the modules own.
		if err := s.suspendreOuReprendre(r, id, true); err != nil {
			apiErr(w, 502, "account deactivated, but its module accounts are not: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"deactivated": true, "id": id})
	// REACTIVATE is the INVERSE of deactivate, and it did not exist:
	// deactivating an account by mistake left no recourse from the interface,
	// while Keycloak forgets nothing. An action without its inverse is a dead
	// end.
	case "reactivate":
		payload, _ := json.Marshal(map[string]any{"enabled": true})
		resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+id, string(payload))
		if err != nil {
			apiErr(w, 502, "reactivation: "+err.Error())
			return
		}
		resp.Body.Close()
		if err := s.suspendreOuReprendre(r, id, false); err != nil {
			apiErr(w, 502, "account reactivated, but its module accounts are not: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"reactivated": true, "id": id})
	case "password":
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password == "" {
			apiErr(w, 400, "password required")
			return
		}
		if err := s.setPassword(r, id, body.Password); err != nil {
			apiErr(w, 502, "password reset: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"passwordUpdated": true, "id": id})
	// DELETION IS THE ONE GESTURE THAT CANNOT BE UNDONE: it removes the module
	// objects, the Nextcloud account and the Keycloak account, in that order.
	case "delete":
		s.handleDelete(w, r, id)
	default:
		apiErr(w, 405, "unknown action")
	}
}
