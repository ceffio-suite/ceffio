// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

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
// Client REST Keycloak Admin (realm master → token ; admin/realms/ceffio).

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
// GET /api/users → list; POST /api/users → creation (non-temporary password).

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
			apiErr(w, 400, "username required")
			return
		}
		id, err := s.createUser(r, body.Username, body.Email, body.Password)
		if err != nil {
			apiErr(w, 502, "user creation: "+err.Error())
			return
		}
		writeJSON(w, 201, map[string]any{"id": id, "username": body.Username, "created": true})

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
		return "", fmt.Errorf("user %q already exists", username)
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
	return id, nil
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

// POST /api/users/{id}/deactivate|password
func (s *Server) handleUsersByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	parts := strings.Split(rest, "/")
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
	default:
		apiErr(w, 405, "unknown action")
	}
}
