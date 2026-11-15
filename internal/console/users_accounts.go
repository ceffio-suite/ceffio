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

	"github.com/ceffio-suite/ceffio/internal/module"
)

// This file is the console's side of the module.Accounts contract: it renders
// the extra creation fields of the installed modules, runs their validation,
// their provisioning and their lifecycle, and writes the results back.
//
// WHY IT LIVES BESIDE users.go AND NOT INSIDE IT: users.go is the platform
// account (Keycloak + Nextcloud) and knows no module. Everything that reaches
// into a module belongs here, so a reader can answer "does the console know a
// module name?" by reading one file — and it does not: modules are discovered
// through the registry at call time.

// moduleCompte is one installed module that takes part in the Users page.
type moduleCompte struct {
	ID  string
	Mod module.Module
	Acc module.Accounts
	Env module.Env
}

// titre is how the module is named to the operator (errors, page labels).
func (c moduleCompte) titre() string {
	if t := c.Mod.Info().Title; t != "" {
		return t
	}
	return c.ID
}

// executerOcc runs an occ script in the Nextcloud pod.
//
// WHY A SEAM: the real call goes through the Kubernetes exec subresource,
// which needs an in-cluster SPDY connection; a unit test cannot have one.
// Swapping this variable lets the tests assert the scripts the console WOULD
// run (which is the contract with Nextcloud) without a cluster.
var executerOcc = func(s *Server, ctx context.Context, script string) (string, error) {
	return s.occScript(ctx, script)
}

// modulesComptes lists the INSTALLED modules that take part in the Users page.
//
// WHY INSTALLED ONLY: a module that is not installed has no account objects to
// create, and asking it for fields would put a mailbox checkbox on the form of
// a platform that cannot create mailboxes. Degraded counts as installed: the
// module is there and its accounts exist, only one of its checks fails — the
// page must still manage them.
func (s *Server) modulesComptes(ctx context.Context) []moduleCompte {
	var comptes []moduleCompte
	for _, m := range moduleAll() {
		acc, ok := module.AccountsOf(m)
		if !ok {
			continue
		}
		env := s.moduleEnvReadOnly(m)
		st := m.State(ctx, env)
		if st.Status != module.Installed && st.Status != module.Degraded {
			continue
		}
		comptes = append(comptes, moduleCompte{ID: m.Info().ID, Mod: m, Acc: acc, Env: env})
	}
	return comptes
}

// valeursDe completes the values the operator sent with the modules' declared
// defaults, and refuses a key no field declares.
//
// WHY DEFAULTS ARE APPLIED HERE: the console asks the module for its fields on
// every render, then receives only what the form changed. Applying the default
// on the server means a script calling the API without the optional field gets
// the same result as the page, instead of an empty value the module has to
// interpret — "no value" and "empty value" must not be two different requests.
//
// WHY AN UNKNOWN KEY IS REFUSED: a typo ("quota_gb" for "quota_gio") would
// otherwise be dropped silently and the creation would run with the default,
// which looks like it worked. The message names the key.
func valeursDe(champs []module.AccountField, recus module.Values) (module.Values, error) {
	valeurs := make(module.Values, len(champs))
	connus := make(map[string]bool, len(champs))
	for _, c := range champs {
		connus[c.Key] = true
		if c.Default != "" {
			valeurs[c.Key] = c.Default
		}
	}
	for k, v := range recus {
		if !connus[k] {
			return nil, fmt.Errorf("unknown field %q", k)
		}
		valeurs[k] = v
	}
	return valeurs, nil
}

// emailRemplace says whether a module makes the email input meaningless.
//
// The field is a checkbox (module.Bool): its value is the string "true" or
// "false" as sent by every frontend, and "true" means the module computes the
// address itself (an internal user's address is <username>@<domain>).
func emailRemplace(champs []module.AccountField, valeurs module.Values) bool {
	for _, c := range champs {
		if c.Type == module.Bool && c.ReplacesEmail && valeurs[c.Key] == "true" {
			return true
		}
	}
	return false
}

// utilisateursModule converts the platform accounts to the contract's User.
func utilisateursModule(users []KCUser) []module.User {
	out := make([]module.User, 0, len(users))
	for _, u := range users {
		out = append(out, module.User{ID: u.ID, Username: u.Username, Email: u.Email, Attributes: u.Attributes})
	}
	return out
}

// comptesPourPage builds the fields and the per-user account summaries of the
// Users page, and the per-module errors that could not be answered.
//
// A module that fails to answer does NOT fail the page: the list of users is
// the page's primary data, and hiding it because a mailbox server is down would
// make the whole interface unusable for a problem that concerns one column.
func (s *Server) comptesPourPage(ctx context.Context, users []KCUser) (
	champs map[string][]module.AccountField,
	comptes map[string]map[string]module.AccountInfo,
	errs map[string]string,
) {
	champs = make(map[string][]module.AccountField)
	comptes = make(map[string]map[string]module.AccountInfo)
	errs = make(map[string]string)
	mu := utilisateursModule(users)
	for _, c := range s.modulesComptes(ctx) {
		champs[c.ID] = c.Acc.AccountFields(ctx, c.Env)
		infos, err := c.Acc.AccountInfos(ctx, c.Env, mu)
		if err != nil {
			errs[c.ID] = err.Error()
			continue
		}
		comptes[c.ID] = infos
	}
	return champs, comptes, errs
}

// utilisateurModule returns one user as the contract sees it.
func (s *Server) utilisateurModule(r *http.Request, id string) (module.User, error) {
	u, err := s.utilisateurParID(r, id)
	if err != nil {
		return module.User{}, err
	}
	return module.User{ID: u.ID, Username: u.Username, Email: u.Email, Attributes: u.Attributes}, nil
}

// ---------------------------------------------------------------------------
// creation

// creationUtilisateur is the body of POST /api/users.
type creationUtilisateur struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	// Modules carries the values of the fields each module declared, keyed by
	// module then by field key: {"mail": {"boite": "true", "quota_gio": "5"}}.
	Modules map[string]map[string]string `json:"modules"`
}

// creerUtilisateurCompte creates a platform user AND the objects every
// installed module owns for it, in the order the contract prescribes.
//
// THE ORDER IS THE WHOLE POINT (docs/plan-mail.md §4.6): every module validates
// BEFORE Keycloak is touched, then the platform account exists in the two
// systems that authenticate, then each module provisions, then each module's
// result is written back. A refusal that arrives after the Keycloak account is
// created leaves a user with no mailbox and no way to retry from the page; a
// mailbox created before the account exists is an object with no owner.
func (s *Server) creerUtilisateurCompte(w http.ResponseWriter, r *http.Request, body creationUtilisateur) {
	ctx := r.Context()
	comptes := s.modulesComptes(ctx)

	connus := make(map[string]moduleCompte, len(comptes))
	for _, c := range comptes {
		connus[c.ID] = c
	}
	for id := range body.Modules {
		if _, ok := connus[id]; !ok {
			apiErr(w, 400, fmt.Sprintf("module %q does not take part in user creation", id))
			return
		}
	}

	// The values AND the effective email are resolved before anything is
	// created, because a module that owns the address (an internal mailbox)
	// changes what the platform account is created with.
	valeurs := make(map[string]module.Values, len(comptes))
	email := body.Email
	for _, c := range comptes {
		champs := c.Acc.AccountFields(ctx, c.Env)
		v, err := valeursDe(champs, module.Values(body.Modules[c.ID]))
		if err != nil {
			apiErr(w, 400, "user creation: "+c.titre()+": "+err.Error())
			return
		}
		valeurs[c.ID] = v
		if emailRemplace(champs, v) {
			email = ""
		}
	}

	mu := module.User{Username: body.Username, Email: email}
	// 1. VALIDATION, all modules, before Keycloak.
	for _, c := range comptes {
		if err := c.Acc.ValidateAccount(ctx, c.Env, mu, valeurs[c.ID]); err != nil {
			apiErr(w, 400, "user creation: "+c.titre()+": "+err.Error())
			return
		}
	}

	// 2. The platform account, then Nextcloud (createUser does both).
	id, err := s.createUser(r, body.Username, email, body.Password)
	if err != nil {
		apiErr(w, 502, "user creation: "+err.Error())
		return
	}

	// 3. Provisioning, 4. write-back.
	faits := make(map[string]string, len(comptes))
	for _, c := range comptes {
		res, err := c.Acc.EnsureAccount(ctx, c.Env, mu, valeurs[c.ID])
		if err != nil {
			// WHAT EXISTS IS SAID, AND HOW TO FINISH: the Keycloak account is
			// there, so the correct next gesture is the same request again —
			// not "delete the user and start over", which is what an operator
			// guesses when the error only says "failed".
			apiErr(w, 502, fmt.Sprintf(
				"user %q created; provisioning %s failed: %v — send the same request again to finish the setup",
				body.Username, c.titre(), err))
			return
		}
		if err := s.ecrireResultatCompte(r, id, body.Username, c.titre(), res); err != nil {
			apiErr(w, 502, fmt.Sprintf(
				"user %q created and provisioned by %s, but the result could not be written back: %v",
				body.Username, c.titre(), err))
			return
		}
		faits[c.ID] = res.Email
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "username": body.Username, "created": true, "email": email, "modules": faits,
	})
}

// ---------------------------------------------------------------------------
// Keycloak read / write helpers used by the account paths

// kcUserComplet is a Keycloak user representation: the fields the console
// needs to merge an update (a PUT replaces the whole representation, so an
// attribute written alone would erase every other one).
type kcUserComplet struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Email      string              `json:"email"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes"`
}

// premierAttribut flattens Keycloak's multi-valued attributes to the contract's
// single value.
//
// WHY NOT LOSE THEM ALL: the contract's User.Attributes is map[string]string,
// and every attribute this platform writes has one value (ceffio_kind,
// provenance). Keeping the first value is right for those; a module that needs
// several values would ask Keycloak for them itself.
func premierAttribut(attrs map[string][]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// utilisateurParID reads one user, attributes included.
func (s *Server) utilisateurParID(r *http.Request, id string) (KCUser, error) {
	resp, err := s.kcReq(r, http.MethodGet, "/admin/realms/"+realm+"/users/"+url.PathEscape(id), "")
	if err != nil {
		return KCUser{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return KCUser{}, fmt.Errorf("user not found")
	}
	if resp.StatusCode/100 != 2 {
		return KCUser{}, fmt.Errorf("reading the user: HTTP %d", resp.StatusCode)
	}
	var u kcUserComplet
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return KCUser{}, err
	}
	return KCUser{ID: u.ID, Username: u.Username, Email: u.Email, Enabled: u.Enabled,
		Protege: estCompteProtege(u.Username), Attributes: premierAttribut(u.Attributes)}, nil
}

// idParNom finds a user's id by exact username.
func (s *Server) idParNom(r *http.Request, username string) (string, error) {
	q := url.Values{"username": {username}, "exact": {"true"}}
	resp, err := s.kcReq(r, http.MethodGet, "/admin/realms/"+realm+"/users?"+q.Encode(), "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("looking up %q: HTTP %d", username, resp.StatusCode)
	}
	var users []KCUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", err
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("user %q not found", username)
}

// ecrireResultatCompte writes a module's AccountResult to the platform
// account: the address in Keycloak and Nextcloud, the attributes in Keycloak.
//
// WHY THE RESULT IS WRITTEN BACK AT ALL: an internal user's address is not the
// one the operator typed, it is <username>@<domain> — the mail server's
// convention, and the address the mailbox answers on. Letting each module write
// the Keycloak user itself would make several writers of one object; the module
// states the result, one writer applies it.
func (s *Server) ecrireResultatCompte(r *http.Request, id, username, moduleTitre string, res module.AccountResult) error {
	if res.Email == "" && len(res.Attributes) == 0 {
		return nil
	}
	// A PUT replaces the whole representation: read, merge, write.
	u, err := s.kcUserBrut(r, id)
	if err != nil {
		return err
	}
	if res.Email != "" {
		// The address a module assigns is authoritative and the account can
		// receive mail at it at once: verified, not pending.
		u["email"] = res.Email
		u["emailVerified"] = true
	}
	if len(res.Attributes) > 0 {
		attrs, _ := u["attributes"].(map[string]any)
		if attrs == nil {
			attrs = map[string]any{}
		}
		for k, v := range res.Attributes {
			attrs[k] = []string{v}
		}
		u["attributes"] = attrs
	}
	b, _ := json.Marshal(u)
	resp, err := s.kcReq(r, http.MethodPut, "/admin/realms/"+realm+"/users/"+url.PathEscape(id), string(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("writing the user back: HTTP %d", resp.StatusCode)
	}
	if res.Email != "" {
		// THE NEXTCLOUD ACCOUNT CARRIES THE ADDRESS TOO: Nextcloud shows it in
		// the profile and uses it to send notifications, so an account whose
		// Keycloak email is the mailbox but whose Nextcloud email is empty
		// looks like a user without an address in half of the interface.
		if err := s.poserEmailNextcloud(r.Context(), username, res.Email); err != nil {
			// Non-blocking, like the account creation: the platform account is
			// provisioned and usable, and the operator can fix the address
			// without recreating anything.
			fmt.Printf("  ⚠ %s: address written in Keycloak but not in Nextcloud (module %s): %v\n",
				username, moduleTitre, err)
		}
	}
	return nil
}

// kcUserBrut reads the raw Keycloak representation, kept as a generic map so a
// field the console does not know (federatedIdentities, requiredActions…)
// survives the round trip. Re-encoding a struct would silently drop them.
func (s *Server) kcUserBrut(r *http.Request, id string) (map[string]any, error) {
	resp, err := s.kcReq(r, http.MethodGet, "/admin/realms/"+realm+"/users/"+url.PathEscape(id), "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("reading the user: HTTP %d", resp.StatusCode)
	}
	var u map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return u, nil
}

// poserEmailNextcloud sets the address on the local Nextcloud account.
func (s *Server) poserEmailNextcloud(ctx context.Context, username, email string) error {
	script := "php occ user:setting " + shellQuote(username) + " settings email " + shellQuote(email)
	sortie, err := executerOcc(s, ctx, script)
	if err != nil {
		return fmt.Errorf("Nextcloud: %w: %s", err, tronquer(sortie, 160))
	}
	return nil
}

// ---------------------------------------------------------------------------
// lifecycle: deactivate / reactivate / delete / module action

// suspendreOuReprendre applies the whole-user lifecycle to every module, after
// the platform account has changed.
//
// NEXTCLOUD IS NOT ALLOWED TO FAIL THE GESTURE: its local account is the
// fallback door when Keycloak is unavailable; a failure there is logged and the
// gestures that matter (Keycloak's flag, the modules' objects) still happen. A
// module's failure IS returned, because the mailbox of a deactivated user that
// still receives mail is a security problem, not a cosmetic one.
func (s *Server) suspendreOuReprendre(r *http.Request, id string, suspendre bool) error {
	u, err := s.utilisateurModule(r, id)
	if err != nil {
		return err
	}
	verbe := "user:enable"
	if suspendre {
		verbe = "user:disable"
	}
	if _, err := executerOcc(s, r.Context(), "php occ "+verbe+" "+shellQuote(u.Username)); err != nil {
		fmt.Printf("  ⚠ %s: Nextcloud account not updated (%s): %v\n", u.Username, verbe, err)
	}
	var errs []string
	for _, c := range s.modulesComptes(r.Context()) {
		var err error
		if suspendre {
			err = c.Acc.SuspendAccount(r.Context(), c.Env, u)
		} else {
			err = c.Acc.ResumeAccount(r.Context(), c.Env, u)
		}
		if err != nil {
			errs = append(errs, c.titre()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// supprimerComptes supprime the module objects, then the Nextcloud account,
// then the Keycloak account.
//
// THE MODULES GO FIRST: they are the objects no other page can reach once the
// platform account is gone (a mailbox whose owner has disappeared). Deleting
// Keycloak first would leave orphans that only a terminal could remove.
func (s *Server) supprimerComptes(r *http.Request, u module.User) error {
	for _, c := range s.modulesComptes(r.Context()) {
		if err := c.Acc.DeleteAccount(r.Context(), c.Env, u); err != nil {
			return fmt.Errorf("%s: %v", c.titre(), err)
		}
	}
	if _, err := executerOcc(s, r.Context(), "php occ user:delete "+shellQuote(u.Username)); err != nil {
		return fmt.Errorf("Nextcloud account: %w", err)
	}
	resp, err := s.kcReq(r, http.MethodDelete, "/admin/realms/"+realm+"/users/"+url.PathEscape(u.ID), "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Keycloak account: HTTP %d", resp.StatusCode)
	}
	return nil
}

// handleDelete supprime un utilisateur après confirmation tapée.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, 400, "confirmation required")
		return
	}
	u, err := s.utilisateurModule(r, id)
	if err != nil {
		apiErr(w, 404, err.Error())
		return
	}
	// THE CONFIRMATION IS THE USERNAME, compared without case: Keycloak's
	// usernames are case-insensitive, and a typed confirmation that refuses
	// "Alice" for "alice" would be a rule the platform itself does not apply.
	if !strings.EqualFold(strings.TrimSpace(body.Confirm), u.Username) {
		apiErr(w, 400, fmt.Sprintf("type the username %q to confirm the deletion", u.Username))
		return
	}
	if err := s.supprimerComptes(r, u); err != nil {
		apiErr(w, 502, "deletion stopped, the platform account was kept so it can be retried: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id, "username": u.Username})
}

// handleActionCompte runs one action a module offers on one user's account.
//
// The action is looked up in the module's OWN declaration for this user, so an
// unknown id is a disagreement between the page and the module and is refused
// rather than forwarded: a module receiving an action it never declared would
// have to interpret it, and the day it stops offering it the page keeps calling
// it silently.
func (s *Server) handleActionCompte(w http.ResponseWriter, r *http.Request, id, moduleID, actionID string) {
	var body struct {
		Confirm string            `json:"confirm"`
		Values  map[string]string `json:"values"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var cible *moduleCompte
	for _, c := range s.modulesComptes(r.Context()) {
		if c.ID == moduleID {
			c := c
			cible = &c
			break
		}
	}
	if cible == nil {
		apiErr(w, 404, fmt.Sprintf("module %q does not take part in user accounts", moduleID))
		return
	}
	u, err := s.utilisateurModule(r, id)
	if err != nil {
		apiErr(w, 404, err.Error())
		return
	}
	infos, err := cible.Acc.AccountInfos(r.Context(), cible.Env, []module.User{u})
	if err != nil {
		apiErr(w, 502, cible.titre()+": "+err.Error())
		return
	}
	var action *module.AccountAction
	if info, ok := infos[u.ID]; ok {
		for i := range info.Actions {
			if info.Actions[i].ID == actionID {
				action = &info.Actions[i]
				break
			}
		}
	}
	if action == nil {
		apiErr(w, 404, fmt.Sprintf("action %q is not offered for %q", actionID, u.Username))
		return
	}
	if action.Confirm != "" && !strings.EqualFold(strings.TrimSpace(body.Confirm), action.Confirm) {
		apiErr(w, 400, fmt.Sprintf("type %q to confirm this action", action.Confirm))
		return
	}
	// The action's fields are settings fields (module.Field); the helper works
	// on the account variant, which wraps them — so the conversion is the
	// contract's, not the caller's.
	champsAction := make([]module.AccountField, 0, len(action.Fields))
	for _, f := range action.Fields {
		champsAction = append(champsAction, module.AccountField{Field: f})
	}
	valeurs, err := valeursDe(champsAction, module.Values(body.Values))
	if err != nil {
		apiErr(w, 400, cible.titre()+": "+err.Error())
		return
	}
	if err := cible.Acc.AccountAction(r.Context(), cible.Env, u, actionID, valeurs); err != nil {
		apiErr(w, 502, cible.titre()+": "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"done": true, "id": id, "module": moduleID, "action": actionID})
}
