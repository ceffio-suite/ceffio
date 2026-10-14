// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Configuration of Stalwart's single sign-on (Keycloak SSO).
//
// WHY THIS FILE EXISTS: everything that follows was established by hand, on a
// live server, while hunting for the reason the admin interface refused access.
// Each setting corresponds to a real failure, often a silent one. Reproducing
// them here avoids redoing the same hunt.
//
// THE MOST EXPENSIVE OUTAGE: Stalwart's Authentication object had its four role
// tables EMPTY. Those tables are what translate a role (User/Admin) into
// effective permissions. Empty, any account authenticated by the external
// directory receives zero permissions — hence no "authenticate" — and the
// interface answers "403 Forbidden" after a nevertheless successful login.
// The token was valid, the account resolved, the role correct: only the
// role → permissions mapping was missing.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// compteGestion is the identifier of Stalwart's internal admin account, the one
// carried by STALWART_RECOVERY_ADMIN. It bypasses the directory: that is what
// allows configuring the server even when OIDC is broken.
const compteGestion = "d333333"

// rolesByDefault describes, for each table of the Authentication object, the
// roles it must reference.
//
// WHY BY LABEL AND NOT BY IDENTIFIER: the short identifiers ("b", "e"…) are not
// guaranteed stable across versions or installations. The label, however, is
// stable. So we read the roles actually present and match them on their
// description.
//
// WHY THE ADMIN ALSO CARRIES "User": that is the composition of Stalwart's
// factory default. An administrator is first of all a user — they must keep
// access to the ordinary services (mailbox, sending). Referencing only the
// admin role would deprive them of those permissions.
var rolesByDefault = []struct {
	champ        string
	descriptions []string
}{
	{"defaultUserRoleIds", []string{"User"}},
	{"defaultGroupRoleIds", []string{"Group"}},
	{"defaultTenantRoleIds", []string{"Tenant Administrator", "User"}},
	{"defaultAdminRoleIds", []string{"System Administrator", "User"}},
}

// SSO describes the single sign-on to put in place.
type SSO struct {
	Hote         string // public host, e.g. "mail.ceffio.example.com"
	Issuer       string // realm URL, e.g. "https://keycloak.…/realms/ceffio"
	ClientID     string // WebUI OIDC client, e.g. "stalwart-webui"
	DomaineAdmin string // domain of the admin accounts, OUTSIDE mail, e.g. "ceffio.local"
	CompteAdmin  string // name of the admin account, e.g. "adminceffio"
}

// ConfigurerSSO applies delegated authentication to Stalwart.
//
// Idempotent: each object is created if missing, updated otherwise. Replaying
// the function on an already-configured installation breaks nothing.
func ConfigurerSSO(ctx context.Context, domaineMessagerie string, o SSO) error {
	if o.Issuer == "" || o.ClientID == "" || o.DomaineAdmin == "" || o.CompteAdmin == "" {
		return fmt.Errorf("incomplete SSO: issuer, clientID, domaineAdmin and compteAdmin are required")
	}
	fmt.Println("∙ single sign-on (Keycloak)")

	// --- 1. the OIDC directory ------------------------------------------------
	// It must exist BEFORE the domains: each one references it.
	idAnnuaire, err := assurerAnnuaireOIDC(ctx, o)
	if err != nil {
		return err
	}

	// --- 2. the domains -------------------------------------------------------
	// The mail domain receives mail; the admin domain does not. Separating them
	// avoids the admin account being an ordinary mail address — it has no reason
	// to be reachable from outside.
	//
	// EACH DOMAIN CARRIES ITS OWN directoryId, on top of the global setting: it
	// is through it that Stalwart knows which directory to query for a given
	// domain. Left empty, the account is never resolved (discussion
	// stalwartlabs/stalwart#3049).
	idMessagerie, err := assurerDomaine(ctx, domaineMessagerie, idAnnuaire)
	if err != nil {
		return err
	}
	idAdmin, err := assurerDomaine(ctx, o.DomaineAdmin, idAnnuaire)
	if err != nil {
		return err
	}

	// --- 3. the roles: THIS is where the 403 played out ----------------------
	if err := assurerRoles(ctx); err != nil {
		return err
	}

	// --- 4. the active directory ----------------------------------------------
	// Without this setting, Stalwart keeps using its internal directory.
	if err := majJMAP(ctx, "x:Authentication/set", map[string]any{
		"update": map[string]any{"singleton": map[string]any{"directoryId": idAnnuaire}},
	}); err != nil {
		return fmt.Errorf("active directory: %w", err)
	}

	// --- 5. default domain ----------------------------------------------------
	// The WebUI queries the API WITHOUT a username. Stalwart then falls back to
	// the default domain to know which directory to consult. If it is the
	// built-in domain (without a directory), the account is never resolved.
	// defaultHostname is mandatory as soon as we write into this object.
	if err := majJMAP(ctx, "x:SystemSettings/set", map[string]any{
		"update": map[string]any{"singleton": map[string]any{
			"defaultHostname": o.Hote,
			"defaultDomainId": idMessagerie,
		}},
	}); err != nil {
		return fmt.Errorf("default domain: %w", err)
	}

	// --- 6. the admin account -------------------------------------------------
	// OIDC provisions NOTHING: an account absent from Stalwart is unknown to the
	// server, and mail addressed to it is refused.
	if err := assurerCompteAdmin(ctx, o.CompteAdmin, idAdmin); err != nil {
		return err
	}

	// --- 7. the WebUI OIDC client ---------------------------------------------
	// Without oauthClientId, the /admin page announces no client and only shows
	// its internal form: no SSO button.
	if err := assurerClientWebUI(ctx, o.ClientID); err != nil {
		return err
	}

	// --- 8. restart: MANDATORY -------------------------------------------------
	// Directories and role tables are read ONCE at startup into an in-memory
	// snapshot. Writing the configuration is not enough: without a restart,
	// /api/discover still returns Stalwart's internal endpoints and the
	// permissions stay empty.
	fmt.Println("      restarting (configuration is read at startup)")
	if out, err := k8s.Command(ctx, "kubectl", "-n", ns, "rollout", "restart",
		"deployment/stalwart").CombinedOutput(); err != nil {
		return fmt.Errorf("restart: %w: %s", err, tronquer(string(out), 200))
	}
	// We wait for the END of the restart, not just for a pod to be ready: during
	// the transition, the old pod still answers and `kubectl exec
	// deploy/stalwart` may reach it — the verification below then failed on a
	// refused connection.
	if out, err := k8s.Command(ctx, "kubectl", "-n", ns, "rollout", "status",
		"deployment/stalwart", "--timeout=240s").CombinedOutput(); err != nil {
		return fmt.Errorf("waiting for the restart: %w: %s", err, tronquer(string(out), 200))
	}
	if err := waitReady(ctx); err != nil {
		return err
	}

	// --- 9. verification: discovery must point to the provider ---------------
	// This is the only check that distinguishes "configured" from "active". We
	// retry a few times: right after a restart, the service may not have
	// reopened its port yet.
	compte := o.CompteAdmin + "@" + o.DomaineAdmin
	var dernier string
	for essai := 0; essai < 6; essai++ {
		out, err := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "deploy/stalwart", "-c", "stalwart", "--",
			"sh", "-c", `curl -s --max-time 15 -u "$STALWART_RECOVERY_ADMIN" `+
				`"http://localhost:8080/api/discover/`+compte+`"`).CombinedOutput()
		if err == nil {
			dernier = string(out)
			if strings.Contains(dernier, o.Issuer) {
				fmt.Printf("  ✓ SSO active: %s redirects to %s\n", compte, o.Issuer)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("discovery does not return the expected provider (%s): %s",
		o.Issuer, tronquer(dernier, 200))
}

// assurerDomaine creates the domain if missing and returns its identifier.
//
// The domain is attached to the OIDC directory: that link is what allows
// Stalwart to know where to resolve this domain's accounts.
func assurerDomaine(ctx context.Context, nom, idAnnuaire string) (string, error) {
	existant, err := chercherID(ctx, "x:Domain/get", "name", nom)
	if err != nil {
		return "", fmt.Errorf("reading domains: %w", err)
	}
	if existant != "" {
		if err := majJMAPObjet(ctx, "x:Domain/set", existant, map[string]any{
			"directoryId": idAnnuaire,
		}); err != nil {
			return "", fmt.Errorf("attaching domain %s: %w", nom, err)
		}
		return existant, nil
	}
	fmt.Printf("  ∙ domain created: %s\n", nom)
	cree, err := creerObjet(ctx, "x:Domain/set", map[string]any{
		"name":        nom,
		"directoryId": idAnnuaire,
	})
	if err != nil {
		return "", fmt.Errorf("creating domain %s: %w", nom, err)
	}
	return cree, nil
}

// assurerAnnuaireOIDC creates or updates the OIDC directory and returns its id.
//
// THREE SETTINGS THAT EACH CAUSED A FAILURE:
//
//   - requireAudience: its default value is "stalwart". Keycloak never emits
//     that value, so ALL tokens were rejected and the session fell back to
//     anonymous. We align it with the client identifier, which an audience
//     mapper adds to the token on the Keycloak side.
//   - requireScopes: the WebUI does not send the list expected by default
//     (openid+email); so we require nothing. The empty value is written as {} —
//     "null" is refused by the API.
//   - usernameDomain: the domain added to the token's username to form the
//     full account (user@domain).
func assurerAnnuaireOIDC(ctx context.Context, o SSO) (string, error) {
	corps := map[string]any{
		"@type":           "Oidc",
		"description":     "OIDC directory of the platform",
		"issuerUrl":       o.Issuer,
		"requireAudience": o.ClientID,
		"requireScopes":   map[string]any{},
		"claimUsername":   "preferred_username",
		"usernameDomain":  o.DomaineAdmin,
		"claimName":       "name",
		"claimGroups":     "groups",
	}
	// The directory is recognized by its issuer URL, not by its description.
	id, err := chercherIDParIssuer(ctx, o.Issuer)
	if err != nil {
		return "", err
	}
	if id == "" {
		cree, err := creerObjet(ctx, "x:Directory/set", corps)
		if err != nil {
			return "", fmt.Errorf("creating the OIDC directory: %w", err)
		}
		fmt.Printf("  ∙ OIDC directory created: %s\n", o.Issuer)
		return cree, nil
	}
	if err := majJMAPObjet(ctx, "x:Directory/set", id, corps); err != nil {
		return "", fmt.Errorf("updating the OIDC directory: %w", err)
	}
	return id, nil
}

// assurerRoles fills in the four role tables of the Authentication object.
//
// This is THE fix for the "403 after a successful login". The tables are read
// from the roles actually present, matched on their description.
func assurerRoles(ctx context.Context) error {
	roles, err := lireChamps(ctx, "x:Role/get", "description")
	if err != nil {
		return fmt.Errorf("reading roles: %w", err)
	}
	if len(roles) == 0 {
		return fmt.Errorf("no declared role: the server is not initialized")
	}
	maj := map[string]any{}
	for _, table := range rolesByDefault {
		composition := map[string]any{}
		for _, description := range table.descriptions {
			id, ok := roles[description]
			if !ok {
				return fmt.Errorf("role %q not found: the installation is incomplete", description)
			}
			composition[id] = true
		}
		maj[table.champ] = composition
	}
	if err := majJMAP(ctx, "x:Authentication/set", map[string]any{
		"update": map[string]any{"singleton": maj},
	}); err != nil {
		return fmt.Errorf("role tables: %w", err)
	}
	fmt.Println("  ✓ roles → permissions (User, Group, Tenant Admin, System Admin)")
	return nil
}

// assurerCompteAdmin creates the admin account if missing.
func assurerCompteAdmin(ctx context.Context, nom, idDomaine string) error {
	id, err := chercherID(ctx, "x:Account/get", "name", nom)
	if err != nil {
		return fmt.Errorf("reading accounts: %w", err)
	}
	corps := map[string]any{
		"@type":    "User",
		"name":     nom,
		"domainId": idDomaine,
		"roles":    map[string]any{"@type": "Admin"},
	}
	if id == "" {
		if _, err := creerObjet(ctx, "x:Account/set", corps); err != nil {
			return fmt.Errorf("creating account %s: %w", nom, err)
		}
		fmt.Printf("  ∙ admin account created: %s\n", nom)
		return nil
	}
	// The account exists: we make sure it carries the admin role and that it is
	// attached to the admin domain.
	if err := majJMAPObjet(ctx, "x:Account/set", id, map[string]any{
		"domainId": idDomaine,
		"roles":    map[string]any{"@type": "Admin"},
	}); err != nil {
		return fmt.Errorf("updating account %s: %w", nom, err)
	}
	return nil
}

// assurerClientWebUI declares the OIDC client used by the admin interface.
//
// Without it, the /admin page exposes no client: the SSO button does not appear
// and only the internal form is offered.
func assurerClientWebUI(ctx context.Context, clientID string) error {
	existants, err := lireChamps(ctx, "x:Application/get", "oauthClientId")
	if err != nil {
		return fmt.Errorf("reading applications: %w", err)
	}
	if _, ok := existants[clientID]; ok {
		return nil
	}
	// A single application serves the WebUI: we complete the first one declared
	// rather than adding a second, which would never be served.
	ids, err := lireIDs(ctx, "x:Application/get")
	if err != nil || len(ids) == 0 {
		return fmt.Errorf("no WebUI application declared: %v", err)
	}
	if err := majJMAPObjet(ctx, "x:Application/set", ids[0], map[string]any{
		"oauthClientId": clientID,
	}); err != nil {
		return fmt.Errorf("WebUI OIDC client: %w", err)
	}
	fmt.Printf("  ∙ WebUI OIDC client: %s\n", clientID)
	return nil
}

// ---------------------------------------------------------------------------
// JMAP access
//
// FORMAT: all of Stalwart v0.16 configuration is a JMAP object. We go through
// the pod (and not through the Ingress): the call stays on the internal network
// and STALWART_RECOVERY_ADMIN is already in the container environment — the
// secret therefore never travels through a command line.
// ---------------------------------------------------------------------------

// appelJMAP sends a JMAP request and returns the first response body.
func appelJMAP(ctx context.Context, methode string, args map[string]any) (map[string]any, error) {
	enveloppe := map[string]any{
		"using":       []string{},
		"methodCalls": []any{[]any{methode, args, "c1"}},
	}
	brut, err := json.Marshal(enveloppe)
	if err != nil {
		return nil, err
	}
	script := `curl -s --max-time 20 -u "$STALWART_RECOVERY_ADMIN" ` +
		`-H "Content-Type: application/json" -X POST http://localhost:8080/jmap --data @-`
	cmd := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "-i", "deploy/stalwart", "-c", "stalwart", "--",
		"sh", "-c", script)
	cmd.Stdin = strings.NewReader(string(brut))
	sortie, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("JMAP call %s: %w: %s", methode, err, tronquer(string(sortie), 200))
	}

	var reponse struct {
		MethodResponses []json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(sortie, &reponse); err != nil {
		return nil, fmt.Errorf("unreadable JMAP response (%s): %w", tronquer(string(sortie), 200), err)
	}
	if len(reponse.MethodResponses) == 0 {
		return nil, fmt.Errorf("empty JMAP response: %s", tronquer(string(sortie), 200))
	}
	var couple []json.RawMessage
	if err := json.Unmarshal(reponse.MethodResponses[0], &couple); err != nil || len(couple) < 2 {
		return nil, fmt.Errorf("unexpected JMAP response: %s", tronquer(string(sortie), 200))
	}
	var nom string
	_ = json.Unmarshal(couple[0], &nom)
	var corps map[string]any
	if err := json.Unmarshal(couple[1], &corps); err != nil {
		return nil, fmt.Errorf("unreadable JMAP body: %w", err)
	}
	// The API reports its refusals in the body, not through an HTTP code.
	if _, estErreur := corps["type"]; estErreur && nom == "error" {
		return nil, fmt.Errorf("Stalwart refusal: %s", tronquer(string(couple[1]), 300))
	}
	for _, cle := range []string{"notCreated", "notUpdated", "notDestroyed"} {
		if v, ok := corps[cle]; ok {
			return nil, fmt.Errorf("Stalwart refused (%s): %v", cle, tronquer(fmt.Sprint(v), 300))
		}
	}
	return corps, nil
}

// majJMAP sends a modification and returns nothing.
func majJMAP(ctx context.Context, methode string, args map[string]any) error {
	args["accountId"] = compteGestion
	_, err := appelJMAP(ctx, methode, args)
	return err
}

// majJMAPObjet updates one specific object.
func majJMAPObjet(ctx context.Context, methode, id string, champs map[string]any) error {
	return majJMAP(ctx, methode, map[string]any{"update": map[string]any{id: champs}})
}

// creerObjet creates an object and returns its identifier.
func creerObjet(ctx context.Context, methode string, champs map[string]any) (string, error) {
	corps, err := appelJMAP(ctx, methode, map[string]any{
		"accountId": compteGestion,
		"create":    map[string]any{"n1": champs},
	})
	if err != nil {
		return "", err
	}
	crees, ok := corps["created"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("creation without a returned identifier")
	}
	for _, v := range crees {
		if m, ok := v.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("creation without a returned identifier")
}

// chercherID returns the identifier of the first object whose field equals the value.
func chercherID(ctx context.Context, methode, champ, valeur string) (string, error) {
	trouves, err := lireChamps(ctx, methode, champ)
	if err != nil {
		return "", err
	}
	return trouves[valeur], nil
}

// lireChamps returns, for each object, the value of the field associated with its id.
func lireChamps(ctx context.Context, methode, champ string) (map[string]string, error) {
	corps, err := appelJMAP(ctx, methode, map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id", champ},
	})
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	resultat := map[string]string{}
	for _, e := range liste {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		val, _ := m[champ].(string)
		if id != "" && val != "" {
			resultat[val] = id
		}
	}
	return resultat, nil
}

// lireIDs returns all identifiers of an object type.
func lireIDs(ctx context.Context, methode string) ([]string, error) {
	corps, err := appelJMAP(ctx, methode, map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id"},
	})
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	var ids []string
	for _, e := range liste {
		if m, ok := e.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// chercherIDParIssuer finds the OIDC directory by its issuer URL.
//
// We do not trust the description: it is free-form, and changing it would make
// us believe a directory is missing — hence a duplicate.
func chercherIDParIssuer(ctx context.Context, issuer string) (string, error) {
	corps, err := appelJMAP(ctx, "x:Directory/get", map[string]any{
		"accountId":  compteGestion,
		"properties": []string{"id", "issuerUrl"},
	})
	if err != nil {
		return "", fmt.Errorf("reading directories: %w", err)
	}
	liste, _ := corps["list"].([]any)
	for _, e := range liste {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if u, _ := m["issuerUrl"].(string); u == issuer {
			id, _ := m["id"].(string)
			return id, nil
		}
	}
	return "", nil
}

// attendreStabilite gives Stalwart time to reload its configuration.
func attendreStabilite(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(3 * time.Second):
		return nil
	}
}
