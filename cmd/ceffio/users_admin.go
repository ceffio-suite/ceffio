// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// WHY THIS FILE: `ceffio users` manages the two directories the platform has
// always written to — Keycloak (the user directory) and Nextcloud (the file
// accounts) — and both are reachable only by running commands inside their
// pods. users.go reads as the contract's orchestration (validate, create,
// ensure, write back); this file holds the "how do I reach the pod" half, so a
// change of image or of command layout has exactly one place to land.
//
// Keycloak is reached through internal/identity's EXPORTED ExecuterKcadm: the
// pod selection, the /secrets/env sourcing and the JVM memory cap are the same
// ones the login page uses, and a second copy of that script would drift into an
// authentication failure nobody can reproduce. Nextcloud has no such export, so
// its single `occ` helper is restated here (and nowhere else in this package).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	// The namespaces and workloads of the platform accounts. They are the same
	// values as internal/identity (ns, nsFiles) and internal/modules/files;
	// those constants are unexported, so they are restated here and the comment
	// names the source of truth. A change there must be mirrored here.
	nsIdentite  = "ceffio-identity"
	nsFichiers  = "ceffio-files"
	realmCeffio = "ceffio"
	compteAdmin = "adminceffio"
	kcadmBin    = "/opt/keycloak/bin/kcadm.sh"

	// Nextcloud: the deployment is nextcloud, its pods carry app=nextcloud and
	// the occ command runs in the nextcloud container.
	deploiementNextcloud = "nextcloud"
	etiquetteNextcloud   = "nextcloud"
	conteneurNextcloud   = "nextcloud"
)

// comptePlateforme is one Keycloak account as the CLI shows it: the contract's
// module.User plus the "enabled" flag, which the account contract does not
// carry (a module does not manage sessions; the directory does).
type comptePlateforme struct {
	module.User
	Actif bool
}

// compteKeycloak is the subset of Keycloak's user representation the CLI reads.
// Attributes are multi-valued in Keycloak and single-valued in the contract;
// premierAttribut flattens them.
type compteKeycloak struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Email      string              `json:"email"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes"`
}

// compte converts the directory's representation to the CLI's.
func (b compteKeycloak) compte() comptePlateforme {
	return comptePlateforme{
		User: module.User{
			ID: b.ID, Username: b.Username, Email: b.Email, Attributes: premierAttribut(b.Attributes),
		},
		Actif: b.Enabled,
	}
}

// ---------------------------------------------------------------------------
// Seams
//
// Every operation below is a VARIABLE so that users_test.go can assert which
// call the command makes, in which order, with which values — the two
// directories need a cluster, and a unit test must never need one. The seam is
// per OPERATION rather than a raw "run this script" hook: a test that only
// checks script text would pass while the command creates the wrong user.

var (
	// Keycloak, the platform directory.
	keycloakLister    = listerComptesKeycloak
	keycloakParNom    = trouverCompteKeycloak
	keycloakCreer     = creerCompteKeycloak
	keycloakActiver   = activerCompteKeycloak
	keycloakSupprimer = supprimerCompteKeycloak
	keycloakEcrire    = ecrireCompteKeycloak

	// Nextcloud, the file accounts.
	nextcloudCreer       = creerCompteNextcloud
	nextcloudActiver     = activerCompteNextcloud
	nextcloudSupprimer   = supprimerCompteNextcloud
	nextcloudEcrireEmail = ecrireEmailNextcloud
)

// executerKcadm runs an authenticated kcadm command in the Keycloak pod,
// optionally feeding its standard input.
//
// WHY A VARIABLE: the real call needs an in-cluster SPDY connection; the tests
// substitute canned output (see users_test.go). entree is written first and
// read by the script with `IFS= read -r`, which is how a password travels
// without appearing in this command's arguments.
var executerKcadm = func(ctx context.Context, entree, commande string) (string, error) {
	return identity.ExecuterKcadm(ctx, nsIdentite, entree, commande)
}

// executerOcc runs a shell script inside the Nextcloud pod, optionally feeding
// its standard input (same reason as executerKcadm).
var executerOcc = occDansPod

// ---------------------------------------------------------------------------
// Pod access

// occDansPod executes a shell script in the Nextcloud pod.
func occDansPod(ctx context.Context, entree, script string) (string, error) {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return "", fmt.Errorf("connecting to the cluster: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, nsFichiers, deploiementNextcloud, etiquetteNextcloud)
	if err != nil {
		return "", fmt.Errorf("locating the Nextcloud pod: %w", err)
	}
	args := []string{"sh", "-c", script}
	if entree == "" {
		sortie, err := cli.Executer(ctx, nsFichiers, pod, conteneurNextcloud, args...)
		if err != nil {
			return sortie, fmt.Errorf("running occ in the Nextcloud pod: %w", err)
		}
		return sortie, nil
	}
	sortie, err := cli.ExecuterAvecEntree(ctx, nsFichiers, pod, conteneurNextcloud, entree, args...)
	if err != nil {
		return sortie, fmt.Errorf("running occ in the Nextcloud pod: %w", err)
	}
	return sortie, nil
}

// ---------------------------------------------------------------------------
// Keycloak operations

// champsCompte is the field filter both account reads use. THE BRACKETS AND THE
// QUOTES ARE BOTH LOAD-BEARING: `attributes` without `(*)` comes back as an empty
// map (Keycloak's documented filter rule), and the parentheses reach a shell, so
// an unquoted `attributes(*)` is a syntax error — `sh: syntax error near
// unexpected token '('` — which is how this fix first landed and failed.
const champsCompte = `"id,username,email,enabled,attributes(*)"`

// listerComptesKeycloak returns every platform account, pages included.
//
// briefRepresentation=false is what makes Keycloak return the attributes: with
// the default (true) it returns the names only, and every module would see an
// account with no attributes. The pages are read until a short one, because
// Keycloak caps a response at 100 users by default and a directory that grew
// past it would silently lose accounts from the list.
//
// PAGINATION IS `--offset`, NOT `--first`: Keycloak 26.8 removed the old name and
// kcadm exits 2 with `Unknown options: '--first', '0'` — which `ceffio users list`
// turned into an authentication-shaped failure on the live demo (2026-11-14), on a
// realm whose credentials were fine. `kcadm get --help` documents the surviving
// pair ("kcadm.sh get users -r demorealm --offset 0 --limit 100").
//
// `attributes(*)` IS NOT OPTIONAL EITHER. kcadm's field filter returns an EMPTY
// object for a map-valued field whose children are not requested — the documented
// rule reads "if attribute of object type is included, but its children are not
// specified by using brackets, then an empty object will be returned". Measured on
// the same realm: `--fields attributes` answers `"attributes": {}`, the bracketed
// form answers the map. The modules' markers (`ceffio_kind`) live there.
func listerComptesKeycloak(ctx context.Context) ([]comptePlateforme, error) {
	const page = 100
	var comptes []comptePlateforme
	for decalage := 0; ; decalage += page {
		sortie, err := executerKcadm(ctx, "", fmt.Sprintf(
			"%s get users -r %s -q briefRepresentation=false --fields %s --offset %d --limit %d",
			kcadmBin, realmCeffio, champsCompte, decalage, page))
		if err != nil {
			return nil, fmt.Errorf("listing the platform accounts: %w", err)
		}
		bruts, err := decoderComptes(sortie)
		if err != nil {
			return nil, fmt.Errorf("listing the platform accounts: %w", err)
		}
		for _, b := range bruts {
			comptes = append(comptes, b.compte())
		}
		if len(bruts) < page {
			return comptes, nil
		}
		if decalage >= page*100 {
			return nil, fmt.Errorf("the directory returned more than %d accounts: refusing to list a truncated page", decalage+page)
		}
	}
}

// trouverCompteKeycloak returns one account by exact username, and whether it
// exists. Keycloak's usernames are case-insensitive, so the comparison is.
func trouverCompteKeycloak(ctx context.Context, nom string) (comptePlateforme, bool, error) {
	sortie, err := executerKcadm(ctx, "", kcadmBin+" get users -r "+realmCeffio+
		" -q briefRepresentation=false -q username="+entreGuillemets(nom)+" -q exact=true"+
		" --fields "+champsCompte)
	if err != nil {
		return comptePlateforme{}, false, fmt.Errorf("looking up %q in Keycloak: %w", nom, err)
	}
	bruts, err := decoderComptes(sortie)
	if err != nil {
		return comptePlateforme{}, false, fmt.Errorf("looking up %q in Keycloak: %w", nom, err)
	}
	for _, b := range bruts {
		// exact=true is the SERVER's filter, but comparing again here is what
		// keeps a substring match (or a mis-encoded query) from selecting the
		// wrong account for a destructive operation.
		if strings.EqualFold(strings.TrimSpace(b.Username), strings.TrimSpace(nom)) {
			return b.compte(), true, nil
		}
	}
	return comptePlateforme{}, false, nil
}

// creerCompteKeycloak creates the platform account, adopting an existing one.
//
// WHY ADOPT RATHER THAN REFUSE: the Keycloak account is the FIRST step of a
// creation (see the contract's ordering). A retry after a module failed later
// must find the account and finish the job; refusing "already exists" would
// leave the operator with half a user and no command to complete it. The
// password is NOT reset on adoption: the operator may have changed it.
func creerCompteKeycloak(ctx context.Context, u module.User, motDePasse string) (comptePlateforme, error) {
	if existant, existe, err := keycloakParNom(ctx, u.Username); err != nil {
		return comptePlateforme{}, err
	} else if existe {
		return existant, nil
	}
	commande := kcadmBin + " create users -r " + realmCeffio +
		" -s username=" + entreGuillemets(u.Username) + " -s enabled=true"
	if u.Email != "" {
		commande += " -s email=" + entreGuillemets(u.Email) + " -s emailVerified=true"
	}
	if _, err := executerKcadm(ctx, "", commande); err != nil {
		return comptePlateforme{}, fmt.Errorf("creating %q in Keycloak: %w", u.Username, err)
	}
	// The create command prints the new id, but parsing free text is brittle
	// and `get` is the same round trip as trusting it: read the account back,
	// which also proves it is there.
	cree, existe, err := keycloakParNom(ctx, u.Username)
	if err != nil {
		return comptePlateforme{}, err
	}
	if !existe {
		return comptePlateforme{}, fmt.Errorf("Keycloak reported %q created, but reading it back found nothing", u.Username)
	}
	if motDePasse != "" {
		if err := poserMotDePasseKeycloak(ctx, cree.ID, motDePasse); err != nil {
			return comptePlateforme{}, err
		}
	}
	return cree, nil
}

// poserMotDePasseKeycloak sets one account's password.
//
// THE PASSWORD TRAVELS ON STANDARD INPUT, up to the pod: it never appears in
// this process's arguments (visible in ps on the operator's machine) nor in the
// Kubernetes API request body. Inside the pod it is expanded from a shell
// variable into kcadm's argv, which kcadm offers no way around — the exposure is
// limited to the pod's own process list for the duration of the call, on a
// machine only the platform administrators can read.
func poserMotDePasseKeycloak(ctx context.Context, id, motDePasse string) error {
	commande := `IFS= read -r ceffio_mdp || exit 1; ` + kcadmBin +
		" set-password -r " + realmCeffio +
		" --userid " + entreGuillemets(id) + ` --new-password "$ceffio_mdp"`
	if _, err := executerKcadm(ctx, motDePasse, commande); err != nil {
		return fmt.Errorf("setting the password of the account %q: %w", id, err)
	}
	return nil
}

// activerCompteKeycloak opens or closes the account's sessions.
func activerCompteKeycloak(ctx context.Context, u module.User, actif bool) error {
	valeur := "false"
	if actif {
		valeur = "true"
	}
	_, err := executerKcadm(ctx, "", kcadmBin+" update users/"+entreGuillemets(u.ID)+
		" -r "+realmCeffio+" -s enabled="+valeur)
	if err != nil {
		return fmt.Errorf("setting the \"enabled\" flag of %q: %w", u.Username, err)
	}
	return nil
}

// supprimerCompteKeycloak deletes the account, and treats "already gone" as
// success.
//
// WHY: the Keycloak account is the LAST thing the delete sequence removes, so a
// retry after an earlier failure must find the account already deleted. Keycloak
// answers an error for an account that does not exist; re-reading the name is
// what distinguishes "someone else deleted it, we are done" from "the delete
// failed and the account is still there".
func supprimerCompteKeycloak(ctx context.Context, u module.User) error {
	_, err := executerKcadm(ctx, "", kcadmBin+" delete users/"+entreGuillemets(u.ID)+" -r "+realmCeffio)
	if err == nil {
		return nil
	}
	if _, encore, errTrouve := keycloakParNom(ctx, u.Username); errTrouve == nil && !encore {
		return nil
	}
	return fmt.Errorf("deleting %q from Keycloak: %w", u.Username, err)
}

// ecrireCompteKeycloak writes a module's AccountResult to the platform account:
// the address, and the attributes.
//
// WHY READ, MERGE, WRITE: a kcadm update with `-s` replaces the fields it names
// but the contract's attributes are nested, and a whole-representation update
// built from scratch would erase every attribute this platform did not write.
// Reading the representation first is the only way to merge safely. The document
// goes to kcadm through standard input and a 0600 temporary file, removed in
// the same shell — the same pattern internal/platformmail uses for a realm.
func ecrireCompteKeycloak(ctx context.Context, u module.User, res module.AccountResult) error {
	if res.Email == "" && len(res.Attributes) == 0 {
		return nil
	}
	sortie, err := executerKcadm(ctx, "", kcadmBin+" get users/"+entreGuillemets(u.ID)+" -r "+realmCeffio)
	if err != nil {
		return fmt.Errorf("reading %q back from Keycloak: %w", u.Username, err)
	}
	var repr map[string]any
	if err := json.Unmarshal([]byte(corpsJSON(sortie)), &repr); err != nil {
		return fmt.Errorf("reading %q back from Keycloak: %w", u.Username, err)
	}
	if res.Email != "" {
		// A module-assigned address is the one the account answers on: it is
		// verified, not pending.
		repr["email"] = res.Email
		repr["emailVerified"] = true
	}
	if len(res.Attributes) > 0 {
		attrs, _ := repr["attributes"].(map[string]any)
		if attrs == nil {
			attrs = map[string]any{}
		}
		for k, v := range res.Attributes {
			attrs[k] = []string{v}
		}
		repr["attributes"] = attrs
	}
	doc, err := json.Marshal(repr)
	if err != nil {
		return fmt.Errorf("encoding the account of %q: %w", u.Username, err)
	}
	commande := `umask 077; f=$(mktemp) || exit 1; cat > "$f"; ` +
		kcadmBin + " update users/" + entreGuillemets(u.ID) + " -r " + realmCeffio + ` -f "$f" >/dev/null; ` +
		`rc=$?; rm -f "$f"; exit $rc`
	if _, err := executerKcadm(ctx, string(doc), commande); err != nil {
		return fmt.Errorf("writing the account of %q back to Keycloak: %w", u.Username, err)
	}
	return nil
}

// decoderComptes decodes kcadm's answer.
//
// kcadm prints progress lines ("Logging into ...") on the same stream as the
// JSON, so the document is extracted by its brackets before decoding. An answer
// with no document at all is an error, never an empty list: an empty list would
// let the CLI conclude "no users" from a broken command.
func decoderComptes(sortie string) ([]compteKeycloak, error) {
	corps := corpsJSON(sortie)
	if strings.TrimSpace(corps) == "" {
		return nil, fmt.Errorf("kcadm returned no JSON document (output: %s)", tronquer(sortie, 200))
	}
	var bruts []compteKeycloak
	if err := json.Unmarshal([]byte(corps), &bruts); err != nil {
		return nil, fmt.Errorf("decoding the Keycloak answer: %w", err)
	}
	return bruts, nil
}

// corpsJSON returns the JSON document contained in a command's output.
//
// FROM THE FIRST OPENING BRACKET TO THE LAST CLOSING ONE: both objects and
// arrays are handled, and every progress line before or after the document is
// dropped. The output is trusted for nothing else.
func corpsJSON(sortie string) string {
	debut := strings.IndexAny(sortie, "[{")
	if debut < 0 {
		return ""
	}
	fin := strings.LastIndexAny(sortie, "]}")
	if fin <= debut {
		return ""
	}
	return sortie[debut : fin+1]
}

// premierAttribut flattens Keycloak's multi-valued attributes to the contract's
// single value (first one). The attributes this platform writes are
// single-valued; a module that needs several values reads them itself.
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

// ---------------------------------------------------------------------------
// Nextcloud operations

// creerCompteNextcloud creates the file account, and CONVERGES on a retry.
//
// WHY THE `|| true` THEN A VERIFICATION: occ refuses `user:add` for an account
// that already exists — which is exactly the state a retry finds after a later
// step failed. Ignoring the add and then requiring `user:info` keeps the
// command idempotent without believing the add succeeded; an absent account
// still fails, loudly. This is the console's script (internal/console/users.go),
// restated because it is unexported.
func creerCompteNextcloud(ctx context.Context, identifiant, motDePasse string) error {
	// THE PASSWORD GOES THROUGH STANDARD INPUT: occ only accepts it through the
	// environment, and a PodExecOptions cannot set one, so the shell reads the
	// stdin line into OC_PASS. Passing it as an argument would put it in the
	// pod's process list and in this command's request.
	script := `IFS= read -r ceffio_mdp || exit 1; export OC_PASS="$ceffio_mdp"; ` +
		"php occ user:add --password-from-env " + entreGuillemets(identifiant) + " >/dev/null 2>&1 || true; " +
		"php occ user:info " + entreGuillemets(identifiant) + " >/dev/null 2>&1 || { echo 'account absent after creation'; exit 1; }"
	sortie, err := executerOcc(ctx, motDePasse, script)
	if err != nil {
		return fmt.Errorf("creating %q in Nextcloud: %w (output: %s)", identifiant, err, tronquer(sortie, 200))
	}
	return nil
}

// activerCompteNextcloud opens or closes the file account.
func activerCompteNextcloud(ctx context.Context, identifiant string, actif bool) error {
	verbe := "user:enable"
	if !actif {
		verbe = "user:disable"
	}
	sortie, err := executerOcc(ctx, "", "php occ "+verbe+" "+entreGuillemets(identifiant))
	if err != nil {
		return fmt.Errorf("%s %q: %w (output: %s)", verbe, identifiant, err, tronquer(sortie, 200))
	}
	return nil
}

// supprimerCompteNextcloud deletes the file account.
func supprimerCompteNextcloud(ctx context.Context, identifiant string) error {
	sortie, err := executerOcc(ctx, "", "php occ user:delete "+entreGuillemets(identifiant))
	if err != nil {
		return fmt.Errorf("deleting %q from Nextcloud: %w (output: %s)", identifiant, err, tronquer(sortie, 200))
	}
	return nil
}

// ecrireEmailNextcloud writes the module-assigned address to the file account.
//
// WHY IT MATTERS: the address Nextcloud knows is what it uses to send share
// notifications and to look the user up in the address book; leaving the
// operator's value there while the mailbox answers on another address makes
// Nextcloud claim an address that is not the user's.
func ecrireEmailNextcloud(ctx context.Context, identifiant, email string) error {
	if email == "" {
		return nil
	}
	sortie, err := executerOcc(ctx, "", "php occ user:setting "+entreGuillemets(identifiant)+
		" settings email "+entreGuillemets(email))
	if err != nil {
		return fmt.Errorf("setting the email of %q in Nextcloud: %w (output: %s)", identifiant, err, tronquer(sortie, 200))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shell and text utilities

// entreGuillemets wraps a value in single quotes for a POSIX shell.
//
// Needed for every value the CLI interpolates into a script: a password with
// !@#$%&*, an address with an apostrophe, or a username with a space would
// otherwise be interpreted by the pod's shell, and the value that arrives would
// not be the one displayed. The escaped form is the standard '\” sequence.
func entreGuillemets(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// tronquer shortens a command's output for an error message.
//
// A pod's output can be thousands of lines (a Keycloak stack trace); the message
// is shown on a terminal, and the useful part is at the beginning.
func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
