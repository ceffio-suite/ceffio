// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/sso"
	"github.com/ceffio-suite/ceffio/internal/storage"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Images: READ FROM THE REGISTRY, never written here — a copy is what let the
// registry move while the cluster stayed behind (TestAucuneImageEnDurHorsDuRegistre).
var (
	imageOpenProject = version.Image("openproject")
	imageProxy       = version.Image("oauth2-proxy")
)

// Seams, so the install sequence can be tested without a vault or Keycloak.
var (
	assurerClient = sso.AssurerClient
	// assurerRoleVault asserts the vault policy and the Kubernetes role the
	// registry declares for this module. See step 0 of installer for why the
	// install cannot leave that to `ceffio vault`.
	assurerRoleVault = vault.AssurerRoleModule
	lireCoffre       = func(ctx context.Context, composant, nom string) (map[string]string, error) {
		return secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), composant, nom)
	}
	ecrireCoffre = func(ctx context.Context, composant, nom string, v map[string]string) error {
		return secrets.EcrireDansCoffre(ctx, secrets.DepuisEnvironnement(), composant, nom, v)
	}
)

// sortie returns where progress is written: the operation journal in the
// console, stdout in the CLI.
func sortie(env module.Env) io.Writer {
	if env.Out != nil {
		return env.Out
	}
	return io.Discard
}

// installer deploys the module. EVERY STEP IS RE-RUNNABLE, and says how.
func installer(ctx context.Context, env module.Env) error {
	domaine := env.Domain
	if domaine == "" {
		return erreurDomaine()
	}
	out := sortie(env)
	cli, err := nouveauClient()
	if err != nil {
		return fmt.Errorf("openproject: Kubernetes client: %w", err)
	}

	// 0. THE VAULT ROLE AND ITS POLICY, BEFORE THE FIRST POD.
	//
	// `ceffio vault` builds one policy and one Kubernetes role per module from
	// the registry it read WHEN IT WAS DEPLOYED. A vault deployed by an earlier
	// binary therefore has no role for a module added since, and the injector
	// says so from inside a failing init container:
	//
	//	vault-agent-init: Code: 400. Errors: * invalid role name "openproject"
	//
	// The installation then waits 15 minutes for pods that cannot start, and
	// names neither the cause nor the fix. Measured on the acceptance run of
	// 2026-11-21. Asserting the access here costs two vault writes and turns
	// that failure into a message.
	//
	// THE ACCESS COMES FROM THE REGISTRY, not from a second copy of the paths:
	// what the module declares is exactly what the install asserts.
	fmt.Fprintln(out, "∙ openproject: vault policy and Kubernetes role")
	for _, acces := range (&openprojectModule{}).Info().Vault {
		if err := assurerRoleVault(ctx, cli, idModule, acces.ServiceAccount, acces.Namespace, acces.Paths); err != nil {
			return fmt.Errorf("openproject: vault access: %w", err)
		}
	}

	// 1. THE SECRETS, GENERATED ONCE AND REUSED. A regenerated database
	// password breaks the pair with the role; a regenerated Rails secret
	// invalidates every session and every signed link; a regenerated cookie
	// secret signs everybody out. So an existing value always wins.
	fmt.Fprintln(out, "∙ openproject: secrets")
	pwDB, err := assurerEntree(ctx, coffreDB, map[string]int{"password": 24}, map[string]string{"username": dbUser})
	if err != nil {
		return err
	}
	if _, err := assurerEntree(ctx, coffreApp, map[string]int{"secret_key_base": 64, "admin_password": 24}, nil); err != nil {
		return err
	}

	// 2. THE DATABASE AND ITS ROLE, idempotently: created when absent, and the
	// password re-asserted every time so the role always matches the vault.
	fmt.Fprintln(out, "∙ openproject: PostgreSQL database and role")
	if err := assurerBase(ctx, cli, pwDB["password"]); err != nil {
		return err
	}

	// 3. THE KEYCLOAK CLIENT of the proxy. Audience is required: oauth2-proxy
	// checks that the token is meant for it, and Keycloak only puts the client
	// in `aud` with an explicit mapper (see sso.Client.Audience).
	fmt.Fprintln(out, "∙ openproject: Keycloak client")
	secretClient, err := assurerClient(ctx, sso.Client{
		ID:              clientOIDC,
		Redirects:       "https://" + nomHote(domaine) + "/oauth2/callback",
		PostLogout:      "https://" + nomHote(domaine) + "/",
		Public:          false,
		Audience:        true,
		CoffreComposant: coffreComposant,
		CoffreChemin:    coffreProxy,
	})
	if err != nil {
		return err
	}
	if secretClient == "" {
		return fmt.Errorf("openproject: the Keycloak client %q has no secret: a confidential "+
			"client must have one, and the proxy cannot sign anybody in without it", clientOIDC)
	}
	if err := assurerCookie(ctx); err != nil {
		return err
	}

	// 4. THE OBJECTS, in dependency order: the identity and volume first
	// (a pod naming a missing ServiceAccount is never created), the policy
	// BEFORE the application (so OpenProject is never reachable unguarded,
	// not even during its first start), then the application, the proxy and
	// the route. Appliquer creates or updates each object: re-running converges.
	//
	// THE RESPONDER COMES BEFORE THE APPLICATION, and its address is in the auth
	// source the administrator step writes: a pod that starts while the lookup
	// answers nothing signs nobody in, and the next account creation would point
	// at a name that resolves.
	fmt.Fprintln(out, "∙ openproject: "+imageOpenProject)
	annProxy, err := annotationsProxy()
	if err != nil {
		return err
	}
	for _, doc := range []string{
		manifesteBase(storage.Classe()),
		manifestePolitique(),
		manifesteRepondant(),
		manifesteApp(domaine, annotationsApp(), imageOpenProject),
		manifesteProxy(domaine, annProxy, imageProxy),
		manifesteRoute(domaine, ingress.PourDomaine(domaine)),
	} {
		if err := cli.Appliquer(ctx, doc); err != nil {
			return fmt.Errorf("openproject: applying the manifests: %w", err)
		}
	}

	// 5. WAIT FOR BOTH, READ BACK. A successful apply means the API accepted
	// the objects, not that OpenProject migrated its database.
	fmt.Fprintln(out, "∙ openproject: waiting for the first start (migrations included)...")
	// THE RESPONDER FIRST: it starts in a second and the application's sign-in
	// depends on it, so waiting for it costs nothing and removes an ordering
	// question from the first sign-in.
	if err := cli.AttendreDeploiement(ctx, nsProjets, nomRepondant, attenteRepondant); err != nil {
		return fmt.Errorf("openproject: the LDAP responder did not become ready: %w", err)
	}
	if err := cli.AttendreDeploiement(ctx, nsProjets, nomApp, attenteApp); err != nil {
		return fmt.Errorf("openproject: the application did not become ready: %w — the "+
			"seeder's log (init container \"seeder\") names the failing migration", err)
	}
	if err := cli.AttendreDeploiement(ctx, nsProjets, nomProxy, attenteProxy); err != nil {
		return fmt.Errorf("openproject: the sign-in proxy did not become ready: %w", err)
	}

	// 6. THE ADMINISTRATOR. Header SSO creates no account, and the seeded
	// "admin" is locked on purpose (manifesteApp): without this step, nobody
	// could administer the instance. Idempotent like every account call.
	fmt.Fprintln(out, "∙ openproject: administrator account ("+compteAdmin+")")
	if err := assurerCompteOpenProject(ctx, cli, compteOP{
		Login: compteAdmin, Mail: mailAdmin, Admin: true,
	}); err != nil {
		return err
	}

	fmt.Fprintf(out, "✓ OpenProject: https://%s — accounts are created from the Users page\n", nomHote(domaine))
	return nil
}

// assurerEntree reads a vault entry and fills the missing keys, ONCE.
//
// longueurs maps a key to its length in random bytes; fixes are constant keys
// (a username). Existing values are never replaced, and the entry is written
// only when something was missing — a re-run writes nothing.
func assurerEntree(ctx context.Context, nom string, longueurs map[string]int, fixes map[string]string) (map[string]string, error) {
	entree, err := lireCoffre(ctx, coffreComposant, nom)
	switch {
	case err == nil:
	case secrets.EntreeAbsente(err):
		entree = nil
	default:
		// AN UNREADABLE VAULT IS NOT AN ABSENT ENTRY: generating here would
		// overwrite a live password the moment the vault answers again.
		return nil, fmt.Errorf("openproject: vault unreadable for %s/%s: %w", coffreComposant, nom, err)
	}
	if entree == nil {
		entree = map[string]string{}
	}
	change := false
	for k, v := range fixes {
		if entree[k] == "" {
			entree[k] = v
			change = true
		}
	}
	for k, n := range longueurs {
		if entree[k] != "" {
			continue
		}
		v, err := genererSecret(n)
		if err != nil {
			return nil, err
		}
		entree[k] = v
		change = true
	}
	if change {
		if err := ecrireCoffre(ctx, coffreComposant, nom, entree); err != nil {
			return nil, err
		}
	}
	return entree, nil
}

// genererSecret returns n random bytes in HEXADECIMAL.
//
// HEX, NOT BASE64: the database password is spliced into a postgres:// URL by
// the injector, and inside psql's SQL by assurerBase. Hexadecimal needs no
// escaping in either place, so no character can ever break the URL or the
// statement — the cheapest way to make quoting a non-question.
func genererSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("openproject: generating a secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// assurerCookie stores the proxy's 32-byte cookie secret next to the client
// secret, once. 32 BYTES because oauth2-proxy refuses anything shorter; URL-safe
// base64 without padding is the form it documents.
func assurerCookie(ctx context.Context) error {
	entree, err := lireCoffre(ctx, coffreComposant, coffreProxy)
	if err != nil && !secrets.EntreeAbsente(err) {
		return fmt.Errorf("openproject: vault unreadable for the proxy entry: %w", err)
	}
	if entree != nil && entree["cookie_secret"] != "" {
		return nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("openproject: generating the cookie secret: %w", err)
	}
	if entree == nil {
		entree = map[string]string{}
	}
	entree["cookie_secret"] = base64.RawURLEncoding.EncodeToString(b)
	return ecrireCoffre(ctx, coffreComposant, coffreProxy, entree)
}

// sqlBase renders the idempotent SQL that creates the role and the database.
//
// IDEMPOTENT BY CONSTRUCTION, because Install is: the role is created only when
// absent, its password re-asserted every time (the vault is the truth), and the
// database created through \gexec only when absent — CREATE DATABASE cannot run
// inside the DO block's transaction.
//
// THE PASSWORD IS HEXADECIMAL (genererSecret), checked here rather than
// escaped: a value that is not what we generated is refused instead of being
// trusted inside a SQL literal.
func sqlBase(motDePasse string) (string, error) {
	if motDePasse == "" || strings.Trim(motDePasse, "0123456789abcdef") != "" {
		return "", fmt.Errorf("openproject: the database password in the vault is not the " +
			"hexadecimal value this module generates; refusing to place it in SQL")
	}
	return fmt.Sprintf(`DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN
    CREATE ROLE %[1]s LOGIN;
  END IF;
END
$$;
ALTER ROLE %[1]s WITH LOGIN PASSWORD '%[2]s';
SELECT 'CREATE DATABASE %[3]s OWNER %[1]s'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%[3]s')\gexec
`, dbUser, motDePasse, dbName), nil
}

// assurerBase runs sqlBase in the PostgreSQL pod.
//
// THROUGH STANDARD INPUT: the statement carries the password, and an argument
// would be readable in the pod's process table.
func assurerBase(ctx context.Context, cli *k8sapi.Client, motDePasse string) error {
	sql, err := sqlBase(motDePasse)
	if err != nil {
		return err
	}
	if out, err := cli.ExecuterAvecEntree(ctx, pgNS, pgPod, "postgres", sql,
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"); err != nil {
		return fmt.Errorf("openproject: creating the database: %w: %s", err, out)
	}
	return nil
}

// lireEtat reads the cluster. It never guesses.
func lireEtat(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		// FAILURE TO LOOK IS UNKNOWN, NEVER ABSENT: offering "install" on top of
		// a module that may already run is worse than saying we do not know.
		return module.State{Status: module.Unknown,
			Detail: "no Kubernetes client: the module state cannot be read"}
	}
	app, errApp := etatDeploiement(ctx, env, nomApp)
	proxy, errProxy := etatDeploiement(ctx, env, nomProxy)
	// THE RESPONDER IS PART OF THE SIGN-IN, so it is part of the state: an
	// installation whose responder is down signs nobody in, and saying
	// "installed" because the other two deployments are ready would hide
	// exactly the failure this module was rebuilt to fix.
	repondant, errRepondant := etatDeploiement(ctx, env, nomRepondant)
	switch {
	case errApp != nil || errProxy != nil || errRepondant != nil:
		return module.State{Status: module.Unknown,
			Detail: "reading the deployments failed: " + premiereErreur(errApp, errProxy, errRepondant)}
	case app == absent && proxy == absent && repondant == absent:
		return module.State{Status: module.Absent}
	case app == pret && proxy == pret && repondant == pret:
		return module.State{Status: module.Installed}
	case app == pret && proxy == pret:
		return module.State{Status: module.Degraded,
			Detail: "the sign-in proxy and OpenProject are ready but the LDAP responder is not: " +
				"no account can sign in until \"openproject-ldap\" runs"}
	case app != pret && proxy == pret:
		return module.State{Status: module.Degraded,
			Detail: "the sign-in works but OpenProject is not ready: users reach an error page " +
				"after signing in (a failing migration is named in the \"seeder\" init container's log)"}
	case app == pret && proxy != pret:
		return module.State{Status: module.Degraded,
			Detail: "OpenProject runs but its sign-in proxy is not ready: the site does not answer"}
	default:
		return module.State{Status: module.Degraded,
			Detail: "neither OpenProject nor its sign-in proxy is ready"}
	}
}

// etatPod is what a Deployment says about itself.
type etatPod int

const (
	absent etatPod = iota
	present
	pret
)

func etatDeploiement(ctx context.Context, env module.Env, nom string) (etatPod, error) {
	d, err := env.Kube.AppsV1().Deployments(nsProjets).Get(ctx, nom, metaGet)
	switch {
	case estIntrouvable(err):
		return absent, nil
	case err != nil:
		return absent, err
	case d.Status.ReadyReplicas > 0:
		return pret, nil
	default:
		return present, nil
	}
}

func premiereErreur(errs ...error) string {
	for _, e := range errs {
		if e != nil {
			return e.Error()
		}
	}
	return ""
}

// desinstaller removes what the module created: the objects of its namespace,
// its database and role, its Keycloak client.
//
// EVERY DELETION IS BEST-EFFORT AND RE-RUNNABLE: an already-absent object is the
// normal case on a second removal, and the console retries after a partial one.
// The errors are collected and reported together rather than stopping at the
// first: stopping would leave everything after it in place, invisible.
//
// NOTHING SHARED IS TOUCHED: the module lives in ceffio-system next to the
// console and the platform's certificates, so it deletes its objects BY NAME
// and never by label or namespace.
//
// THE VAULT ENTRIES ARE KEPT, as the longhorn-ui module does: removing the
// proxy's entry would destroy a client secret still registered in Keycloak if
// the client deletion below failed. They hold a few short strings.
func desinstaller(ctx context.Context, env module.Env) error {
	cli, err := nouveauClient()
	if err != nil {
		return fmt.Errorf("openproject: Kubernetes client: %w", err)
	}
	var erreurs []string
	for _, cible := range []string{
		"Ingress/" + nomIngress,
		"Deployment/" + nomProxy,
		"Service/" + nomProxy,
		"Deployment/" + nomApp,
		"Service/" + nomApp,
		// THE RESPONDER GOES WITH THE APPLICATION: without the application its
		// only client is gone, and a name resolver left behind on the cluster
		// answers nothing useful and gets no upgrade.
		"Deployment/" + nomRepondant,
		"Service/" + nomRepondant,
		"NetworkPolicy/" + nomPolitique,
		"NetworkPolicy/" + nomRepondant + "-only-from-app",
		// THE VOLUME AFTER THE DEPLOYMENT: a PVC still mounted stays
		// Terminating until its pod is gone, which is fine, but deleting it
		// first would make the running pod's writes fail before it stops.
		"PersistentVolumeClaim/" + nomVolume,
		// THE CERTIFICATE AND ITS SECRET: cert-manager leaves the Secret
		// behind when the Certificate goes unless it was told to own it, so
		// both are named.
		"Certificate/" + nomSecretTLS,
		"Secret/" + nomSecretTLS,
		"ServiceAccount/" + nomServiceAccount,
	} {
		if err := cli.SupprimerEfface(ctx, nsProjets, cible); err != nil {
			erreurs = append(erreurs, cible+": "+err.Error())
		}
	}

	// THE DATABASE GOES TOO, and the module's Warning says so: keeping it
	// without the attachments of the deleted volume would leave work packages
	// pointing at files that no longer exist. WITH (FORCE) ends the sessions
	// the terminating pod may still hold.
	sql := fmt.Sprintf("DROP DATABASE IF EXISTS %[1]s WITH (FORCE);\nDROP ROLE IF EXISTS %[2]s;\n", dbName, dbUser)
	if out, err := cli.ExecuterAvecEntree(ctx, pgNS, pgPod, "postgres", sql,
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"); err != nil {
		erreurs = append(erreurs, fmt.Sprintf("database: %v: %s", err, out))
	}

	if err := supprimerClient(ctx, clientOIDC); err != nil {
		erreurs = append(erreurs, "Keycloak client: "+err.Error())
	}
	if len(erreurs) > 0 {
		return fmt.Errorf("openproject: uninstall left %d problem(s): %s",
			len(erreurs), strings.Join(erreurs, " · "))
	}
	return nil
}

// supprimerClient is a seam over sso.SupprimerClientOIDC.
var supprimerClient = sso.SupprimerClientOIDC
