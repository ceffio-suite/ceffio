// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package openproject installs OpenProject — project management, work packages,
// Gantt charts, boards, time tracking — as an OPTIONAL module of the suite.
//
// # Why the sign-in goes through oauth2-proxy and not OpenID Connect
//
// OpenProject's OpenID Connect providers are an ENTERPRISE add-on: the
// documentation page that configures them says "OpenID Connect providers is an
// Enterprise add-on", and the Community edition hides the button. Ceffio ships
// software nobody has to subscribe to, so the module cannot rely on it.
//
// What the Community edition DOES offer is header-based "auth source SSO"
// (OPENPROJECT_AUTH__SOURCE__SSO_HEADER): a trusted reverse proxy names the
// signed-in user in a header, and OpenProject logs that user in. Ceffio already
// runs that proxy for the Longhorn interface — oauth2-proxy, in front of
// Keycloak — so the module reuses the same pattern:
//
//	browser → Traefik → oauth2-proxy (OIDC with Keycloak) → OpenProject
//	                         sets X-Forwarded-Preferred-Username
//
// # The two things that make a trusted header safe
//
//  1. NOTHING BUT THE PROXY REACHES OPENPROJECT. The Ingress points at the
//     proxy, never at OpenProject, and a NetworkPolicy refuses every other pod
//     in the cluster: a header is only as trustworthy as the set of clients
//     that can send it.
//  2. THE PROXY OVERWRITES THE HEADER. oauth2-proxy sets X-Forwarded-* user
//     headers from the token it validated, so a browser cannot smuggle one in.
//
// # Why users must be provisioned
//
// Header SSO does NOT create accounts: auth_source_sso.rb looks the login up
// and, when nobody matches, redirects to a failure page. The module therefore
// takes part in the Users page (module.Accounts): creating a Ceffio user
// creates the OpenProject account, and the page offers a "create" action for
// users that existed before the module was installed.
//
// AND THE LOOKUP ITSELF IS AN LDAP SEARCH: OpenProject resolves the header's
// login through the account's auth source (LdapAuthSource.find_user), not
// against its own database. An account linked to a source that names no
// reachable directory is active, has the right flags, and still cannot sign
// in — the state the module ships today, documented in docs/openproject.md.
package openproject

import (
	"context"
	"fmt"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// Identifiers of the module. They appear in object names, in the vault path and
// in the Keycloak client, so they are stable.
const (
	idModule = "openproject"

	// nsProjets is where the module lives: ceffio-system, like longhorn-ui.
	//
	// NOT A NAMESPACE OF ITS OWN, and the reason is the console's grant: the
	// console holds a Role in each platform namespace, generated from the
	// registry and pinned by rbac_nonregression_test.go to the ten namespaces
	// that exist on every installation. A Role in a namespace that does not
	// exist yet makes the console's own deployment fail, and an optional
	// module's namespace does not exist until the module is installed.
	// ceffio-system also already holds the HTTPS redirection middleware
	// Traefik requires in the Ingress's own namespace.
	nsProjets = "ceffio-system"

	// sousDomaine: projects.<domain>.
	sousDomaine = "projects"

	nomApp            = "openproject"
	nomProxy          = "openproject-proxy"
	nomServiceAccount = "openproject"
	nomVolume         = "openproject-assets"
	nomIngress        = "openproject"
	nomPolitique      = "openproject-only-from-proxy"
	nomSecretTLS      = "projects-tls"

	// nomRepondant is the LDAP responder OpenProject's header SSO looks the user
	// up in (repondant.go). NOT A DIRECTORY: it answers one search, from the
	// query itself, and holds nothing.
	nomRepondant = "openproject-ldap"

	// portRepondant is UNPRIVILEGED on purpose: the responder runs as an
	// unprivileged user and 389 belongs to root. Nothing reads the port except
	// this module — no LDAP client is configured with it by hand.
	portRepondant = 1389

	// uidRepondant is the unprivileged user the Ceffio image runs the responder
	// as, the same one the public-IP reporter uses.
	uidRepondant = 65532

	// clientOIDC is the Keycloak client the PROXY uses. OpenProject itself
	// never talks to Keycloak.
	clientOIDC = "openproject"

	// PostgreSQL: the shared CloudNativePG cluster of the data layer, one
	// database and one role for this module — the convention of
	// internal/files and internal/identity.
	pgPod     = "ceffio-pg-1"
	pgNS      = "ceffio-data"
	pgService = "ceffio-pg-rw.ceffio-data.svc"
	dbName    = "openproject"
	dbUser    = "openproject"
)

// Vault layout: component "openproject", three entries.
//
// SPLIT BY CONSUMER, not by kind: the database credentials and the Rails secret
// are read by the application pod, the client and cookie secrets by the proxy.
const (
	coffreComposant = idModule
	coffreDB        = "db"           // username, password
	coffreApp       = "app"          // secret_key_base, admin_password
	coffreProxy     = "oauth2-proxy" // client-secret (written by sso), cookie_secret
)

// cheminCoffre returns the KV v2 path the injector reads for an entry.
func cheminCoffre(entree string) string {
	return "kv/data/ceffio/" + coffreComposant + "/" + entree
}

// Timeouts, all measured or derived from a measurement elsewhere in the suite.
var (
	// The FIRST start runs every migration and the seed of a fresh database;
	// on the Rails apps of this suite that is minutes, not seconds, and a
	// Longhorn volume attachment on a fresh disk adds up to six minutes on its
	// own (see waitNextcloudReady in internal/files). 15 minutes is that sum
	// with margin, and a later install converges in seconds.
	attenteApp   = 15 * time.Minute
	attenteProxy = 5 * time.Minute

	// The responder has no volume, no migration and no secret to read: a
	// second or two from scheduling to listening. A minute is the cluster's
	// own slowness with margin, and the wait is what makes the first sign-in
	// safe rather than lucky.
	attenteRepondant = 1 * time.Minute
)

// nouveauClient is a variable so tests can run the contract without a cluster.
var nouveauClient = k8sapi.Nouveau

// openprojectModule is the registry entry.
type openprojectModule struct{}

func init() { module.Register(&openprojectModule{}) }

// Info describes the module.
func (m *openprojectModule) Info() module.Info {
	return module.Info{
		ID:    idModule,
		Title: "Project management (OpenProject)",
		Description: "Projects, work packages, Gantt charts, boards and time tracking, " +
			"behind the single sign-on.",
		Kind: module.Optional,
		// OFF BY DEFAULT: ~4 GiB of RAM is not something every installation
		// should receive without asking for it.
		Default: false,

		// EACH DEPENDENCY IS A REAL ONE: the database lives in the data layer,
		// the sign-in in Keycloak, the route and certificate in the ingress
		// layer, the secrets in the vault, the attachments on Longhorn.
		Requires: []string{"storage", "data", "identity", "vault", "ingress"},

		Namespaces: []string{nsProjets},

		// ONE IDENTITY FOR BOTH PODS. The application and its proxy run under
		// the same ServiceAccount, so a single vault role covers them — the
		// vault layer builds exactly one role per module, named after its ID.
		// Read only, and only under kv/data/ceffio/openproject/.
		Vault: []module.VaultAccess{{
			ServiceAccount: nomServiceAccount,
			Namespace:      nsProjets,
			Paths:          []string{"kv/data/ceffio/" + coffreComposant + "/*"},
		}},

		Services: []module.Service{{
			Sub:         sousDomaine,
			Name:        "OpenProject",
			Role:        "Projects, work packages and planning",
			SSO:         true,
			PodPrefixes: []string{nomApp, nomProxy},
		}},

		// Measured on the upstream recommendations, not guessed: OpenProject
		// asks for 4 GiB of RAM for a small installation; the volume holds the
		// attachments.
		Resources: "~4 GiB RAM, 10 GiB disk (attachments) and one PostgreSQL database",

		Warning: "Removing this module DELETES every project, work package and " +
			"attachment: the database and the volume go with it.",

		Permissions: []module.Permission{permissionsSysteme(), permissionsDonnees()},
	}
}

// Install deploys OpenProject and its sign-in. Idempotent.
func (m *openprojectModule) Install(ctx context.Context, env module.Env) error {
	return installer(ctx, env)
}

// State is Installed only when the application, its proxy AND its LDAP
// responder are ready: the responder resolves the login of every sign-in, so
// an installation without it signs nobody in.
func (m *openprojectModule) State(ctx context.Context, env module.Env) module.State {
	etat := module.State{Blocked: module.Blocked(ctx, env, m)}
	e := lireEtat(ctx, env)
	e.Blocked = etat.Blocked
	return e
}

// Uninstall removes everything the module created, data included.
func (m *openprojectModule) Uninstall(ctx context.Context, env module.Env) error {
	return desinstaller(ctx, env)
}

// nomHote is the public host.
func nomHote(domaine string) string { return sousDomaine + "." + domaine }

// erreurDomaine: every address of the module is built from the domain.
func erreurDomaine() error {
	return fmt.Errorf("openproject: the domain is required — the host name, the " +
		"redirect URI of the sign-in and the certificate are all built from it")
}
