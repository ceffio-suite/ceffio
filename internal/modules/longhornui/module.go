// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package longhornui exposes the Longhorn interface behind the single sign-on, for the
// administrator only.
//
// WHY A PROXY AND NOT THE INTERFACE ITSELF: the Longhorn UI HAS NO AUTHENTICATION.
// Anyone who reaches it can delete a volume, and a volume here is PostgreSQL, the
// Nextcloud files or the mail store. Exposing it directly is not a permission
// decision, it is a data-loss one.
//
// SO THE ONLY THING EXPOSED IS oauth2-proxy, which performs the OIDC exchange with
// Keycloak and then decides — on the token's `email` claim — whether to pass the
// request to the interface or refuse it. The interface itself stays a ClusterIP.
//
// THE MODULE IS OPTIONAL AND OFF BY DEFAULT: an administration interface with this much
// power does not install itself.
package longhornui

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// Identifiants du module.
const (
	idModule    = "longhorn-ui"
	nsSysteme   = "ceffio-system"
	nsLonghorn  = "longhorn-system"
	nomDeploy   = "longhorn-oauth2-proxy"
	nomService  = "longhorn-oauth2-proxy"
	nomConfig   = "longhorn-oauth2-proxy-emails"
	clientOIDC  = "longhorn"
	sousDomaine = "longhorn"

	// devi est l'URL publique de l'interface, construite par le module.
	cheminAdresses = "/etc/oauth2-proxy/emails"
	adresseDefaut  = "adminceffio@ceffio.local"
)

// longhornUIModule is the "longhorn-ui" module.
type longhornUIModule struct{}

func init() { module.Register(&longhornUIModule{}) }

// Info describes the module.
func (m *longhornUIModule) Info() module.Info {
	return module.Info{
		ID:          idModule,
		Title:       "Storage interface (Longhorn)",
		Description: "Volume management, reserved to the administrator, behind single sign-on.",
		Kind:        module.Optional,
		Default:     false,

		// THE STORAGE, THE IDENTITY AND THE INGRESS are all three required, and each
		// for a reason a reader can check: the proxy proxies to Longhorn, it
		// authenticates against Keycloak, and it is reached through Traefik.
		Requires: []string{"storage", "identity", "ingress"},

		Namespaces: []string{nsSysteme},

		// THE MODULE DECLARES WHAT ITS POD READS, and the vault layer builds both
		// the policy and the Kubernetes auth role from this declaration — role
		// name = module ID, bound to this ServiceAccount in this namespace.
		//
		// READ ONLY, AND UNDER ITS OWN PREFIX: vault.PolitiqueModule refuses
		// anything outside kv/data/ceffio/longhorn-ui/, so this line cannot be
		// widened by a typo without failing the provisioning.
		Vault: []module.VaultAccess{{
			ServiceAccount: nomServiceAccount,
			Namespace:      nsSysteme,
			Paths:          []string{cheminCoffre},
		}},

		Services: []module.Service{
			{
				Sub:         sousDomaine,
				Name:        "Longhorn",
				Role:        "Storage volumes — administrator only",
				Technical:   true,
				SSO:         true,
				PodPrefixes: []string{nomDeploy},
			},
		},

		Warning: "This interface can DELETE VOLUMES, and therefore data. It is reachable " +
			"only by the addresses allowed in its settings.",

		// THE RIGHTS, NARROW ON PURPOSE: everything this module creates lives in
		// ceffio-system, and NOTHING is written in longhorn-system. The proxy only
		// needs to reach a ClusterIP there, which is a Service resolution — not an
		// API permission.
		Permissions: []module.Permission{permissionsLonghornUI()},
	}
}

// Install deploys the proxy, its client, its settings and its route. Idempotent.
func (m *longhornUIModule) Install(ctx context.Context, env module.Env) error {
	return installer(ctx, env)
}

// State reports Installed only when the proxy is ready AND its client exists.
//
// BOTH HALVES MATTER: a running proxy with no client redirects to a Keycloak error
// page, which looks like an outage rather than a configuration gap. Saying Degraded
// with the missing half named is what makes it fixable.
func (m *longhornUIModule) State(ctx context.Context, env module.Env) module.State {
	return etat(ctx, env)
}

// Uninstall removes everything this module created, and NOTHING in longhorn-system.
func (m *longhornUIModule) Uninstall(ctx context.Context, env module.Env) error {
	return desinstaller(ctx, env)
}

// nomHote is the public host of the interface.
func nomHote(domaine string) string {
	return sousDomaine + "." + domaine
}

// erreurDomaine is returned whenever the domain is missing: every address this module
// declares is built from it, and a wrong one produces a client that Keycloak refuses to
// redirect to.
func erreurDomaine() error {
	return fmt.Errorf("longhorn-ui: the domain is required — the redirect URI, the cookie " +
		"domain and the ingress host are all built from it")
}

// nomConfigReglages is the ConfigMap the SETTINGS store writes to (not the one holding
// the rendered file of addresses: one is the source, the other is what the proxy reads).
const nomConfigReglages = "ceffio-settings-longhorn-ui"

// ManifestePourTest exposes the Service and Ingress documents for the plan's proof.
func ManifestePourTest(domaine string) string {
	return manifesteServiceEtRoute(domaine)
}
