// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package platform declares the "platform" layer (namespaces, cert-manager,
// TLS authorities) as a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/platform and
// remains driven by the explicit sequence of cmd/ceffio/install.go. This
// package rewrites nothing: it DESCRIBES the layer (state, namespaces,
// services) so that the CLI, the console and the doctor read the core in
// the registry, instead of guessing it.
package platform

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	couchePlatform "github.com/ceffio-suite/ceffio/internal/platform"
)

const (
	// The namespace of the umbrella chart and of the Helm release "ceffio"
	// (internal/platform/platform.go, installUmbrella).
	nsSystem = "ceffio-system"
	// cert-manager lives in ITS OWN namespace (jetstack chart): the state
	// of the layer is read there, not in ceffio-system.
	nsCertManager = "cert-manager"
	// The umbrella chart creates this namespace (internal/charts/ceffio/
	// values.yaml, namespaces.observability) and no other module owns it —
	// the platform layer declares its permissions.
	nsObservability = "ceffio-observability"
	// The ExApp namespace, prepared unconditionally by exapps.Preparer
	// (internal/exapps): the platform topology owns its console rights, so
	// they do not depend on the Optional exapps-daemon module staying
	// registered.
	nsExapps = "ceffio-exapps"
)

// platformModule is the "platform" module.
type platformModule struct{}

func init() { module.Register(&platformModule{}) }

// Info describes the layer. Requires remains DELIBERATELY empty for all
// Core modules: the order of the core (platform ‖ data → vault → identity → …)
// belongs to the explicit sequence of cmd/ceffio/install.go, which stays in
// charge; duplicating it here would create a second source of truth, with
// the risk that it contradicts the first.
func (m *platformModule) Info() module.Info {
	return module.Info{
		ID:          "platform",
		Title:       "Platform",
		Description: "Namespaces, cert-manager and the certificate authorities every other layer relies on.",
		Kind:        module.Core,
		Default:     true,

		// Both namespaces are real: the umbrella chart lays down the
		// ceffio-* namespaces from ceffio-system, and cert-manager
		// (expected ready by waitCertManagerReady) lives in cert-manager.
		Namespaces: []string{nsSystem, nsCertManager},

		// Permissions (batch B6): the console's namespace-scoped rights are
		// the SUM of the module registry, and the sum must reproduce the
		// former hand-written grant exactly (see socle.StandardPermission).
		// The platform layer owns the namespaces of the install sequence's
		// topology that no application module owns:
		//   - ceffio-system: the umbrella release namespace;
		//   - ceffio-observability: created by the umbrella chart
		//     (internal/charts/ceffio/values.yaml);
		//   - ceffio-exapps: prepared UNCONDITIONALLY by exapps.Preparer in
		//     the install sequence — the legacy RoleBinding existed whether
		//     or not HaRP was deployed, so the Core platform module carries
		//     it, not the Optional exapps-daemon (whose own declaration is a
		//     subset, merged into this one).
		// cert-manager and cnpg-system deliberately get NOTHING: the legacy
		// grant excluded them — infrastructure namespaces are not driven
		// from the console.
		Permissions: []module.Permission{
			socle.StandardPermission(nsSystem),
			socle.StandardPermission(nsObservability),
			socle.StandardPermission(nsExapps),
		},
	}
}

// Install delegates to platform.Deploy, unchanged.
//
// WHY THE DELEGATION DOES NOT MAKE THE REGISTRY THE INSTALLER: the core
// sequence remains in cmd/ceffio/install.go. This method honors the
// module.Module contract and lets a frontend replay ONE layer identically —
// not reorder the core.
func (m *platformModule) Install(ctx context.Context, env module.Env) error {
	return couchePlatform.Deploy(ctx)
}

// State reads the cluster: the ceffio-system namespace active and the three
// cert-manager Deployments ready — exactly what platform.Deploy waits for
// before continuing (waitCertManagerReady).
func (m *platformModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatNamespaceActif(ctx, env, nsSystem),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager"),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager-cainjector"),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager-webhook"),
	)
}

// Uninstall refuses: the core is removed with the cluster (ceffio
// uninstall), never layer by layer — see socle.ErreurSocleIndemontable.
func (m *platformModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
