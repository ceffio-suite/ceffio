// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package identity declares the "identity" layer (Keycloak, the SSO) as a
// Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/identity and
// remains driven by cmd/ceffio/install.go. This package DESCRIBES the layer
// so that the state and the diagnostic read it in the registry.
package identity

import (
	"context"

	coucheIdentity "github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// The namespace of Keycloak (internal/identity/identity.go, ns).
const nsIdentity = "ceffio-identity"

// identityModule is the "identity" module.
type identityModule struct{}

func init() { module.Register(&identityModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (identity AFTER data, because Keycloak needs its database) belongs
// to the explicit sequence of cmd/ceffio/install.go.
func (m *identityModule) Info() module.Info {
	return module.Info{
		ID:          "identity",
		Title:       "Identity (SSO)",
		Description: "Keycloak: one login for every application of the suite.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsIdentity},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsIdentity)},

		// EXACT copy of the "keycloak" entry of catalogueServices
		// (internal/console/status.go): same texts, same SSO=false —
		// Keycloak IS the entry point of the SSO, it does not go through
		// itself.
		Services: []module.Service{
			{
				Sub:         "keycloak",
				Name:        "Keycloak",
				Role:        "Single sign-on (SSO) for all apps",
				Technical:   false,
				SSO:         false,
				PodPrefixes: []string{"keycloak"},
			},
		},
	}
}

// Install delegates to identity.Deploy, unchanged — the registry describes,
// the sequence of cmd/ceffio/install.go remains master of the core order.
func (m *identityModule) Install(ctx context.Context, env module.Env) error {
	return coucheIdentity.Deploy(ctx)
}

// State reads the cluster: the Deployment keycloak ready in
// ceffio-identity.
func (m *identityModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsIdentity, "keycloak")
}

// Uninstall refuses: without identity, nobody can log in to anything
// anymore — the core is removed with the cluster (ceffio uninstall).
func (m *identityModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
