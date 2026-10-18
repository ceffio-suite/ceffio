// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package identity déclare la couche « identity » (Keycloak, le SSO) comme
// module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans
// internal/identity et reste pilotée par cmd/ceffio/install.go. Ce package
// DÉCRIT la couche pour que l'état et le diagnostic la lisent dans le
// registre.
package identity

import (
	"context"

	coucheIdentity "github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// Le namespace de Keycloak (internal/identity/identity.go, ns).
const nsIdentity = "ceffio-identity"

// identityModule est le module « identity ».
type identityModule struct{}

func init() { module.Register(&identityModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (identité APRÈS data, car Keycloak a besoin de sa base) appartient à la
// séquence explicite de cmd/ceffio/install.go.
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

		// Reprise EXACTE de l'entrée « keycloak » de catalogueServices
		// (internal/console/status.go) : mêmes textes, même SSO=false —
		// Keycloak EST la porte d'entrée du SSO, il ne passe pas par
		// lui-même.
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

// Install délègue à identity.Deploy, inchangé — le registre décrit, la
// séquence de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *identityModule) Install(ctx context.Context, env module.Env) error {
	return coucheIdentity.Deploy(ctx)
}

// State lit le cluster : le Deployment keycloak prêt dans ceffio-identity.
func (m *identityModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsIdentity, "keycloak")
}

// Uninstall refuse : sans identité, plus personne ne peut se connecter à
// rien — le socle se retire avec le cluster (ceffio uninstall).
func (m *identityModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
