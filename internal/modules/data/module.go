// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package data déclare la couche « data » (opérateur CloudNativePG,
// PostgreSQL, Valkey) comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/data
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
package data

import (
	"context"

	coucheData "github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

const (
	// Le namespace des bases (internal/data/data.go, pgNamespace).
	nsData = "ceffio-data"
	// L'opérateur CNPG vit dans SON namespace (chart Helm) : la couche
	// l'installe et l'attend prêt — l'état doit le lire là.
	nsCNPG = "cnpg-system"
)

// dataModule est le module « data ».
type dataModule struct{}

func init() { module.Register(&dataModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// appartient à la séquence explicite de cmd/ceffio/install.go.
func (m *dataModule) Info() module.Info {
	return module.Info{
		ID:          "data",
		Title:       "Data",
		Description: "PostgreSQL and Valkey: the databases and cache every application of the suite stores its state in.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsData, nsCNPG},

		// Permissions (batch B6): the console administers ceffio-data —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission). cnpg-system gets NOTHING: the legacy
		// grant excluded it — the operator's namespace is infrastructure,
		// not driven from the console (the PostgreSQL CLUSTERS live in the
		// application namespaces, and their postgresql.cnpg.io rights come
		// with the standard set).
		Permissions: []module.Permission{socle.StandardPermission(nsData)},
	}
}

// Install délègue à data.Deploy, inchangé — voir la note de platform :
// le registre décrit, l'installateur reste maître de l'ordre du socle.
func (m *dataModule) Install(ctx context.Context, env module.Env) error {
	return coucheData.Deploy(ctx)
}

// State lit le cluster : l'opérateur CNPG prêt (deployPostgres l'attend),
// et les pods du cluster PostgreSQL et de Valkey prêts dans ceffio-data.
func (m *dataModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatDuDeploiement(ctx, env, nsCNPG, "cnpg-cloudnative-pg"),
		socle.EtatDesPods(ctx, env, []string{nsData},
			[]string{"ceffio-pg", "ceffio-valkey"}),
	)
}

// Uninstall refuse : retirer PostgreSQL effacerait les données de toute la
// suite — le socle se retire avec le cluster (ceffio uninstall).
func (m *dataModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
