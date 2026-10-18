// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package data declares the "data" layer (CloudNativePG operator,
// PostgreSQL, Valkey) as a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/data and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
package data

import (
	"context"

	coucheData "github.com/ceffio-suite/ceffio/internal/data"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

const (
	// The namespace of the databases (internal/data/data.go, pgNamespace).
	nsData = "ceffio-data"
	// The CNPG operator lives in ITS OWN namespace (Helm chart): the layer
	// installs it and waits for it to be ready — the state must read it
	// there.
	nsCNPG = "cnpg-system"
)

// dataModule is the "data" module.
type dataModule struct{}

func init() { module.Register(&dataModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core belongs to the explicit sequence of cmd/ceffio/install.go.
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

// Install delegates to data.Deploy, unchanged — see the note in platform:
// the registry describes, the installer remains master of the core order.
func (m *dataModule) Install(ctx context.Context, env module.Env) error {
	return coucheData.Deploy(ctx)
}

// State reads the cluster: the CNPG operator ready (deployPostgres waits
// for it), and the pods of the PostgreSQL cluster and of Valkey ready in
// ceffio-data.
func (m *dataModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatDuDeploiement(ctx, env, nsCNPG, "cnpg-cloudnative-pg"),
		socle.EtatDesPods(ctx, env, []string{nsData},
			[]string{"ceffio-pg", "ceffio-valkey"}),
	)
}

// Uninstall refuses: removing PostgreSQL would erase the data of the whole
// suite — the core is removed with the cluster (ceffio uninstall).
func (m *dataModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
