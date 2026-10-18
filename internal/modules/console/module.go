// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package console declares the "console" layer (the web administration
// console) as a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/console/deploy.go
// and remains driven by cmd/ceffio/install.go. This package DESCRIBES the
// layer so that the state and the diagnostic read it in the registry.
//
// HONESTY NOTE: the console is also the frontend that READS the registry —
// but no cycle is possible: this package imports internal/console (the
// layer), not the reverse; internal/console imports NO module.
package console

import (
	"context"

	coucheConsole "github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// The namespace of the console (internal/console/deploy.go, deployNS).
const nsSystem = "ceffio-system"

// consoleModule is the "console" module.
type consoleModule struct{}

func init() { module.Register(&consoleModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (console deployed LAST, after everything it administers) belongs to
// the explicit sequence of cmd/ceffio/install.go.
func (m *consoleModule) Info() module.Info {
	return module.Info{
		ID:          "console",
		Title:       "Administration console",
		Description: "The web console: observe the suite, install and remove optional modules, administer users.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsSystem},

		// EXACT copy of the "admin" entry of catalogueServices
		// (internal/console/status.go): technical (admin tool, not a
		// user service), SSO=false in the current table — the value is
		// reproduced as-is so that the answer of /api/status stays
		// identical, even though the real access goes through Keycloak.
		Services: []module.Service{
			{
				Sub:         "admin",
				Name:        "Ceffio console",
				Role:        "This administration console",
				Technical:   true,
				SSO:         false,
				PodPrefixes: []string{"ceffio-admin"},
			},
		},
	}
}

// Install delegates to console.Deploy, unchanged — the registry describes,
// the sequence of cmd/ceffio/install.go remains master of the core order.
func (m *consoleModule) Install(ctx context.Context, env module.Env) error {
	return coucheConsole.Deploy(ctx, env.Domain)
}

// State reads the cluster: the Deployment ceffio-admin ready in
// ceffio-system.
func (m *consoleModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsSystem, "ceffio-admin")
}

// Uninstall refuses: the console is the frontend that drives the registry —
// removing it by itself would cut the hand holding the tool. The core is
// removed with the cluster (ceffio uninstall).
func (m *consoleModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
