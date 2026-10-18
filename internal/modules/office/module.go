// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package office declares the "office" layer (ONLYOFFICE Document Server)
// as a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/office and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
package office

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheOffice "github.com/ceffio-suite/ceffio/internal/office"
)

// The namespace of ONLYOFFICE (internal/office/office.go, ns).
const nsOffice = "ceffio-office"

// officeModule is the "office" module.
type officeModule struct{}

func init() { module.Register(&officeModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (office AFTER files, because the connector is activated via occ in
// the Nextcloud pod) belongs to the explicit sequence of
// cmd/ceffio/install.go.
func (m *officeModule) Info() module.Info {
	return module.Info{
		ID:          "office",
		Title:       "Document editing (ONLYOFFICE)",
		Description: "ONLYOFFICE Document Server: the editing engine the browser loads when a document opens in Nextcloud.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsOffice},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsOffice)},

		// EXACT copy of the "office" entry of catalogueServices
		// (internal/console/status.go), comment included: technical,
		// because nobody accesses it directly — but the BROWSER loads
		// the editor from this address (DocumentServerUrl), so removing
		// it from the exposure would break document editing.
		Services: []module.Service{
			{
				Sub:         "office",
				Name:        "ONLYOFFICE",
				Role:        "Editing engine for Nextcloud documents — loaded by the browser, no useful direct access",
				Technical:   true,
				SSO:         false,
				PodPrefixes: []string{"onlyoffice"},
			},
		},
	}
}

// Install delegates to office.Deploy, unchanged — the registry describes,
// the sequence of cmd/ceffio/install.go remains master of the core order.
func (m *officeModule) Install(ctx context.Context, env module.Env) error {
	return coucheOffice.Deploy(ctx)
}

// State reads the cluster: the Deployment onlyoffice ready in ceffio-office.
func (m *officeModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsOffice, "onlyoffice")
}

// Uninstall refuses: the layer is part of the product (Kind Core); removing
// it would break document editing without anything saying so. The core is
// removed with the cluster (ceffio uninstall).
func (m *officeModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
