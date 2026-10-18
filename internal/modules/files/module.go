// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package files declares the "files" layer (Nextcloud) as a Core module of
// the registry.
//
// WHY A WRAPPER: the install already exists in internal/files and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
//
// NOTE ON THE SERVICES: this layer carries TWO public exposures (cloud AND
// talk) because Nextcloud Talk is an app INSIDE Nextcloud — both are served
// by the same "nextcloud" pods. The Talk media server (Janus, signaling,
// coturn), for its part, is described by the "talk" module.
package files

import (
	"context"

	coucheFiles "github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// The namespace of Nextcloud (internal/files/files.go, ns).
const nsFiles = "ceffio-files"

// filesModule is the "files" module.
type filesModule struct{}

func init() { module.Register(&filesModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (files after identity, office after files) belongs to the explicit
// sequence of cmd/ceffio/install.go.
func (m *filesModule) Info() module.Info {
	return module.Info{
		ID:          "files",
		Title:       "Files (Nextcloud)",
		Description: "Nextcloud: file storage, sharing and the collaboration apps the whole suite is built around.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsFiles},

		// Permissions (batch B6): the console administers this namespace
		// (workloads, config, the occ Role lives here) — the standard set
		// reproduces what the former ClusterRole ceffio-admin-namespaces
		// granted via its RoleBinding (see socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsFiles)},

		// EXACT copy of the "cloud" and "talk" entries of
		// catalogueServices (internal/console/status.go): same texts,
		// same pod prefixes, same SSO=true (both go through Keycloak).
		Services: []module.Service{
			{
				Sub:         "cloud",
				Name:        "Nextcloud",
				Role:        "Files, sharing and collaboration",
				Technical:   false,
				SSO:         true,
				PodPrefixes: []string{"nextcloud"},
			},
			{
				Sub:         "talk",
				Name:        "Nextcloud Talk",
				Role:        "Messaging and video conferencing (built into Nextcloud)",
				Technical:   false,
				SSO:         true,
				PodPrefixes: []string{"nextcloud"},
			},
		},
	}
}

// Install delegates to files.Deploy, unchanged — the registry describes,
// the sequence of cmd/ceffio/install.go remains master of the core order.
func (m *filesModule) Install(ctx context.Context, env module.Env) error {
	return coucheFiles.Deploy(ctx)
}

// State reads the cluster: the Deployment nextcloud ready in ceffio-files.
func (m *filesModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsFiles, "nextcloud")
}

// Uninstall refuses: Nextcloud carries the users' files — the core is
// removed with the cluster (ceffio uninstall).
func (m *filesModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
