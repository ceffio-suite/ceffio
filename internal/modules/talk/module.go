// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package talk declares the "talk" layer (High Performance Backend of
// Nextcloud Talk: signaling, NATS, Janus, coturn) as a Core module of the
// registry.
//
// WHY A WRAPPER: the install already exists in internal/talk and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
//
// NOTE ON THE SERVICES: the Talk page itself (sub "talk") is an app INSIDE
// Nextcloud — it is described by the "files" module, which carries the
// "nextcloud" pods. This module describes the MEDIA SERVER (sub "spreed"):
// signaling, Janus, coturn and NATS, in ceffio-video.
package talk

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheTalk "github.com/ceffio-suite/ceffio/internal/talk"
)

// The namespace of the media server (internal/talk/talk.go, ns).
const nsVideo = "ceffio-video"

// talkModule is the "talk" module.
type talkModule struct{}

func init() { module.Register(&talkModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (talk after files and identity) belongs to the explicit sequence of
// cmd/ceffio/install.go.
func (m *talkModule) Info() module.Info {
	return module.Info{
		ID:          "talk",
		Title:       "Talk media server",
		Description: "High Performance Backend for Nextcloud Talk: signaling, Janus media gateway, coturn and NATS that carry calls and meetings.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsVideo},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission). The Optional recording module declares
		// a subset of it; the union is unchanged.
		Permissions: []module.Permission{socle.StandardPermission(nsVideo)},

		// EXACT copy of the "spreed" entry of catalogueServices
		// (internal/console/status.go): technical (media transport, not a
		// human access), SSO=false, and the four pod prefixes of the
		// media server.
		Services: []module.Service{
			{
				Sub:         "spreed",
				Name:        "Talk — media server",
				Role:        "Video transport for meetings (Janus + signaling)",
				Technical:   true,
				SSO:         false,
				PodPrefixes: []string{"janus", "talk-signaling", "coturn", "nats"},
			},
		},
	}
}

// Install delegates to talk.Deploy, unchanged — the registry describes, the
// sequence of cmd/ceffio/install.go remains master of the core order.
func (m *talkModule) Install(ctx context.Context, env module.Env) error {
	return coucheTalk.Deploy(ctx)
}

// State reads the cluster: the four Deployments of the media server ready.
// We list each workload rather than counting the pods of the namespace:
// ceffio-video also hosts the recorder (module "recording", optional) — the
// state of the CORE must not depend on the presence of an optional module.
func (m *talkModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatDuDeploiement(ctx, env, nsVideo, "nats"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "coturn"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "janus"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "talk-signaling"),
	)
}

// Uninstall refuses: without the media server, Talk calls no longer go
// through — the core is removed with the cluster (ceffio uninstall).
func (m *talkModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
