// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package mail declares the "mail" layer (Stalwart) as a Core module of the
// registry.
//
// WHY A WRAPPER: the install already exists in internal/mail and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
//
// THE PARTICULAR CASE OF THIS MODULE — Install DOES NOT DELEGATE:
// mail.Deploy requires the outbound SMTP relay settings (host, port, user,
// password) that module.Env does not carry, and rightly so: they are
// operator data entered by the install command (--smtp-relais, …). Outbound
// port 25 is blocked by ISPs (verified), so a Stalwart deployed WITHOUT a
// relay would receive but never send — a silently broken installation.
// Rather than delegate with an empty relay and pretend, Install returns an
// explicit error: the install sequence, which holds the settings, remains
// the only one to install this layer.
package mail

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// NO IMPORT OF internal/mail HERE, and it is deliberate: this module NEVER
// calls mail.Deploy (see Install). Keeping an unusable import for the sake
// of a symbolic link would suggest a delegation that does not exist. The
// layer is described, not driven.

// The namespace of Stalwart (internal/mail/mail.go, ns).
const nsMail = "ceffio-mail"

// mailModule is the "mail" module.
type mailModule struct{}

func init() { module.Register(&mailModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (mail after ingress, because Stalwart's SSO checks its OIDC
// discovery on https://keycloak.<domain>) belongs to the explicit sequence
// of cmd/ceffio/install.go.
func (m *mailModule) Info() module.Info {
	return module.Info{
		ID:          "mail",
		Title:       "Mail server (Stalwart)",
		Description: "Stalwart: the mail server behind Nextcloud Mail, with SMTP relay settings held by the install sequence.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsMail},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsMail)},

		Warning: "Installed by the install sequence only: it needs the outbound SMTP relay settings, which the registry does not carry.",
	}
}

// Install refuses, EXPLICITLY.
//
// WHY AN ERROR RATHER THAN AN APPROXIMATE DELEGATION: calling mail.Deploy
// with an empty relay would produce a Stalwart that runs, that receives,
// and that sends NOTHING — the worst possible state, because everything
// would look installed. Env does not have the relay settings and must not
// have them (an SMTP password is not cluster data). The only honest answer
// is to say who installs this layer, and why.
func (m *mailModule) Install(ctx context.Context, env module.Env) error {
	return fmt.Errorf("mail is installed by the install sequence, which holds the SMTP relay settings; " +
		"the registry describes it but does not install it")
}

// State reads the cluster: the Deployment stalwart ready in ceffio-mail.
func (m *mailModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsMail, "stalwart")
}

// Uninstall refuses: the layer is part of the product (Kind Core); the
// users' mailboxes live in its volume. The core is removed with the cluster
// (ceffio uninstall).
func (m *mailModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
