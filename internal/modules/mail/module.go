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
// mail.Deploy creates the workload, the volume, the Service and the ingress
// host of a CORE layer, in the order the installation has fixed; it is the
// installation sequence's job, not the registry's. Install therefore returns
// an explicit error rather than pretending to do it.
//
// WHAT THIS MODULE DOES DRIVE: its SETTINGS. The outbound relay (host, port,
// password) used to be four installation flags; it is now the relay group of
// this module (reglages.go), stored in the common settings and applied through
// Stalwart's own admin API. The server group adds what the deployment could not
// express: send mode, volume size, default quota, and whether IMAP / SMTPS are
// published — the ports it declared (587, 143) were NOT the ones Stalwart 1.0.3
// listens on (465, 993), measured in docs/plan-mail.md §9.E.
package mail

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// THE IMPORT OF internal/mail BELOW IS THE SETTINGS PATH ONLY: this module
// never calls mail.Deploy (see Install), but it does need the stored form of
// the mail settings (mailcore.Reglages, mailcore.AppliquerServeur) to apply a
// group to the running server. It is imported as mailcore because this package
// is itself called mail.

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
		Description: "Stalwart: the mail server behind Nextcloud Mail, configured by its own settings (relay, volume, exposure).",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsMail},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsMail)},

		Warning: "Installed by the install sequence only: it needs the outbound SMTP relay settings, which the registry does not carry.",

		// THE WEB INTERFACE'S HOST. It was missing from the registry, so `ceffio dns`
		// never checked it: the mail host could stop resolving and nothing said so
		// until someone opened it. SSO is true because the WebUI signs in through
		// Keycloak (the stalwart-webui client).
		Services: []module.Service{
			{
				Sub:         "mail",
				Name:        "Mail",
				Role:        "Mail server and webmail",
				Technical:   false,
				SSO:         true,
				PodPrefixes: []string{"stalwart"},
			},
		},
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
