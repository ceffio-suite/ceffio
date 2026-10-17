// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package files déclare la couche « files » (Nextcloud) comme module Core du
// registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/files
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
//
// NOTE SUR LES SERVICES : cette couche porte DEUX expositions publiques
// (cloud ET talk) parce que Nextcloud Talk est une app DANS Nextcloud — les
// deux sont servies par les mêmes pods « nextcloud ». Le media server de
// Talk (Janus, signaling, coturn) est, lui, décrit par le module « talk ».
package files

import (
	"context"

	coucheFiles "github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// Le namespace de Nextcloud (internal/files/files.go, ns).
const nsFiles = "ceffio-files"

// filesModule est le module « files ».
type filesModule struct{}

func init() { module.Register(&filesModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (files après identity, office après files) appartient à la séquence
// explicite de cmd/ceffio/install.go.
func (m *filesModule) Info() module.Info {
	return module.Info{
		ID:          "files",
		Title:       "Files (Nextcloud)",
		Description: "Nextcloud: file storage, sharing and the collaboration apps the whole suite is built around.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsFiles},

		// Reprise EXACTE des entrées « cloud » et « talk » de
		// catalogueServices (internal/console/status.go) : mêmes textes,
		// mêmes préfixes de pods, mêmes SSO=true (les deux passent par
		// Keycloak).
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

// Install délègue à files.Deploy, inchangé — le registre décrit, la
// séquence de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *filesModule) Install(ctx context.Context, env module.Env) error {
	return coucheFiles.Deploy(ctx)
}

// State lit le cluster : le Deployment nextcloud prêt dans ceffio-files.
func (m *filesModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsFiles, "nextcloud")
}

// Uninstall refuse : Nextcloud porte les fichiers des utilisateurs — le
// socle se retire avec le cluster (ceffio uninstall).
func (m *filesModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
