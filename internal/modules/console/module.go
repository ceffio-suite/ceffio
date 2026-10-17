// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package console déclare la couche « console » (la console d'administration
// web) comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans
// internal/console/deploy.go et reste pilotée par cmd/ceffio/install.go. Ce
// package DÉCRIT la couche pour que l'état et le diagnostic la lisent dans
// le registre.
//
// NOTE D'HONNÊTETÉ : la console est aussi le frontal qui LIT le registre —
// mais aucun cycle n'est possible : ce package importe internal/console
// (la couche), pas l'inverse ; internal/console n'importe AUCUN module.
package console

import (
	"context"

	coucheConsole "github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// Le namespace de la console (internal/console/deploy.go, deployNS).
const nsSystem = "ceffio-system"

// consoleModule est le module « console ».
type consoleModule struct{}

func init() { module.Register(&consoleModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (console déployée en DERNIER, après tout ce qu'elle administre)
// appartient à la séquence explicite de cmd/ceffio/install.go.
func (m *consoleModule) Info() module.Info {
	return module.Info{
		ID:          "console",
		Title:       "Administration console",
		Description: "The web console: observe the suite, install and remove optional modules, administer users.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsSystem},

		// Reprise EXACTE de l'entrée « admin » de catalogueServices
		// (internal/console/status.go) : technique (outil d'admin, pas
		// un service utilisateur), SSO=false dans la table actuelle —
		// la valeur est reprise telle quelle pour que la réponse de
		// /api/status reste identique, même si l'accès réel passe par
		// Keycloak.
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

// Install délègue à console.Deploy, inchangé — le registre décrit, la
// séquence de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *consoleModule) Install(ctx context.Context, env module.Env) error {
	return coucheConsole.Deploy(ctx, env.Domain)
}

// State lit le cluster : le Deployment ceffio-admin prêt dans
// ceffio-system.
func (m *consoleModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsSystem, "ceffio-admin")
}

// Uninstall refuse : la console est le frontal qui pilote le registre — la
// retirer par elle-même couperait la main qui tient l'outil. Le socle se
// retire avec le cluster (ceffio uninstall).
func (m *consoleModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
