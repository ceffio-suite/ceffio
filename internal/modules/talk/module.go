// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package talk déclare la couche « talk » (High Performance Backend de
// Nextcloud Talk : signaling, NATS, Janus, coturn) comme module Core du
// registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/talk
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
//
// NOTE SUR LES SERVICES : la page Talk elle-même (sub « talk ») est une app
// DANS Nextcloud — elle est décrite par le module « files », qui porte les
// pods « nextcloud ». Ce module-ci décrit le MEDIA SERVER (sub « spreed ») :
// signaling, Janus, coturn et NATS, dans ceffio-video.
package talk

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheTalk "github.com/ceffio-suite/ceffio/internal/talk"
)

// Le namespace du media server (internal/talk/talk.go, ns).
const nsVideo = "ceffio-video"

// talkModule est le module « talk ».
type talkModule struct{}

func init() { module.Register(&talkModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (talk après files et identity) appartient à la séquence explicite de
// cmd/ceffio/install.go.
func (m *talkModule) Info() module.Info {
	return module.Info{
		ID:          "talk",
		Title:       "Talk media server",
		Description: "High Performance Backend for Nextcloud Talk: signaling, Janus media gateway, coturn and NATS that carry calls and meetings.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsVideo},

		// Reprise EXACTE de l'entrée « spreed » de catalogueServices
		// (internal/console/status.go) : technique (transport média, pas
		// un accès humain), SSO=false, et les quatre préfixes de pods du
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

// Install délègue à talk.Deploy, inchangé — le registre décrit, la séquence
// de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *talkModule) Install(ctx context.Context, env module.Env) error {
	return coucheTalk.Deploy(ctx)
}

// State lit le cluster : les quatre Deployments du media server prêts.
// On liste chaque charge plutôt que de compter les pods du namespace :
// ceffio-video héberge aussi le recorder (module « recording », optionnel)
// — l'état du SOCLE ne doit pas dépendre de la présence d'un module à la
// carte.
func (m *talkModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatDuDeploiement(ctx, env, nsVideo, "nats"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "coturn"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "janus"),
		socle.EtatDuDeploiement(ctx, env, nsVideo, "talk-signaling"),
	)
}

// Uninstall refuse : sans media server, les appels Talk ne passent plus —
// le socle se retire avec le cluster (ceffio uninstall).
func (m *talkModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
