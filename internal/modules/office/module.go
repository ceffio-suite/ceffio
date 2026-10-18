// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package office déclare la couche « office » (ONLYOFFICE Document Server)
// comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/office
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
package office

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheOffice "github.com/ceffio-suite/ceffio/internal/office"
)

// Le namespace d'ONLYOFFICE (internal/office/office.go, ns).
const nsOffice = "ceffio-office"

// officeModule est le module « office ».
type officeModule struct{}

func init() { module.Register(&officeModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (office APRÈS files, car le connecteur s'active via occ dans le pod
// Nextcloud) appartient à la séquence explicite de cmd/ceffio/install.go.
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

		// Reprise EXACTE de l'entrée « office » de catalogueServices
		// (internal/console/status.go), commentaire compris : technique,
		// car personne n'y accède directement — mais le NAVIGATEUR charge
		// l'éditeur depuis cette adresse (DocumentServerUrl), donc la
		// retirer de l'exposition casserait l'édition des documents.
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

// Install délègue à office.Deploy, inchangé — le registre décrit, la
// séquence de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *officeModule) Install(ctx context.Context, env module.Env) error {
	return coucheOffice.Deploy(ctx)
}

// State lit le cluster : le Deployment onlyoffice prêt dans ceffio-office.
func (m *officeModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsOffice, "onlyoffice")
}

// Uninstall refuse : la couche fait partie du produit (Kind Core) ; la
// retirer casserait l'édition des documents sans que rien ne le dise.
// Le socle se retire avec le cluster (ceffio uninstall).
func (m *officeModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
