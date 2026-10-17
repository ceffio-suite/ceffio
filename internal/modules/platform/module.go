// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package platform déclare la couche « platform » (namespaces, cert-manager,
// autorités TLS) comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans
// internal/platform et reste pilotée par la séquence explicite de
// cmd/ceffio/install.go. Ce package ne réécrit rien : il DÉCRIT la couche
// (état, namespaces, services) pour que le CLI, la console et le doctor
// lisent le socle dans le registre, au lieu de le deviner.
package platform

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	couchePlatform "github.com/ceffio-suite/ceffio/internal/platform"
)

const (
	// Le namespace du chart parapluie et de la release Helm « ceffio »
	// (internal/platform/platform.go, installUmbrella).
	nsSystem = "ceffio-system"
	// cert-manager vit dans SON namespace (chart jetstack) : l'état de la
	// couche se lit là, pas dans ceffio-system.
	nsCertManager = "cert-manager"
)

// platformModule est le module « platform ».
type platformModule struct{}

func init() { module.Register(&platformModule{}) }

// Info décrit la couche. Requires reste VOLONTAIREMENT vide pour tous les
// modules Core : l'ordre du socle (platform ‖ data → vault → identity → …)
// appartient à la séquence explicite de cmd/ceffio/install.go, qui garde la
// main ; le duplicer ici créerait une seconde source de vérité, avec le
// risque qu'elle contredisse la première.
func (m *platformModule) Info() module.Info {
	return module.Info{
		ID:          "platform",
		Title:       "Platform",
		Description: "Namespaces, cert-manager and the certificate authorities every other layer relies on.",
		Kind:        module.Core,
		Default:     true,

		// Les deux namespaces sont réels : le chart parapluie pose les
		// namespaces ceffio-* depuis ceffio-system, et cert-manager
		// (attendu prêt par waitCertManagerReady) vit dans cert-manager.
		Namespaces: []string{nsSystem, nsCertManager},
	}
}

// Install délègue à platform.Deploy, inchangé.
//
// POURQUOI LA DÉLÉGATION NE FAIT PAS DU REGISTRE L'INSTALLATEUR : la
// séquence du socle reste dans cmd/ceffio/install.go. Cette méthode honore
// le contrat module.Module et permet à un frontal de rejouer UNE couche à
// l'identique — pas de réordonner le socle.
func (m *platformModule) Install(ctx context.Context, env module.Env) error {
	return couchePlatform.Deploy(ctx)
}

// State lit le cluster : le namespace ceffio-system actif et les trois
// Deployments de cert-manager prêts — exactement ce que platform.Deploy
// attend avant de continuer (waitCertManagerReady).
func (m *platformModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatLePlusBas(
		socle.EtatNamespaceActif(ctx, env, nsSystem),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager"),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager-cainjector"),
		socle.EtatDuDeploiement(ctx, env, nsCertManager, "cert-manager-webhook"),
	)
}

// Uninstall refuse : le socle se retire avec le cluster (ceffio uninstall),
// jamais couche par couche — voir socle.ErreurSocleIndemontable.
func (m *platformModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
