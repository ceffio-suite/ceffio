// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package ingress déclare la couche « ingress » (autorité TLS interne,
// émetteurs Let's Encrypt, redirections HTTPS et Ingresses des applications)
// comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans
// internal/ingress et reste pilotée par cmd/ceffio/install.go. Ce package
// DÉCRIT la couche pour que l'état et le diagnostic la lisent dans le
// registre.
package ingress

import (
	"context"
	"fmt"

	coucheIngress "github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Les namespaces où la couche pose des objets : la CA vit dans
	// cert-manager (Certificate ceffio-ca + secret ceffio-ca-tls), et les
	// Ingresses + middlewares de redirection vivent dans les namespaces
	// des applications (boucle de redirectionManifest,
	// internal/ingress/ingress.go). La couche n'a AUCUN pod à elle :
	// Traefik est fourni par le runtime (kube-system).
	nsSystem   = "ceffio-system"
	nsCertMgr  = "cert-manager"
	nsFiles    = "ceffio-files"
	nsIdentity = "ceffio-identity"
	nsOffice   = "ceffio-office"
	nsVault    = "ceffio-vault"
	nsVideo    = "ceffio-video"
	nsMail     = "ceffio-mail"
)

// ingressModule est le module « ingress ».
type ingressModule struct{}

func init() { module.Register(&ingressModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (ingress appliqué AVANT les blocs OIDC, car le SSO de Stalwart vérifie
// son discovery sur https://keycloak.<domain>) appartient à la séquence
// explicite de cmd/ceffio/install.go.
func (m *ingressModule) Info() module.Info {
	return module.Info{
		ID:          "ingress",
		Title:       "Ingress & TLS",
		Description: "Public hostnames, certificates and the internal certificate authority: how every service of the suite is reached over HTTPS.",
		Kind:        module.Core,
		Default:     true,

		// ceffio-system est BIEN listé : ingress.Deploy y pose un
		// Middleware de redirection HTTPS. Traefik résout
		// « <namespace>-<nom>@kubernetescrd », donc le middleware doit
		// vivre dans le même namespace que l'Ingress qui le référence
		// — et l'Ingress de la console vit dans ceffio-system. Il y
		// pose aussi les Middlewares et Ingresses des namespaces des
		// applications, et la CA dans cert-manager.
		Namespaces: []string{nsSystem, nsCertMgr, nsFiles, nsIdentity, nsOffice, nsVault, nsVideo, nsMail},
	}
}

// Install délègue à ingress.Deploy, inchangé — le registre décrit, la
// séquence de cmd/ceffio/install.go reste maître de l'ordre du socle.
func (m *ingressModule) Install(ctx context.Context, env module.Env) error {
	return coucheIngress.Deploy(ctx, env.Domain)
}

// State lit le cluster : la CA interne (Certificate ceffio-ca dans
// cert-manager) et l'Ingress de Nextcloud (cloud.<domain>, dans
// ceffio-files) doivent exister.
//
// POURQUOI ces deux objets : ce sont les deux preuves que ingress.Deploy a
// abouti — caManifest est appliqué en premier (la CA est « créée TOUJOURS »),
// ingressesManifest en dernier. Vérifier le premier et le dernier borne
// toute la séquence sans rejouer les sept middlewares un par un. On vérifie
// l'EXISTENCE, pas la santé : un certificat Ready ou non est l'affaire de
// cert-manager, que le module « platform » observe déjà.
func (m *ingressModule) State(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment"}
	}
	if _, err := env.Kube.CoreV1().Secrets(nsCertMgr).Get(ctx, "ceffio-ca-tls", metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return module.State{Status: module.Absent}
		}
		return module.State{Status: module.Unknown, Detail: fmt.Sprintf("reading the internal CA secret: %v", err)}
	}
	// L'Ingress « cloud » porte le nom du sub (ingressesManifest :
	// name: %[1]s = r.sub). Son absence dit que la phase des Ingresses
	// n'a pas abouti, même si la CA est là.
	if _, err := env.Kube.NetworkingV1().Ingresses(nsFiles).Get(ctx, "cloud", metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return module.State{Status: module.Degraded, Detail: "internal CA present, but the public Ingresses are not"}
		}
		return module.State{Status: module.Unknown, Detail: fmt.Sprintf("reading the cloud Ingress: %v", err)}
	}
	return module.State{Status: module.Installed}
}

// Uninstall refuse : sans Ingress ni TLS, plus aucun service n'est
// joignable — le socle se retire avec le cluster (ceffio uninstall).
func (m *ingressModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
