// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package ingress declares the "ingress" layer (internal TLS authority,
// Let's Encrypt issuers, HTTPS redirections and the application Ingresses)
// as a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/ingress and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
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
	// The namespaces where the layer lays down objects: the CA lives in
	// cert-manager (Certificate ceffio-ca + secret ceffio-ca-tls), and the
	// Ingresses + redirection middlewares live in the application
	// namespaces (redirectionManifest loop, internal/ingress/ingress.go).
	// The layer has NO pod of its own: Traefik is provided by the runtime
	// (kube-system).
	nsSystem   = "ceffio-system"
	nsCertMgr  = "cert-manager"
	nsFiles    = "ceffio-files"
	nsIdentity = "ceffio-identity"
	nsOffice   = "ceffio-office"
	nsVault    = "ceffio-vault"
	nsVideo    = "ceffio-video"
	nsMail     = "ceffio-mail"
)

// ingressModule is the "ingress" module.
type ingressModule struct{}

func init() { module.Register(&ingressModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core (ingress applied BEFORE the OIDC blocks, because Stalwart's SSO
// checks its discovery on https://keycloak.<domain>) belongs to the
// explicit sequence of cmd/ceffio/install.go.
func (m *ingressModule) Info() module.Info {
	return module.Info{
		ID:          "ingress",
		Title:       "Ingress & TLS",
		Description: "Public hostnames, certificates and the internal certificate authority: how every service of the suite is reached over HTTPS.",
		Kind:        module.Core,
		Default:     true,

		// ceffio-system IS indeed listed: ingress.Deploy lays down an
		// HTTPS redirection Middleware there. Traefik resolves
		// "<namespace>-<name>@kubernetescrd", so the middleware must
		// live in the same namespace as the Ingress that references it
		// — and the console's Ingress lives in ceffio-system. It also
		// lays down the Middlewares and Ingresses of the application
		// namespaces there, and the CA in cert-manager.
		Namespaces: []string{nsSystem, nsCertMgr, nsFiles, nsIdentity, nsOffice, nsVault, nsVideo, nsMail},
	}
}

// Install delegates to ingress.Deploy, unchanged — the registry describes,
// the sequence of cmd/ceffio/install.go remains master of the core order.
func (m *ingressModule) Install(ctx context.Context, env module.Env) error {
	return coucheIngress.Deploy(ctx, env.Domain)
}

// State reads the cluster: the internal CA (Certificate ceffio-ca in
// cert-manager) and the Nextcloud Ingress (cloud.<domain>, in ceffio-files)
// must exist.
//
// WHY these two objects: they are the two proofs that ingress.Deploy went
// through — caManifest is applied first (the CA is "created ALWAYS"),
// ingressesManifest last. Checking the first and the last bounds the whole
// sequence without replaying the seven middlewares one by one. We check
// EXISTENCE, not health: whether a certificate is Ready or not is
// cert-manager's business, which the "platform" module already observes.
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
	// The "cloud" Ingress carries the name of the sub (ingressesManifest:
	// name: %[1]s = r.sub). Its absence says that the Ingresses phase did
	// not go through, even if the CA is there.
	if _, err := env.Kube.NetworkingV1().Ingresses(nsFiles).Get(ctx, "cloud", metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return module.State{Status: module.Degraded, Detail: "internal CA present, but the public Ingresses are not"}
		}
		return module.State{Status: module.Unknown, Detail: fmt.Sprintf("reading the cloud Ingress: %v", err)}
	}
	return module.State{Status: module.Installed}
}

// Uninstall refuses: without Ingress nor TLS, no service is reachable
// anymore — the core is removed with the cluster (ceffio uninstall).
func (m *ingressModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
