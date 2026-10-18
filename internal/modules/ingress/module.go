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
	"sort"
	"strings"

	coucheIngress "github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"

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

// nsIngresses lists the namespaces where ingress.Deploy lays down an
// Ingress — the redirectionManifest loop of internal/ingress/ingress.go,
// minus cert-manager, which receives the CA and no Ingress.
//
// WHY A SEPARATE LIST FROM Info.Namespaces: Info.Namespaces says where the
// layer puts OBJECTS (cert-manager holds the CA); this list says where the
// observable PROOF of the layer lives. The two are not the same, and
// conflating them is what produced the bug fixed below.
var nsIngresses = []string{nsSystem, nsFiles, nsIdentity, nsOffice, nsVault, nsVideo, nsMail}

// State reads the cluster: the Ingresses this layer lays down.
//
// WHY NOT THE INTERNAL CA SECRET, WHICH AN EARLIER VERSION READ: the console
// cannot read it. The grant is the sum of what modules declare
// (internal/console/deploy.go, AdminRights), and reading a Secret in
// cert-manager is not part of it — verified on a fresh install:
//
//	reading the internal CA secret: secrets "ceffio-ca-tls" is forbidden:
//	User "system:serviceaccount:ceffio-system:ceffio-admin" cannot get
//	resource "secrets" in API group "" in the namespace "cert-manager"
//
// The state then reported "unknown" on EVERY installation, forever, for a
// layer that had worked. The fix is to observe what the layer delivers AND
// what the console is entitled to read — NOT to widen the grant: the RBAC
// non-regression test exists precisely to refuse that, and a module that
// needs a right to report on itself would be asking the wrong question.
//
// We check EXISTENCE, not health: whether a Certificate is Ready is
// cert-manager's business, which the "platform" module observes.
func (m *ingressModule) State(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment"}
	}

	// One read per namespace: a bare error here (forbidden, unreachable)
	// is genuinely unknown; only a successful read proves anything.
	var missing []string
	for _, ns := range nsIngresses {
		list, err := env.Kube.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return module.State{Status: module.Unknown,
				Detail: fmt.Sprintf("listing the Ingresses of %s: %v", ns, err)}
		}
		if len(list.Items) == 0 {
			missing = append(missing, ns)
		}
	}

	switch len(missing) {
	case 0:
		return module.State{Status: module.Installed}
	case len(nsIngresses):
		// Nothing at all: the layer never ran. Reported as absent rather
		// than degraded, so an operator sees "not installed" and not "half
		// installed" — the two call for different actions.
		return module.State{Status: module.Absent}
	default:
		sort.Strings(missing)
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("no Ingress in %s — the layer did not go through everywhere",
				strings.Join(missing, ", "))}
	}
}

// Uninstall refuses: without Ingress nor TLS, no service is reachable
// anymore — the core is removed with the cluster (ceffio uninstall).
func (m *ingressModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
