// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package platformmail configures the sender the PLATFORM itself uses.
//
// WHY IT EXISTS: two applications send mail in Ceffio's name — Nextcloud (shares,
// password resets) and Keycloak (account e-mails) — and until now nothing told
// them WHICH sender to use. The relay was typed once in Ceffio's settings, again
// in the Nextcloud form, and often nowhere in Keycloak, so a password reset could
// leave from an address the operator had never chosen. Worse, installing a mail
// server on the platform left both applications talking to an EXTERNAL relay
// forever, because nothing moved them.
//
// THE PLATFORM SENDER IS ONE VALUE, resolved here (Resolve) and written to the
// two applications by ONE writer per application (ApplyNextcloud, ApplyKeycloak).
// The address `noreply@<domain>` is created by the mail module; the external relay
// saved in the files module's `outgoing_mail` settings is the fallback when no
// mail server is installed.
//
// IT NEVER DECIDES TO SEND MAIL. A Sender is a configuration, not a delivery: a
// nil Sender means "the platform has no sender", and every writer then says so
// instead of quietly leaving the previous one in place.
package platformmail

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// The objects this package reaches. NAMED ONCE, because they are also written by
// the mail, files and identity modules: a divergence here would configure nothing
// and report success.
const (
	nsMail     = "ceffio-mail"
	nsFiles    = "ceffio-files"
	nsIdentity = "ceffio-identity"

	deploiementMail = "stalwart"
	serviceMail     = "stalwart"
	ingressMail     = "mail"

	deploiementNextcloud = "nextcloud"
	conteneurNextcloud   = "nextcloud"
	etiquetteNextcloud   = "nextcloud"

	deploiementKeycloak = "keycloak"
	conteneurKeycloak   = "keycloak"
	etiquetteKeycloak   = "keycloak"

	// ComposantCoffre and SousCheminNoreply locate the credential the mail module
	// creates: kv/ceffio/mail/noreply, holding `user` and `password`.
	ComposantCoffre   = "mail"
	SousCheminNoreply = "noreply"

	// ComposantSmtp and SousCheminRelais locate the external relay's password, as
	// the files module stores it: kv/ceffio/smtp/relais, key `mot_de_passe`.
	ComposantSmtp    = "smtp"
	SousCheminRelais = "relais"
)

// cleReglagesSmtp is the settings key of the files module's `outgoing_mail` group.
//
// IT IS THE SAME KEY internal/settings WRITES (`cleConfigMap` is the group ID), and
// it is read RAW rather than through settings.Load: Load needs the group's field
// definitions, which live in the files module, and importing them here would close
// a cycle (the files module imports this package to delegate its writer).
const cleReglagesSmtp = "outgoing_mail"

// Sender is everything an application needs to send mail in the platform's name.
//
// THE FIELDS ARE THE PLAN'S, and they are deliberately the union of what Nextcloud
// and Keycloak accept: Host/Port/Security are the transport, User/Password the
// authentication, From/FromName what the recipient sees.
type Sender struct {
	Host     string
	User     string
	Password string
	From     string
	FromName string
	Port     int
	// Security is "ssl" for implicit TLS (the mail server's port 465) or
	// "starttls" for a plaintext connection upgraded in place (port 587).
	Security string
}

// clientCluster is the slice of the Kubernetes client this package uses.
type clientCluster interface {
	Executer(ctx context.Context, ns, pod, conteneur string, args ...string) (string, error)
	ExecuterAvecEntree(ctx context.Context, ns, pod, conteneur, entree string, args ...string) (string, error)
	PodDuDeploiement(ctx context.Context, ns, nom, etiquette string) (string, error)
	AttendreDeploiement(ctx context.Context, ns, nom string, limite time.Duration) error
	Kubernetes() kubernetes.Interface
}

// clientK8s is a variable so a test injects a fake client instead of reaching for
// a cluster — the same seam the other packages use.
var clientK8s = func() (clientCluster, error) { return k8sapi.Nouveau() }

// lireCoffre reads one vault entry. A nil result means "the vault is not
// configured on this machine" (no BAO_ADDR), which is not an error: the platform
// simply has no credential to read there.
var lireCoffre = func(ctx context.Context, composant, nom string) (map[string]string, error) {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return nil, nil
	}
	return secrets.LireEntreeCoffre(ctx, cfg, composant, nom)
}

// MailInstalle reports whether the mail server is deployed.
//
// IT READS THE DEPLOYMENT rather than the module registry: the registry says what
// an operator SELECTED, while the Deployment says what is actually there. A
// registry entry whose workload was deleted by hand would otherwise claim a
// server that cannot answer.
func MailInstalle(ctx context.Context, env module.Env) (bool, error) {
	if env.Kube == nil {
		return false, nil
	}
	_, err := env.Kube.AppsV1().Deployments(nsMail).Get(ctx, deploiementMail, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading the mail deployment: %w", err)
	}
	return true, nil
}

// hotePlateforme returns the public mail hostname, read from the mail Ingress.
//
// WHY THE INGRESS AND NOT env.Domain: the appliers receive a Sender, not an Env,
// and the question they must answer is precisely "is this sender the platform's
// mail server?" — which is the Ingress's rule, the one object that names it. An
// empty answer means the mail module is not deployed (or has no Ingress yet), and
// then no in-cluster alias must be installed.
func hotePlateforme(ctx context.Context, cli clientCluster) (string, error) {
	ing, err := cli.Kubernetes().NetworkingV1().Ingresses(nsMail).Get(ctx, ingressMail, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading the mail ingress: %w", err)
	}
	for _, regle := range ing.Spec.Rules {
		if regle.Host != "" {
			return regle.Host, nil
		}
	}
	return "", nil
}

// ipStalwart returns the ClusterIP of the mail Service.
//
// THE CLUSTER IP IS WHAT MAKES THE ALIAS WORK: the applications connect to
// `mail.<domain>:465`, so the name must resolve to the in-cluster Service, not to
// the node's public address. The certificate then matches the name, and no
// traffic leaves the node.
func ipStalwart(ctx context.Context, cli clientCluster) (string, error) {
	svc, err := cli.Kubernetes().CoreV1().Services(nsMail).Get(ctx, serviceMail, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading the mail service: %w", err)
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return "", fmt.Errorf("the mail service has no cluster IP")
	}
	return svc.Spec.ClusterIP, nil
}
