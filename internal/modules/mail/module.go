// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package mail exposes the mail server (Stalwart) as an OPTIONAL module.
//
// WHY IT IS NO LONGER A CORE MODULE DEPLOYED OUTSIDE THE REGISTRY: it used to
// be installed by the install sequence, which held the SMTP relay settings in
// its flags — the registry could describe it but not install it. The settings
// groups of the mail plan removed that exception: the relay is stored in the
// same place as every other module's configuration, so Install has everything
// it needs, `--without mail` becomes an ordinary selection, and an upgrade
// replays the module like any other instead of a hard-wired second path.
//
// INSTALL = SETTINGS, DEPLOY, SSO. The settings are not an argument of Install:
// they are STORED values (`server` and `relay` groups), and mailcore.Deploy
// reads them and refuses to touch the cluster when they are invalid. That order
// is what makes a bad volume size or an unreachable relay fail BEFORE anything
// is applied, rather than half-deploying a server around values it cannot use.
package mail

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mailcore "github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// nsMail is the namespace the mail server lives in.
const nsMail = "ceffio-mail"

// nsFiles and nsIdentity are the namespaces the module needs to reach INTO.
//
// WHY: creating a mailbox also creates its Nextcloud Mail account (through occ,
// in the Nextcloud pod) and its directory alias (through the Keycloak admin
// API, in the Keycloak pod). Both go through `kubectl exec`, so the console
// needs pods/exec there — and NOT anywhere else.
const (
	nsFiles    = "ceffio-files"
	nsIdentity = "ceffio-identity"
)

// nomsDesObjets are the Kubernetes objects Install creates on the public side.
const (
	cleDeploiement = "stalwart"
	cleService     = "stalwart"
	cleIngress     = "mail"
	cleCompte      = "stalwart"
	cleConfigMap   = "stalwart-config"
)

// mailModule is the registry entry of the mail server.
type mailModule struct{}

func init() { module.Register(&mailModule{}) }

// Info describes the module.
func (m *mailModule) Info() module.Info {
	return module.Info{
		ID:          "mail",
		Title:       "Mail server (Stalwart)",
		Description: "Mailboxes, webmail and the mail server that talks to the outside world.",
		// OPTIONAL AND INSTALLED BY DEFAULT: a fresh installation gets mail, as
		// it always did, but `--without mail` now really leaves it out and the
		// console can install it later — which the core list made impossible.
		Kind:    module.Optional,
		Default: true,
		// THE DEPENDENCIES ARE REAL ONES: identities come from Keycloak, the
		// public hostname from the ingress layer, and mailboxes are announced in
		// Nextcloud. Requires is what orders the registry and what the console
		// shows before an Install button.
		Requires:   []string{"identity", "ingress", "files"},
		Namespaces: []string{nsMail},
		Permissions: []module.Permission{
			socle.StandardPermission(nsMail),
			{
				Namespace: nsFiles,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec"},
						Verbs:     []string{"create"},
					},
				},
			},
			{
				Namespace: nsIdentity,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec"},
						Verbs:     []string{"create"},
					},
				},
			},
		},
		Services: []module.Service{
			{Sub: "mail", Name: "Mail", Role: "Mail server and webmail", SSO: true,
				PodPrefixes: []string{"stalwart"}},
		},
	}
}

// Install applies the stored settings, deploys the workload, then configures
// SSO.
//
// IT NEVER REFUSES BECAUSE OF AN EXTERNAL PREREQUISITE (DNS, reverse DNS, port
// 25). An operator must be able to install first and fix the outside world
// after; the checks report what is missing, and the module reports Degraded
// until it is fixed. Refusing here would trap an installation behind a DNS
// change it cannot make.
func (m *mailModule) Install(ctx context.Context, env module.Env) error {
	// THE RELAY IS ALREADY STORED when the installation carried --smtp-relais*:
	// the install sequence writes it before the optional phase, because
	// mailcore.Deploy has to read it. Install therefore stores nothing itself —
	// it applies what is there, defaults included.
	if err := mailcore.Deploy(ctx, env.Domain); err != nil {
		return err
	}
	// STEP 3: the directory, the admin account and the web client. THE DOMAIN
	// AND THE ACCOUNT COME FIRST, in that order, because step 7 writes aliases
	// that reference both — an alias is an object of the account, pointing at a
	// domain identifier.
	if err := mailcore.ConfigurerSSO(ctx, env.Domain, mailcore.SSO{
		Hote:         mailcore.DomaineMessagerie(env.Domain),
		Issuer:       "https://keycloak." + env.Domain + "/realms/ceffio",
		ClientID:     "stalwart-webui",
		DomaineAdmin: "ceffio.local",
		CompteAdmin:  "adminceffio",
	}); err != nil {
		return err
	}
	// STEP 7: postmaster@ and abuse@ (RFC 2142). Read back by address, so a
	// second Install writes nothing.
	if err := mailcore.AssurerAlias(ctx, env.Domain, "adminceffio"); err != nil {
		return err
	}
	return afficherExpose(ctx, env)
}

// afficherExpose performs step 9's part that belongs to Install: it PRINTS the
// firewall command, it does not run it.
//
// WHY NOT CALL THE OPNsense API HERE: the API host, the API key and the WAN
// interface live on the operator's machine (`ceffio-expose.json`), not in the
// cluster — the console has no credential and no route to the firewall. Running
// `ceffio expose` from inside the console would either need that file mounted
// into it or would silently do nothing. The plan says the step is done through
// `ceffio expose`, so Install names the exact command and stops there; the
// `inbound-25` check reports whether the port really answers.
func afficherExpose(ctx context.Context, env module.Env) error {
	sortie := env.Out
	if sortie == nil {
		sortie = io.Discard
	}
	cfg, err := mailcore.LireReglages(ctx)
	if err != nil {
		// NOT A FAILURE OF THE INSTALL: the settings were readable a moment ago
		// for Deploy. Printing the widest list is the safe default — an extra
		// forward is undone in one click, a missing one blocks mail with a
		// timeout the checks report.
		fmt.Fprintln(sortie, "  ∙ firewall: run `ceffio expose --ports 25,465,993` (settings unreadable, assuming external clients)")
		return nil
	}
	ports := "25"
	if cfg.ClientsExternes {
		ports = "25,465,993"
	}
	fmt.Fprintf(sortie, "  ∙ firewall: run `ceffio expose --ports %s` to forward them to the node\n", ports)
	fmt.Fprintln(sortie, "    (if your firewall's API cannot create them, `ceffio expose` prints the exact rule)")
	return nil
}

// Checks implements module.Checker (§4.4): what the outside world still lacks
// before this server can send and receive mail properly.
//
// THE CHECKS ARE NOT PART OF State's ANSWER, but of its REASON: State is
// Degraded while a BLOCKING check fails, and the detail names them. A module
// whose DNS is half-done is installed (the server runs, the mailboxes exist) and
// degraded (mail does not flow) — the console shows both, which is the truth.
func (m *mailModule) Checks(ctx context.Context, env module.Env) []module.Check {
	return mailcore.Checks(ctx, env.Domain)
}

// State reports the deployment's state, degraded while a blocking check fails.
func (m *mailModule) State(ctx context.Context, env module.Env) module.State {
	etat := socle.EtatDuDeploiement(ctx, env, nsMail, cleDeploiement)
	if etat.Status != module.Installed {
		return etat
	}
	bloquants := module.Bloquants(m.Checks(ctx, env))
	if len(bloquants) == 0 {
		return etat
	}
	// THE LABELS ARE NAMED, NOT COUNTED: "2 checks failed" tells an operator
	// nothing they can act on, while the two labels are the two things to fix.
	labels := make([]string, 0, len(bloquants))
	for _, c := range bloquants {
		labels = append(labels, c.Label)
	}
	return module.State{Status: module.Degraded, Detail: "blocking checks: " + strings.Join(labels, ", ")}
}

// Uninstall removes the public side, the workload and its configuration, and
// KEEPS THE DATA.
//
// WHY THE DATA SURVIVES: uninstalling a mail server is not a request to destroy
// every mailbox. The volume `stalwart-data` and the vault entries stay, the
// Nextcloud Mail accounts of internal users stay, and a reinstall finds the
// same server. Silently deleting mailboxes would be unrecoverable — no backup
// covers "the operator clicked uninstall".
//
// THE DEPLOYMENT GOES FIRST: it is the only writer of the RocksDB store, and
// deleting the Service or the Ingress first would leave a running server
// unreachable while the volume is about to be detached.
func (m *mailModule) Uninstall(ctx context.Context, env module.Env) error {
	if env.Kube == nil {
		return fmt.Errorf("uninstalling mail needs a Kubernetes client")
	}
	sortie := env.Out
	if sortie == nil {
		sortie = io.Discard
	}

	fmt.Fprintln(sortie, "  ∙ removing the mail server's workload and public exposure")

	if err := env.Kube.AppsV1().Deployments(nsMail).Delete(ctx, cleDeploiement,
		metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("removing the mail deployment: %w", err)
	}
	// WAITING FOR THE POD TO BE GONE, not for the delete to be accepted: the
	// mail store is on a single-writer volume, and a reinstall started while
	// the old pod is still terminating would leave the new one Pending on a
	// ReadWriteOnce claim. Two minutes is the termination grace period with a
	// margin.
	if err := attendreDisparition(ctx, env, 2*time.Minute); err != nil {
		return err
	}
	for _, suppression := range []struct {
		quoi string
		supp func() error
	}{
		{"the public Service", func() error {
			return env.Kube.CoreV1().Services(nsMail).Delete(ctx, cleService, metav1.DeleteOptions{})
		}},
		{"the Ingress host", func() error {
			return env.Kube.NetworkingV1().Ingresses(nsMail).Delete(ctx, cleIngress, metav1.DeleteOptions{})
		}},
		{"the ServiceAccount", func() error {
			return env.Kube.CoreV1().ServiceAccounts(nsMail).Delete(ctx, cleCompte, metav1.DeleteOptions{})
		}},
		{"the configuration", func() error {
			return env.Kube.CoreV1().ConfigMaps(nsMail).Delete(ctx, cleConfigMap, metav1.DeleteOptions{})
		}},
	} {
		if err := suppression.supp(); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("removing %s: %w", suppression.quoi, err)
		}
	}

	fmt.Fprintln(sortie, "  ∙ kept: the volume stalwart-data and the vault entries — the mailboxes are intact")
	fmt.Fprintln(sortie, "  ∙ kept: the Nextcloud Mail accounts of internal users — they work again after a reinstall")
	return nil
}

// attendreDisparition waits until the mail Deployment no longer exists.
//
// WHY NOT k8sapi.AttendreDeploiement: it waits for a Deployment to become
// READY, which is the opposite question. Here the object is being deleted, and
// the only observable that matters is its absence.
func attendreDisparition(ctx context.Context, env module.Env, limite time.Duration) error {
	fin := time.Now().Add(limite)
	for {
		_, err := env.Kube.AppsV1().Deployments(nsMail).Get(ctx, cleDeploiement, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("waiting for the mail deployment to be removed: %w", err)
		}
		if time.Now().After(fin) {
			return fmt.Errorf("removing the mail deployment: still present after %s", limite)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
