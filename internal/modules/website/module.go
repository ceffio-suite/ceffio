// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package website is the OPTIONAL "website" module: the public landing page.
//
// WHAT IT DOES: publishes a static, bilingual (FR/EN) page on the ROOT host of
// the installation — the one host the suite already owns, where the console
// serves /.well-known/security.txt. The page itself lives in
// internal/website (embedded files, one placeholder vocabulary); this package
// turns it into a ConfigMap and asks a pinned nginx to serve it.
//
// WHY IT IS OPTIONAL AND NOT DEFAULT: it is the only module that puts a
// PUBLIC page on the root of the installation's host, with the installation's
// own name on it. A production deployment behind a private domain may not want
// one, and `Default: false` is how the registry says "explicit request only".
// That is also the whole answer to "only deploy it for one domain": the module
// names NO domain, and `ceffio install --with website` (or `ceffio module
// install website`) is what decides. Nothing in this package compares
// Env.Domain to a literal.
//
// WHAT IT DELIBERATELY DOES NOT DO — read before adding either:
//   - no CLI subcommand and no console route: a feature is one package that
//     implements module.Module, and the CLI/console discover it through the
//     registry (docs/adding-a-module.md, checklist item 11);
//   - no Service entry in Info: the page is on the APEX host, and a Service
//     with an empty Sub is rendered as ".<domain>" by the console status page
//     — the status page would show a host that does not exist. The module
//     therefore exposes nothing in the public catalogue, exactly like the
//     console's own security.txt route.
package website

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	"github.com/ceffio-suite/ceffio/internal/website"
)

// websiteModule is the "website" module.
type websiteModule struct{}

func init() { module.Register(&websiteModule{}) }

// Info describes the public landing page.
func (m *websiteModule) Info() module.Info {
	return module.Info{
		ID:    "website",
		Title: "Website",
		Description: "Publishes a static, bilingual (FR/EN) landing page on the installation's root host. " +
			"Static HTML/CSS served by a pinned nginx: no script, no tracker, no third-party request.",
		Kind:       module.Optional,
		Default:    false,
		Requires:   []string{"ingress"},
		Namespaces: []string{nsSite},
		Resources:  "negligible: one nginx pod requesting 10m CPU / 16Mi RAM, no volume, no database",
		Warning: "Publishes a page on the ROOT host of the installation, reachable by anyone. " +
			"The module never names the host itself: it serves whatever domain the installation was created with.",

		// Permissions: the module's own namespace only — it never reads the
		// rest of the cluster. NOTHING about the namespace itself is declared
		// here: a Role is namespaced, so a "namespaces" rule inside it would
		// grant nothing while looking like it did. The platform chart creates
		// the namespace; assurerNamespace only takes effect for the CLI, which
		// runs with cluster rights.
		Permissions: []module.Permission{{
			Namespace: nsSite,
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps", "services"},
					Verbs:     []string{"get", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"deployments"},
					Verbs:     []string{"get", "create", "update", "patch", "delete"},
				},
				{
					APIGroups: []string{"networking.k8s.io"},
					Resources: []string{"ingresses"},
					Verbs:     []string{"get", "create", "update", "patch", "delete"},
				},
			},
		}},
	}
}

// Install publishes the page: namespace, ConfigMap (the page + the server
// configuration), Service, Deployment, Ingress, then wait for the pod to
// answer.
//
// EVERY STEP IS IDEMPOTENT AND RECONCILES DRIFT: running Install twice in a
// row must publish the same page twice, and it must not restart a pod that is
// already serving it (unless the page or the image changed — the ConfigMap
// checksum in the pod template is what draws that line).
func (m *websiteModule) Install(ctx context.Context, env module.Env) error {
	if env.Kube == nil {
		return fmt.Errorf("website: no Kubernetes client in the environment")
	}
	if env.Domain == "" {
		// A page needs a host. Guessing one would publish the wrong
		// certificate for the wrong name.
		return fmt.Errorf("website: no installation domain: a page must be published on a host (use --domain)")
	}
	// The dependency on "ingress" is NOT re-checked here: the runner already
	// does it (cmd/ceffio/module.go for the CLI, module.Blocked feeding
	// State.Blocked for the console's greyed-out button), and a module that
	// queried its own dependencies would fail in isolation — where the
	// registry holds nothing but itself, as every module test does.
	contact, err := m.contactPublie(ctx, env)
	if err != nil {
		return err
	}
	donnees, empreinte, err := rendre(env.Domain, contact)
	if err != nil {
		return err
	}

	dire(env.Out, "∙ publishing the page on https://%s (checksum %s)\n", env.Domain, empreinte)
	if err := assurerNamespace(ctx, env.Kube); err != nil {
		return err
	}
	if err := assurerConfigMap(ctx, env.Kube, donnees); err != nil {
		return err
	}
	dire(env.Out, "  %d files in ConfigMap %s/%s, including the server configuration\n",
		len(website.Paths()), nsSite, nomPage)
	if err := assurerService(ctx, env.Kube); err != nil {
		return err
	}
	if err := assurerDeploiement(ctx, env.Kube, empreinte); err != nil {
		return err
	}
	if err := assurerIngress(ctx, env.Kube, env.Domain); err != nil {
		return err
	}

	dire(env.Out, "∙ waiting for the pod to answer\n")
	if err := attendre(ctx, env.Kube, env.Out); err != nil {
		return err
	}
	dire(env.Out, "✓ https://%s serves the page (the certificate is issued by cert-manager in the background)\n", env.Domain)
	return nil
}

// State reads the cluster.
//
// WHY SEVERAL READS: the page is "installed" only when the whole chain is
// there — a pod without its Ingress is reachable by nobody, and an Ingress
// without its pod answers 503. Each read names its own absence so the
// diagnostic says which link is missing.
func (m *websiteModule) State(ctx context.Context, env module.Env) module.State {
	bloque := module.Blocked(ctx, env, m)
	if env.Kube == nil {
		return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment", Blocked: bloque}
	}

	deploiement := socle.EtatDuDeploiement(ctx, env, nsSite, nomPage)
	if deploiement.Status == module.Unknown {
		return module.State{Status: module.Unknown, Detail: deploiement.Detail, Blocked: bloque}
	}
	manquants, attendus, err := presence(ctx, env.Kube)
	if err != nil {
		return module.State{Status: module.Unknown, Detail: err.Error(), Blocked: bloque}
	}

	etat := module.State{Blocked: bloque}
	switch {
	case deploiement.Status == module.Absent && len(manquants) == attendus:
		// Nothing at all: the module never ran. "Absent" is a fact here,
		// not a guess — every object was read and none exists.
		etat.Status = module.Absent
	case len(manquants) > 0:
		// Half a page: the pod may be fine and still unreachable, because
		// the route or the configuration that feeds it is gone.
		etat.Status = module.Degraded
		etat.Detail = "missing: " + strings.Join(manquants, ", ")
	case deploiement.Status == module.Installed:
		etat.Status = module.Installed
		if env.Domain != "" {
			etat.Detail = "page served on https://" + env.Domain
		}
	default:
		// The Deployment exists but has no ready replica: keep its
		// diagnosis, which is more precise than "degraded".
		etat.Status = module.Degraded
		etat.Detail = deploiement.Detail
	}
	return etat
}

// presence lists the objects of the module that are missing, and how many it
// expects in total.
func presence(ctx context.Context, c kubernetes.Interface) (manquants []string, attendus int, err error) {
	attendus = 3
	if _, err := c.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		manquants = append(manquants, "ConfigMap "+nomPage)
	} else if err != nil {
		return nil, 0, fmt.Errorf("website: reading ConfigMap %s/%s: %w", nsSite, nomPage, err)
	}
	if _, err := c.CoreV1().Services(nsSite).Get(ctx, nomPage, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		manquants = append(manquants, "Service "+nomPage)
	} else if err != nil {
		return nil, 0, fmt.Errorf("website: reading Service %s/%s: %w", nsSite, nomPage, err)
	}
	if _, err := c.NetworkingV1().Ingresses(nsSite).Get(ctx, nomPage, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		manquants = append(manquants, "Ingress "+nomPage)
	} else if err != nil {
		return nil, 0, fmt.Errorf("website: reading Ingress %s/%s: %w", nsSite, nomPage, err)
	}
	return manquants, attendus, nil
}

// Uninstall removes everything the module created, then its namespace.
//
// ORDER: the Ingress first (stop sending traffic), then the Service, the
// Deployment and the ConfigMap, then the namespace. Re-runnable: a missing
// object is not an error, so an interrupted removal can simply be started
// again.
func (m *websiteModule) Uninstall(ctx context.Context, env module.Env) error {
	if env.Kube == nil {
		return fmt.Errorf("website: no Kubernetes client in the environment")
	}
	c := env.Kube
	out := env.Out
	var erreurs []string

	if err := c.NetworkingV1().Ingresses(nsSite).Delete(ctx, nomPage, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		erreurs = append(erreurs, "Ingress: "+err.Error())
	} else if err == nil {
		dire(out, "∙ Ingress %s/%s removed: the host no longer answers\n", nsSite, nomPage)
	}
	if err := c.CoreV1().Services(nsSite).Delete(ctx, nomPage, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		erreurs = append(erreurs, "Service: "+err.Error())
	}
	if err := c.AppsV1().Deployments(nsSite).Delete(ctx, nomPage, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		erreurs = append(erreurs, "Deployment: "+err.Error())
	} else if err == nil {
		dire(out, "∙ Deployment %s/%s removed\n", nsSite, nomPage)
	}
	if err := c.CoreV1().ConfigMaps(nsSite).Delete(ctx, nomPage, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		erreurs = append(erreurs, "ConfigMap: "+err.Error())
	} else if err == nil {
		dire(out, "∙ ConfigMap %s/%s removed: the page itself is gone\n", nsSite, nomPage)
	}

	// The namespace is the module's own (it is the only tenant), so removing
	// the module means removing it. Kubernetes finalises the deletion
	// asynchronously; waiting for it here would add a minute to a command
	// that has nothing left to verify.
	switch err := c.CoreV1().Namespaces().Delete(ctx, nsSite, metav1.DeleteOptions{}); {
	case err == nil:
		dire(out, "∙ namespace %s deletion requested\n", nsSite)
	case apierrors.IsNotFound(err):
	case apierrors.IsForbidden(err):
		// The console removes modules under a namespace-scoped identity: it
		// cannot delete a namespace. Everything the page needs is already
		// gone, and the namespace is declared by the platform chart.
		dire(out, "∙ namespace %s kept: this identity cannot delete it (the platform chart declares it)\n", nsSite)
	default:
		erreurs = append(erreurs, "Namespace: "+err.Error())
	}

	if len(erreurs) > 0 {
		return fmt.Errorf("website: removal incomplete: %s", strings.Join(erreurs, "; "))
	}
	return nil
}

// attendre polls the Deployment until a pod serves the page, or fails with
// the reason a pod is not starting.
//
// WHY POLL AND NOT A WATCH: one object, a few seconds, and the CLI already has
// the client. A watch would add machinery for a wait that lasts less than one
// image pull.
func attendre(ctx context.Context, c kubernetes.Interface, out io.Writer) error {
	echeance := time.Now().Add(delaiDeploiement)
	dernier := ""
	for {
		d, err := c.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("website: reading Deployment %s/%s: %w", nsSite, nomPage, err)
		}
		if d.Status.ObservedGeneration >= d.Generation && d.Status.ReadyReplicas >= 1 {
			return nil
		}
		if msg := resume(d); msg != dernier {
			dire(out, "  %s\n", msg)
			dernier = msg
		}
		if time.Now().After(echeance) {
			return fmt.Errorf("website: the page is not served after %s (%s)", delaiDeploiement, resume(d))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(periodeAttente):
		}
	}
}

// resume explains, in one line, why the Deployment is not ready yet.
//
// The interesting case is a pod that will NEVER become ready: the Deployment
// reports it as a Progressing condition with reason ProgressDeadlineExceeded
// and, in its message, the reason the scheduler or the kubelet gave. That
// message is what tells an operator "wrong image pull secret" instead of
// leaving them with a repeated "0/1 replica ready".
func resume(d *appsv1.Deployment) string {
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			return "rollout failed: " + c.Message
		}
	}
	if d.Status.Replicas == 0 {
		return "pod being created"
	}
	return fmt.Sprintf("%d/%d replica(s) ready", d.Status.ReadyReplicas, d.Status.Replicas)
}

// dire writes a progress line when the environment carries a writer (the tests
// pass io.Discard, the CLI os.Stdout).
func dire(out io.Writer, format string, args ...any) {
	if out == nil {
		return
	}
	fmt.Fprintf(out, format, args...)
}
