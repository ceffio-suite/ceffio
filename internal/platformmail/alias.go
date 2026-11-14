// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// annotationAlias records the alias this package installed, as `<hote>=<ip>`.
//
// IT IS THE IDEMPOTENCE AND THE CLEANUP: without it, the next run cannot tell an
// alias it wrote from one an operator wrote, and removing it would erase the
// operator's work. With it, the alias is refreshed when the ClusterIP changes and
// removed when the platform stops using the mail server.
const annotationAlias = "platformmail.ceffio.io/alias-interne"

// delaiDeploiement is how long a rewritten Deployment gets to roll out.
//
// THE WAIT IS PART OF THE CONFIGURATION: after the template changes, the pod that
// answers the exec is replaced, and a writer that does not wait edits a pod whose
// replacement has not read the new value — the change is then lost silently, which
// is the exact failure this package exists to avoid.
const delaiDeploiement = 3 * time.Minute

// portMail is the port the applications connect to. It is not a parameter: the
// probe asks whether THE PATH THE SENDER USES works, and every platform sender is
// reached on 465 (implicit TLS) — the one port the mail module always publishes.
const portMail = 465

// alignerAlias brings the in-cluster name resolution of one application in line
// with the sender it must reach.
//
// THE PROBLEM IT SOLVES: Nextcloud and Keycloak are told to send through
// `mail.<domain>:465` so that the certificate — whose name is that host — matches.
// From inside a pod, that name resolves through public DNS to the node's public
// address, and the round trip back into the cluster only works when the node's
// NAT hairpins and the port is published. With `clients_externes=false` the mail
// module publishes 25 only, so the two applications cannot reach the sender at all;
// every password reset then sits in a queue that retries until it gives up.
//
// THE ANSWER IS A HOSTS ENTRY, NOT A DIFFERENT HOSTNAME: `hostAliases` makes
// `mail.<domain>` resolve to the mail Service's ClusterIP inside the pod, which
// keeps the certificate valid, keeps the traffic on the cluster network, and works
// whatever the public ports are. The entry is annotated so that it is idempotent,
// refreshed when the ClusterIP changes, and removed when the platform goes back to
// an external relay.
//
// IT ONLY APPLIES TO THE PLATFORM'S OWN SENDER: an external relay is reached by
// public DNS and must never be redirected to the local mail server — that would
// send the platform's mail to a server it was explicitly told not to use.
func alignerAlias(ctx context.Context, cli clientCluster, ns, deploiement, etiquette, conteneur, hote string) error {
	plateforme, err := hotePlateforme(ctx, cli)
	if err != nil {
		return err
	}
	if plateforme != "" && hote == plateforme {
		return assurerAliasInterne(ctx, cli, ns, deploiement, etiquette, conteneur, hote)
	}
	return retirerAliasInterne(ctx, cli, ns, deploiement, hote)
}

// assurerAliasInterne installs or refreshes the alias, if it is needed.
func assurerAliasInterne(ctx context.Context, cli clientCluster, ns, deploiement, etiquette, conteneur, hote string) error {
	kube := cli.Kubernetes()
	dep, err := kube.AppsV1().Deployments(ns).Get(ctx, deploiement, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// THE APPLICATION IS NOT DEPLOYED YET: its own install will call this
		// function once it is, and creating a Deployment here would deploy an
		// application the operator did not ask for.
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading deployment %s/%s: %w", ns, deploiement, err)
	}

	ip, err := ipStalwart(ctx, cli)
	if err != nil {
		return err
	}
	enregistre := dep.Annotations[annotationAlias]
	if enregistre == hote+"="+ip {
		return nil
	}

	// THE PROBE ONLY RUNS WHEN NO ALIAS IS RECORDED. Once one is in place, the name
	// resolves through it, so a probe would always succeed and could no longer
	// answer the question it exists for ("can this pod reach the public path?").
	// Refreshing an existing alias is therefore unconditional: the only reason the
	// recorded address differs is that the Service was recreated.
	if enregistre == "" {
		ouvert, err := sondeOuverte(ctx, cli, ns, deploiement, etiquette, conteneur, hote)
		if err != nil {
			// A PROBE THAT CANNOT RUN IS NOT A REASON TO FAIL AN INSTALL. The
			// applications may have no bash (a shell probe is not a contract they
			// signed), or the exec may fail on a pod that is starting. Installing
			// the alias anyway is the safe direction: the name resolves to the
			// local Service, which is where the platform's mail lives.
			ouvert = false
		}
		if ouvert {
			return nil
		}
	}

	dep.Spec.Template.Spec.HostAliases = aliasesSans(dep.Spec.Template.Spec.HostAliases, hote, ancienHote(enregistre))
	dep.Spec.Template.Spec.HostAliases = append(dep.Spec.Template.Spec.HostAliases,
		corev1.HostAlias{IP: ip, Hostnames: []string{hote}})
	if dep.Annotations == nil {
		dep.Annotations = map[string]string{}
	}
	dep.Annotations[annotationAlias] = hote + "=" + ip
	if _, err := kube.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("pointing %s/%s at the mail service: %w", ns, deploiement, err)
	}
	notifier("  ∙ %s now resolves %s to the mail service (%s); the deployment restarts\n",
		deploiement, hote, ip)

	// THE ROLLOUT IS WAITED FOR: the caller's next step execs into this
	// application, and a pod from the previous generation would run a command
	// against the OLD name resolution.
	if err := cli.AttendreDeploiement(ctx, ns, deploiement, delaiDeploiement); err != nil {
		return fmt.Errorf("waiting for %s/%s to restart: %w", ns, deploiement, err)
	}
	return nil
}

// retirerAliasInterne removes the alias, when this package installed one.
//
// IT IS A NO-OP WHEN THE ANNOTATION IS ABSENT: an operator's own `hostAliases`
// entry for the same name must survive, and there is no way to tell theirs from
// ours without the marker.
func retirerAliasInterne(ctx context.Context, cli clientCluster, ns, deploiement, hote string) error {
	kube := cli.Kubernetes()
	dep, err := kube.AppsV1().Deployments(ns).Get(ctx, deploiement, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading deployment %s/%s: %w", ns, deploiement, err)
	}
	enregistre, ok := dep.Annotations[annotationAlias]
	if !ok {
		return nil
	}

	dep.Spec.Template.Spec.HostAliases = aliasesSans(dep.Spec.Template.Spec.HostAliases, hote, ancienHote(enregistre))
	delete(dep.Annotations, annotationAlias)
	if _, err := kube.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("removing the mail alias from %s/%s: %w", ns, deploiement, err)
	}
	notifier("  ∙ %s no longer points %s at the mail service; the deployment restarts\n",
		deploiement, hote)
	if err := cli.AttendreDeploiement(ctx, ns, deploiement, delaiDeploiement); err != nil {
		return fmt.Errorf("waiting for %s/%s to restart: %w", ns, deploiement, err)
	}
	return nil
}

// sondeOuverte asks the pod itself whether it can open a TLS connection to the
// sender's host and port.
//
// THE POD ASKS, NOT THIS PROCESS: the answering network is the pod's, not the
// operator's machine's — a laptop on the same LAN reaches the public address,
// while a pod behind a NAT that does not hairpin does not, and only the pod's
// answer predicts whether the mail will actually leave.
//
// `/dev/tcp` IS A BASH FEATURE, hence the explicit `bash -c`; the applications'
// images both ship bash (verified for Keycloak, which runs its own entrypoint in
// it), and `timeout` bounds a name that resolves but never answers.
func sondeOuverte(ctx context.Context, cli clientCluster, ns, deploiement, etiquette, conteneur, hote string) (bool, error) {
	pod, err := cli.PodDuDeploiement(ctx, ns, deploiement, etiquette)
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf("timeout 5 bash -c 'exec 3<>/dev/tcp/%s/%d' && echo OUVERT || echo FERME", hote, portMail)
	out, err := cli.Executer(ctx, ns, pod, conteneur, "sh", "-c", script)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "OUVERT"), nil
}

// ancienHote returns the host recorded in an annotation value, or "".
func ancienHote(enregistre string) string {
	avant, _, trouve := strings.Cut(enregistre, "=")
	if !trouve {
		return ""
	}
	return avant
}

// aliasesSans returns the list without any entry naming one of the hosts given.
//
// IT REMOVES AN ENTRY RATHER THAN MERGING INTO IT: a `hostAliases` entry is
// (address, names), and an entry naming two hosts cannot be re-pointed without
// silently moving both. Dropping the conflicting entry and appending a fresh one
// keeps every other name where the operator put it.
func aliasesSans(aliases []corev1.HostAlias, hotes ...string) []corev1.HostAlias {
	vides := map[string]bool{}
	for _, h := range hotes {
		if h != "" {
			vides[h] = true
		}
	}
	gardes := make([]corev1.HostAlias, 0, len(aliases))
	for _, a := range aliases {
		conflit := false
		for _, nom := range a.Hostnames {
			if vides[nom] {
				conflit = true
				break
			}
		}
		if !conflit {
			gardes = append(gardes, a)
		}
	}
	return gardes
}
