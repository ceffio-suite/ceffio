// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package socle groups the state reads shared by the modules of the ten
// core layers (Kind Core).
//
// WHY A SHARED PACKAGE: the ten modules read state the same way — counting
// the ready pods that carry their workloads — and the filtering rules
// (ignore pods in Terminating, do not count a Succeeded job as "not ready",
// a pod without any container status is not ready) are EXACTLY those of the
// status page (internal/console/status.go). Duplicating them ten times
// would guarantee ten silent drifts; sharing them guarantees a single truth
// between the CLI, the console and the doctor.
//
// This package registers NO module (no call to module.Register): it
// therefore does not need to appear in internal/modules/all.go, and the
// all_test.go guard test does not require it.
package socle

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// sansClient is the state returned when Env carries no Kubernetes client:
// without a cluster connection, any read would be an invention. We answer
// Unknown, never Absent — absence is an observed fact, not a lack of
// point of view.
func sansClient() module.State {
	return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment"}
}

// porte says whether the pod name is carried by one of the prefixes, with
// the same rule as porteService in internal/console/status.go: the name must
// start with "prefix-", so that "talk-signaling" does not match a
// "talk-recording-…" pod.
func porte(podNom string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(podNom, p+"-") {
			return true
		}
	}
	return false
}

// podPret follows the status page rule: all containers ready, and at least
// one container status — a pod that has no status yet (image being pulled)
// is not ready.
func podPret(p corev1.Pod) bool {
	if len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}

// EtatDesPods computes the state of a module from the pods of its namespaces
// whose name starts with one of the prefixes.
//
// WHY these thresholds: no pod → Absent (the layer is not there); all
// ready → Installed; otherwise Degraded with the real count. A read failure
// (API unreachable, namespace unreadable) → Unknown: we never conclude
// "absent" on a failure, exactly like the existing modules.
func EtatDesPods(ctx context.Context, env module.Env, namespaces []string, prefixes []string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	total, prets := 0, 0
	for _, ns := range namespaces {
		pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return module.State{Status: module.Unknown,
				Detail: fmt.Sprintf("listing pods in %s: %v", ns, err)}
		}
		for _, p := range pods.Items {
			// Same filtering as the status page: a pod being
			// deleted skews the totals, and a finished job
			// (Succeeded) is not "not ready".
			if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded {
				continue
			}
			if !porte(p.Name, prefixes) {
				continue
			}
			total++
			if podPret(p) {
				prets++
			}
		}
	}
	switch {
	case total == 0:
		return module.State{Status: module.Absent}
	case prets == total:
		return module.State{Status: module.Installed}
	case prets > 0:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("%d/%d pods ready", prets, total)}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("0/%d pods ready", total)}
	}
}

// EtatDuDeploiement reads the state of a specific Deployment (name +
// namespace).
//
// WHY a distinct helper: some workloads of the core cannot be spotted by
// pod prefix in THEIR namespaces (the CNPG operator lives in cnpg-system,
// cert-manager in cert-manager); the ready deployment is then the most
// direct signal. Like k8sapi.DeploiementPret, we read the status and not
// mere existence: a Deployment with zero ready replicas exists, and
// answering "installed" for it would announce a service that serves
// nothing.
func EtatDuDeploiement(ctx context.Context, env module.Env, ns, nom string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	d, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading deployment %s/%s: %v", ns, nom, err)}
	case d.Status.ReadyReplicas > 0:
		return module.State{Status: module.Installed}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("deployment %s/%s exists but has no ready replica", ns, nom)}
	}
}

// EtatNamespaceActif returns Installed if the namespace exists and is
// Active, Absent if it does not exist, Unknown if the read fails.
//
// WHY read the phase and not mere existence: a namespace in Terminating
// still exists but no longer accepts any creation — answering "installed"
// for it would make the next deployment fail without the diagnostic seeing
// anything.
func EtatNamespaceActif(ctx context.Context, env module.Env, nom string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading namespace %s: %v", nom, err)}
	case ns.Status.Phase == corev1.NamespaceActive:
		return module.State{Status: module.Installed}
	default:
		return module.State{Status: module.Degraded,
			Detail: fmt.Sprintf("namespace %s is %s", nom, ns.Status.Phase)}
	}
}

// EtatLePlusBas combines several states: a module backed by several
// workloads is "installed" only if ALL of them are.
//
// WHY Unknown wins: if one of the reads could not complete, nothing can be
// concluded — answering Degraded would invent a diagnostic, and answering
// Installed would hide the unknown.
func EtatLePlusBas(etats ...module.State) module.State {
	installes, absents := 0, 0
	var details []string
	for _, e := range etats {
		if e.Status == module.Unknown {
			return e
		}
		switch e.Status {
		case module.Installed:
			installes++
		case module.Absent:
			absents++
		}
		if e.Detail != "" {
			details = append(details, e.Detail)
		}
	}
	detail := strings.Join(details, "; ")
	switch {
	case installes == len(etats):
		return module.State{Status: module.Installed, Detail: detail}
	case absents == len(etats):
		return module.State{Status: module.Absent}
	default:
		return module.State{Status: module.Degraded, Detail: detail}
	}
}

// ErreurSocleIndemontable is the error returned by Uninstall for any layer
// of the core.
//
// WHY AN ERROR AND NOT A REMOVAL: the ten layers are the product — the
// Module interface requires Uninstall, but no per-layer uninstall exists or
// makes sense (removing PostgreSQL or identity would leave an amnesiac
// suite that believes itself healthy). The real uninstall is
// `ceffio uninstall`, which destroys the entire cluster. A function that
// would claim to remove the layer would lie; an explicit error tells the
// truth and prevents a frontend from triggering a destructive partial
// removal.
func ErreurSocleIndemontable(id string) error {
	return fmt.Errorf("%s is a core layer of the suite: it is removed with the cluster (ceffio uninstall), not on its own", id)
}

// EtatDesDeploiements reports Installed only when EVERY named Deployment is ready.
//
// WHY NOT EtatDuDeploiement IN A LOOP: the loop's last answer is not the whole answer.
// A layer made of three workloads is installed when all three run — reading only the
// last, or the first, reports Installed while the others are missing, which is how a
// single-deployment check made the Longhorn UI look healthy while nothing could claim
// a volume.
//
// A MISSING DEPLOYMENT NAMES ITSELF. Saying "the storage is absent" when only
// longhorn-ui is missing sends the reader to look at the wrong thing.
func EtatDesDeploiements(ctx context.Context, env module.Env, ns string, noms []string) module.State {
	if env.Kube == nil {
		return sansClient()
	}
	var absents, indisponibles []string
	for _, nom := range noms {
		d, err := env.Kube.AppsV1().Deployments(ns).Get(ctx, nom, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			absents = append(absents, nom)
		case err != nil:
			return module.State{Status: module.Unknown,
				Detail: fmt.Sprintf("reading deployment %s/%s: %v", ns, nom, err)}
		case d.Status.ReadyReplicas == 0:
			indisponibles = append(indisponibles, nom)
		}
	}
	if len(absents) == len(noms) {
		return module.State{Status: module.Absent}
	}
	if len(absents) > 0 || len(indisponibles) > 0 {
		var parties []string
		if len(absents) > 0 {
			parties = append(parties, "missing: "+strings.Join(absents, ", "))
		}
		if len(indisponibles) > 0 {
			parties = append(parties, "not ready: "+strings.Join(indisponibles, ", "))
		}
		return module.State{Status: module.Degraded,
			Detail: ns + " — " + strings.Join(parties, " · ")}
	}
	return module.State{Status: module.Installed}
}
