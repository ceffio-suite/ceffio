// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package k8sapi

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// WHY THESE TESTS EXIST: every exec in this program (Nextcloud's settings, the
// mail server's accounts, the theme) starts by naming a pod. Picking the wrong
// one — a pod being deleted, or one that is not serving yet — makes a SEQUENCE of
// commands fail in its middle, and the failure then names whatever the first lost
// command was about instead of the pod. That is a live defect from 0.11.0-rc.5,
// where the write to Nextcloud stopped at its fifth key.

// podDeTest builds a pod with the Deployment's label and the given state.
func podDeTest(nom string, phase corev1.PodPhase, pret bool, suppression *metav1.Time) *corev1.Pod {
	etat := corev1.ConditionFalse
	if pret {
		etat = corev1.ConditionTrue
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              nom,
			Namespace:         "ceffio-files",
			Labels:            map[string]string{"app": "nextcloud"},
			DeletionTimestamp: suppression,
		},
		Status: corev1.PodStatus{
			Phase: phase,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: etat},
			},
		},
	}
	return p
}

// TestPodDuDeploiementIgnoreUnPodEnSuppression: the Ready pod that is going away
// must not be chosen, even when it is listed first. Its containers are being
// stopped, so an exec either fails outright or kills the run mid-way.
func TestPodDuDeploiementIgnoreUnPodEnSuppression(t *testing.T) {
	maintnant := metav1.NewTime(time.Now())
	client := PourTest(kubefake.NewSimpleClientset(
		podDeTest("pod-a-supprime", corev1.PodRunning, true, &maintnant),
		podDeTest("pod-b-actif", corev1.PodRunning, true, nil),
	), nil)

	nom, err := client.PodDuDeploiement(context.Background(), "ceffio-files", "nextcloud", "nextcloud")
	if err != nil {
		t.Fatalf("PodDuDeploiement() = %v", err)
	}
	if nom != "pod-b-actif" {
		t.Fatalf("PodDuDeploiement() chose %q, a pod being deleted; the exec would race its containers", nom)
	}
}

// TestPodDuDeploiementPrefereUnPodPret: a pod that is Running but not Ready yet
// may accept an exec whose command then fails for reasons the operator cannot
// see. A Ready pod is preferred whenever one exists.
func TestPodDuDeploiementPrefereUnPodPret(t *testing.T) {
	client := PourTest(kubefake.NewSimpleClientset(
		podDeTest("pod-a-en-demarrage", corev1.PodRunning, false, nil),
		podDeTest("pod-b-pret", corev1.PodRunning, true, nil),
	), nil)

	nom, err := client.PodDuDeploiement(context.Background(), "ceffio-files", "nextcloud", "nextcloud")
	if err != nil {
		t.Fatalf("PodDuDeploiement() = %v", err)
	}
	if nom != "pod-b-pret" {
		t.Fatalf("PodDuDeploiement() chose %q over the Ready pod", nom)
	}
}

// TestPodDuDeploiementAccepteUnPodPasEncorePret: when no Ready pod exists, the
// running one is still the only possible target — refusing it would turn a
// starting application into an unexplained failure.
func TestPodDuDeploiementAccepteUnPodPasEncorePret(t *testing.T) {
	client := PourTest(kubefake.NewSimpleClientset(
		podDeTest("pod-a-en-demarrage", corev1.PodRunning, false, nil),
	), nil)

	nom, err := client.PodDuDeploiement(context.Background(), "ceffio-files", "nextcloud", "nextcloud")
	if err != nil {
		t.Fatalf("PodDuDeploiement() = %v", err)
	}
	if nom != "pod-a-en-demarrage" {
		t.Fatalf("PodDuDeploiement() = %q, want the running pod", nom)
	}
}

// TestPodDuDeploiementSansPodEnMarche: a Pending pod, or a pod being deleted, is
// not a target; the error must say which Deployment was empty.
func TestPodDuDeploiementSansPodEnMarche(t *testing.T) {
	maintnant := metav1.NewTime(time.Now())
	client := PourTest(kubefake.NewSimpleClientset(
		podDeTest("pod-a-en-attente", corev1.PodPending, false, nil),
		podDeTest("pod-b-supprime", corev1.PodRunning, true, &maintnant),
	), nil)

	_, err := client.PodDuDeploiement(context.Background(), "ceffio-files", "nextcloud", "nextcloud")
	if err == nil {
		t.Fatal("PodDuDeploiement() accepted a Pending pod as an exec target")
	}
	if !strings.Contains(err.Error(), "deployment nextcloud") {
		t.Fatalf("the error does not name the deployment: %v", err)
	}
}
