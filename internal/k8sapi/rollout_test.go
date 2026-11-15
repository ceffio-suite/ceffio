// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests of the deployment restart and rollout wait.
//
// WHY THEY EXIST: both replace a `kubectl` command whose output the mail module
// used to parse — and both have a failure mode that the old command HID. A
// restart that changes nothing looks like a successful command; a wait that
// returns too early lets the next `exec` land on the pod being deleted, and the
// resulting error blames the credentials. These tests pin the two behaviours
// that matter: the annotation really changes, and the wait really waits for the
// new generation to be available.
package k8sapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// deploiementDeTest builds a one-replica Deployment with an existing annotation
// and a generation the controller has already observed.
func deploiementDeTest() *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: "ceffio-mail", Generation: 2},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"existant": "garde"}},
			},
		},
	}
}

// cronometreSonde shortens the wait's polling interval for the duration of a
// test, and restores it.
func cronometreSonde(t *testing.T) {
	t.Helper()
	ancien := intervalleSonde
	intervalleSonde = time.Millisecond
	t.Cleanup(func() { intervalleSonde = ancien })
}

// TestRedemarrerDeploiementChangeLeGabarit: a restart is an observable change of
// the pod template, and it does not touch the other annotations.
func TestRedemarrerDeploiementChangeLeGabarit(t *testing.T) {
	cs := fake.NewSimpleClientset(deploiementDeTest())
	client := PourTest(cs, nil)
	ctx := context.Background()

	if err := client.RedemarrerDeploiement(ctx, "ceffio-mail", "stalwart"); err != nil {
		t.Fatalf("RedemarrerDeploiement() = %v", err)
	}
	d, err := cs.AppsV1().Deployments("ceffio-mail").Get(ctx, "stalwart", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the deployment back: %v", err)
	}
	premier, present := d.Spec.Template.Annotations[etiquetteRedemarrage]
	if !present {
		t.Fatalf("annotations = %v, the restart annotation is absent: no rollout was triggered",
			d.Spec.Template.Annotations)
	}
	if _, err := time.Parse(time.RFC3339Nano, premier); err != nil {
		t.Errorf("restart annotation = %q, want an RFC 3339 timestamp: %v", premier, err)
	}
	if d.Spec.Template.Annotations["existant"] != "garde" {
		t.Errorf("annotations = %v, the unrelated annotation was lost", d.Spec.Template.Annotations)
	}

	// THE SECOND RESTART MUST CHANGE THE VALUE. A constant annotation produces
	// no diff, so no rollout — and the caller waits for a change that never
	// comes.
	time.Sleep(2 * time.Millisecond)
	if err := client.RedemarrerDeploiement(ctx, "ceffio-mail", "stalwart"); err != nil {
		t.Fatalf("second RedemarrerDeploiement() = %v", err)
	}
	d, _ = cs.AppsV1().Deployments("ceffio-mail").Get(ctx, "stalwart", metav1.GetOptions{})
	if d.Spec.Template.Annotations[etiquetteRedemarrage] == premier {
		t.Errorf("annotation stayed %q across two restarts: the second one triggers no rollout", premier)
	}
}

// TestRedemarrerDeploiementNommeLeDeploiementAbsent: a missing Deployment is a
// clear error, not a silent success that leaves the operator waiting.
func TestRedemarrerDeploiementNommeLeDeploiementAbsent(t *testing.T) {
	client := PourTest(fake.NewSimpleClientset(), nil)
	err := client.RedemarrerDeploiement(context.Background(), "ceffio-mail", "stalwart")
	if err == nil || !strings.Contains(err.Error(), "ceffio-mail/stalwart") {
		t.Fatalf("RedemarrerDeploiement() = %v, want an error naming the deployment", err)
	}
}

// repondreAuRoulage installs a reactor that serves the Deployment with the
// given readiness on each read, so the wait's own condition is exercised
// without a real controller.
func repondreAuRoulage(cs *fake.Clientset, pret func(appels int) bool) *int {
	appels := 0
	cs.PrependReactor("get", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		appels++
		d := deploiementDeTest()
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation,
			Replicas:           1,
			UpdatedReplicas:    1,
			AvailableReplicas:  1,
		}
		if !pret(appels) {
			// The controller has not observed the new generation yet: the old
			// replica is still the one answering.
			d.Status.ObservedGeneration = 0
			d.Status.UpdatedReplicas = 0
			d.Status.AvailableReplicas = 0
		}
		return true, d, nil
	})
	return &appels
}

// TestAttendreDeploiementAttendLaNouvelleGeneration: the first read is not
// ready (old replica), the second is — the wait must poll rather than trust the
// deployment's existence.
func TestAttendreDeploiementAttendLaNouvelleGeneration(t *testing.T) {
	cronometreSonde(t)
	cs := fake.NewSimpleClientset()
	appels := repondreAuRoulage(cs, func(n int) bool { return n >= 2 })
	client := PourTest(cs, nil)

	if err := client.AttendreDeploiement(context.Background(), "ceffio-mail", "stalwart", 5*time.Second); err != nil {
		t.Fatalf("AttendreDeploiement() = %v", err)
	}
	if *appels < 2 {
		t.Errorf("reads = %d, want at least 2: the wait returned on the first, not-ready read", *appels)
	}
}

// TestAttendreDeploiementEchoueAvecLEtatAttendu: a rollout that never finishes
// must fail with the state it observed — "deployment not ready" without the
// counts sends the operator back to guessing.
func TestAttendreDeploiementEchoueAvecLEtatAttendu(t *testing.T) {
	cronometreSonde(t)
	cs := fake.NewSimpleClientset()
	repondreAuRoulage(cs, func(int) bool { return false })
	client := PourTest(cs, nil)

	err := client.AttendreDeploiement(context.Background(), "ceffio-mail", "stalwart", 50*time.Millisecond)
	if err == nil {
		t.Fatal("AttendreDeploiement() accepted a rollout that never finished")
	}
	if !strings.Contains(err.Error(), "generation 2 (observed 0)") {
		t.Errorf("error = %v, want the observed state", err)
	}
}

// TestAttendreDeploiementZeroReplique: a Deployment scaled to zero has nothing
// to wait for. Waiting forever would be the alternative.
func TestAttendreDeploiementZeroReplique(t *testing.T) {
	cronometreSonde(t)
	d := deploiementDeTest()
	zero := int32(0)
	d.Spec.Replicas = &zero
	d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation}
	client := PourTest(fake.NewSimpleClientset(d), nil)

	if err := client.AttendreDeploiement(context.Background(), "ceffio-mail", "stalwart", time.Second); err != nil {
		t.Fatalf("AttendreDeploiement() = %v", err)
	}
}

// TestAttendreDeploiementRespecteLeContexte: a cancelled context stops the wait
// instead of leaving a console request hanging for the whole timeout.
func TestAttendreDeploiementRespecteLeContexte(t *testing.T) {
	cronometreSonde(t)
	cs := fake.NewSimpleClientset()
	repondreAuRoulage(cs, func(int) bool { return false })
	client := PourTest(cs, nil)
	ctx, annuler := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		annuler()
	}()

	err := client.AttendreDeploiement(ctx, "ceffio-mail", "stalwart", time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("AttendreDeploiement() = %v, want context.Canceled", err)
	}
}
