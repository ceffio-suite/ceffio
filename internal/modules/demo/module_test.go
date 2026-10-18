//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Unit tests of the demo module against a FAKE clientset: the module
// contract (idempotent Install, observed State, re-runnable Uninstall) is
// verified without a cluster, exactly like the console's own module tests.
//
// The end-to-end proof (registry, CLI help, module list, console API, RBAC
// sum, and the absence of demo from untagged binaries) lives in
// integration_test.go.
package demo

import (
	"context"
	"io"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
)

func testEnv(cs *fake.Clientset) module.Env {
	return module.Env{Domain: "demo.test", Kube: cs, Out: io.Discard}
}

// TestInstallCreePuisMetAJour verifies the idempotency promise of
// module.Module: the first Install creates the ConfigMap, the second one
// UPDATES it instead of failing AlreadyExists — and a drifted ConfigMap is
// reconciled, which is the observable half of the promise.
func TestInstallCreePuisMetAJour(t *testing.T) {
	cs := fake.NewSimpleClientset()
	env := testEnv(cs)
	m := &demoModule{}
	ctx := context.Background()

	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	cm, err := cs.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap not created: %v", err)
	}
	if cm.Data["module"] != "demo" {
		t.Errorf("ConfigMap data = %v, want module=demo", cm.Data)
	}

	// Somebody edited the object behind the module's back.
	cm.Data["module"] = "tampered"
	if _, err := cs.CoreV1().ConfigMaps(nsSystem).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("simulating drift: %v", err)
	}

	// Second Install: no error (a plain Create would fail AlreadyExists
	// here), and the drift is reconciled.
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("second Install must be idempotent, got: %v", err)
	}
	cm, err = cs.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap disappeared after re-Install: %v", err)
	}
	if cm.Data["module"] != "demo" {
		t.Errorf("re-Install left drifted data %v: Install must reconcile, not just tolerate", cm.Data)
	}
}

// TestEtatSuitLeConfigMap verifies that State reports what is OBSERVED, in
// the three situations that matter: absent, installed, and no client
// (Unknown, never Absent — absence is a fact, not a default).
func TestEtatSuitLeConfigMap(t *testing.T) {
	cs := fake.NewSimpleClientset()
	env := testEnv(cs)
	m := &demoModule{}
	ctx := context.Background()

	if st := m.State(ctx, env); st.Status != module.Absent {
		t.Errorf("State before Install = %q, want absent", st.Status)
	}
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if st := m.State(ctx, env); st.Status != module.Installed {
		t.Errorf("State after Install = %q, want installed", st.Status)
	}
	if st := m.State(ctx, module.Env{}); st.Status != module.Unknown {
		t.Errorf("State without a Kubernetes client = %q, want unknown (never absent: nobody looked)", st.Status)
	}
}

// TestUninstallSupprimeEtEstRejouable verifies the removal and its
// re-runnability: a console retry after a partial uninstall must not error
// on the object it already deleted.
func TestUninstallSupprimeEtEstRejouable(t *testing.T) {
	cs := fake.NewSimpleClientset()
	env := testEnv(cs)
	m := &demoModule{}
	ctx := context.Background()

	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := m.Uninstall(ctx, env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if st := m.State(ctx, env); st.Status != module.Absent {
		t.Errorf("State after Uninstall = %q, want absent", st.Status)
	}
	if err := m.Uninstall(ctx, env); err != nil {
		t.Errorf("second Uninstall must be a no-op, got: %v", err)
	}
}

// TestInstallSansClientRefuse: without a Kubernetes client there is nowhere
// to write — Install must say so instead of pretending to succeed.
func TestInstallSansClientRefuse(t *testing.T) {
	m := &demoModule{}
	if err := m.Install(context.Background(), module.Env{}); err == nil {
		t.Error("Install without a Kubernetes client must fail, not succeed silently")
	}
	if err := m.Uninstall(context.Background(), module.Env{}); err == nil {
		t.Error("Uninstall without a Kubernetes client must fail, not succeed silently")
	}
}
