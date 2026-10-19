//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package demo

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// THE SETTINGS, TESTED THROUGH THE SAME ROUTES THE PRODUCT USES.
//
// This file exercises the contract on a real module: it implements
// Configurable and Testable, and every assertion below goes through
// Settings/Current/Apply — the three methods the console and the CLI call.
// A break in the module, or in the contract, shows up here.
//
// The cluster is a FAKE clientset: the module stores into a ConfigMap, so the
// whole round trip runs without a cluster.

func envAvecConfigMap(t *testing.T) (module.Env, *fake.Clientset) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	return module.Env{ModuleID: "demo", Kube: cs, Out: &strings.Builder{}}, cs
}

// TestLeModuleEstConfigured : the module implements the two optional interfaces.
//
// It is the first thing the console and the CLI check, and a module that loses
// them silently stops appearing in the Settings section with no error anywhere.
func TestLeModuleEstConfigurableEtTestable(t *testing.T) {
	var m module.Module = &demoModule{}
	if _, ok := m.(module.Configurable); !ok {
		t.Fatal("the demo module no longer implements Configurable")
	}
	if _, ok := m.(module.Testable); !ok {
		t.Fatal("the demo module no longer implements Testable")
	}
}

// TestInstallPuisReglages : the round trip — install, save, read back.
func TestInstallPuisReglages(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()

	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	g := m.Settings()[0]
	if err := m.Apply(ctx, env, g.ID, module.Values{
		"message": "bonjour", "mode": "simple", "loud": "true", "token": "s3cr3t",
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	obtenu, err := m.Current(ctx, env, g.ID)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if obtenu["message"] != "bonjour" {
		t.Errorf("message = %q, want bonjour", obtenu["message"])
	}
	if obtenu["loud"] != "true" {
		t.Errorf("loud = %q, want true", obtenu["loud"])
	}
}

// TestLeSecretNEstJamaisRenvoye : Current answers the placeholder, never the
// value.
//
// The rule holds for the console AND the CLI because it is enforced HERE, in the
// only method that reads a secret for a frontend. A module that returned the
// value would leak it to every frontend at once.
func TestLeSecretNEstJamaisRenvoye(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}

	const vrai = "mon-jeton-secret"
	g := m.Settings()[0]
	if err := m.Apply(ctx, env, g.ID, module.Values{"message": "hi", "token": vrai}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	obtenu, err := m.Current(ctx, env, g.ID)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if obtenu["token"] == vrai {
		t.Fatal("Current returned the secret itself")
	}
	if obtenu["token"] != module.SecretSet {
		t.Errorf("token = %q, want the placeholder", obtenu["token"])
	}
}

// TestLeSecretVideConserveLAncien : an empty secret keeps the stored one.
func TestLeSecretVideConserveLAncien(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	g := m.Settings()[0]

	if err := m.Apply(ctx, env, g.ID, module.Values{"message": "a", "token": "ancien"}); err != nil {
		t.Fatalf("premier Apply: %v", err)
	}
	// A second save changes the message and leaves the secret empty.
	if err := m.Apply(ctx, env, g.ID, module.Values{"message": "b", "token": ""}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	// The stored value must still be the original.
	cm, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the ConfigMap: %v", err)
	}
	stoc, err := lireReglages(cm.Data[cleReglages], g)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if stoc["token"] != "ancien" {
		t.Errorf("the secret was lost: token = %q, want ancien", stoc["token"])
	}
	if stoc["message"] != "b" {
		t.Errorf("the message was not saved: %q", stoc["message"])
	}
}

// TestApplyRefuseUneValeurInvalide : the shared validation runs, so the CLI and
// the console refuse the same things.
func TestApplyRefuseUneValeurInvalide(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	g := m.Settings()[0]

	// The message is required.
	if err := m.Apply(ctx, env, g.ID, module.Values{"message": ""}); err == nil {
		t.Error("an empty required message was accepted")
	}
	// The colour must match its pattern — and it is only checked in fancy mode,
	// which is why it is submitted there.
	if err := m.Apply(ctx, env, g.ID, module.Values{
		"message": "hi", "mode": "fancy", "colour": "pas-une-couleur",
	}); err == nil {
		t.Error("a colour breaking its pattern was accepted in fancy mode")
	}
}

// TestLesAutresClesDuConfigMapSurvivent : saving settings does not erase what
// Install wrote.
//
// WHY THIS IS ITS OWN TEST: the module's ConfigMap carries both its own state
// (module, purpose) and the settings. A save that replaced the object would
// destroy the module's identity — a loss nothing would report, and that
// Uninstall or a status read would then get wrong.
func TestLesAutresClesDuConfigMapSurvivent(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := m.Apply(ctx, env, m.Settings()[0].ID, module.Values{"message": "hi"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cm, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the ConfigMap: %v", err)
	}
	if cm.Data["module"] != "demo" {
		t.Errorf("Install's own key was erased: %v", cm.Data)
	}
	if cm.Data[cleReglages] == "" {
		t.Errorf("the settings were not written: %v", cm.Data)
	}
}

// TestTestResult : the check reports what it tried, and refuses an empty message.
func TestTestResult(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)

	r := m.Test(context.Background(), env, "greeting", module.Values{"message": "hi"})
	if !r.OK {
		t.Errorf("a valid message was refused: %+v", r)
	}
	if len(r.Steps) == 0 {
		t.Error("the result carries no steps: a failed check would leave the operator guessing")
	}

	r = m.Test(context.Background(), env, "greeting", module.Values{"message": "  "})
	if r.OK {
		t.Error("an empty message passed the check")
	}
	if r.Detail == "" {
		t.Error("a failing check carries no detail")
	}

	r = m.Test(context.Background(), env, "nexistepas", module.Values{})
	if r.OK {
		t.Error("an unknown group passed the check")
	}
}

// TestCurrentSansInstallation : reading before Install answers the defaults,
// not an error.
//
// The console draws the form for a module that is not installed yet, so a read
// that failed would leave the page empty on exactly the installation that has
// something to configure.
func TestCurrentSansInstallation(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)

	obtenu, err := m.Current(context.Background(), env, "greeting")
	if err != nil {
		t.Fatalf("Current on an uninstalled module: %v", err)
	}
	if obtenu["message"] != "hello" {
		t.Errorf("message = %q, want the declared default", obtenu["message"])
	}
	if obtenu["token"] != "" {
		t.Errorf("an unset secret reads as %q, want empty", obtenu["token"])
	}
}

// TestGroupeInconnuEstRefuse : an unknown group is named, not ignored.
func TestGroupeInconnuEstRefuse(t *testing.T) {
	m := &demoModule{}
	env, _ := envAvecConfigMap(t)
	ctx := context.Background()

	if _, err := m.Current(ctx, env, "nexistepas"); err == nil {
		t.Error("Current accepted an unknown group")
	}
	if err := m.Apply(ctx, env, "nexistepas", module.Values{"x": "y"}); err == nil {
		t.Error("Apply accepted an unknown group")
	}
}
