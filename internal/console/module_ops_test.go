// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"testing"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
	"k8s.io/client-go/kubernetes/fake"
)

// moduleEspion records the environment its Install receives.
//
// WHY A SPY MODULE: the console used to hand modules an Env with only Domain,
// Kube and Out. Every module tolerated it because none of them read a setting
// during Install — the mail module is the first one that does, and a nil
// Settings there is a panic in the operation goroutine, not a visible error.
// The test states the contract instead of waiting for that crash.
type moduleEspion struct {
	recu chan module.Env
}

func (m *moduleEspion) Info() module.Info { return module.Info{ID: "espion", Title: "Espion"} }

func (m *moduleEspion) Install(ctx context.Context, env module.Env) error {
	m.recu <- env
	return nil
}

func (m *moduleEspion) Uninstall(ctx context.Context, env module.Env) error {
	m.recu <- env
	return nil
}

func (m *moduleEspion) State(ctx context.Context, env module.Env) module.State {
	return module.State{Status: module.Installed}
}

// TestLInstallationDepuisLaConsoleFournitUnEnvComplet: the console's operation
// path must build the same Env as the CLI's.
func TestLInstallationDepuisLaConsoleFournitUnEnvComplet(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := &Server{Domain: "ceffio.example.com", kube: cs, ops: newOpsManager()}
	cm := &cmFactice{donnees: map[string]string{}}
	sec := &secFactice{donnees: map[string]map[string]string{}}
	s.settingsCM, s.settingsSec = cm, sec

	m := &moduleEspion{recu: make(chan module.Env, 1)}
	if _, ok := s.ops.tryStart("espion", actionInstall); !ok {
		t.Fatal("the module slot was already busy")
	}
	s.runOperation("espion", m, actionInstall)

	var env module.Env
	select {
	case env = <-m.recu:
	case <-time.After(5 * time.Second):
		t.Fatal("Install was never called")
	}

	if env.Domain != s.Domain {
		t.Errorf("Domain = %q, expected %q", env.Domain, s.Domain)
	}
	if env.Kube != cs {
		t.Error("the Kubernetes client is not the server's")
	}
	if env.Out == nil {
		t.Error("Out is nil: the module would panic on its first progress line")
	}
	if env.ModuleID != "espion" {
		t.Errorf("ModuleID = %q, expected the module being installed", env.ModuleID)
	}
	if env.Settings == nil {
		t.Error("Settings is nil: an install that writes a setting would panic")
	}
	if env.Secrets == nil {
		t.Error("Secrets is nil: an install that reads a secret would panic")
	}
	// The stores must be the SERVER'S, not fresh copies: a module that writes
	// a setting during Install has to land where the settings page reads it.
	if env.Settings != module.ConfigMapStore(cm) {
		t.Error("Settings is not the console's store")
	}
	if env.Secrets != module.SecretStore(sec) {
		t.Error("Secrets is not the console's store")
	}
}
