// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// moduleRejoue records what a replay does to it.
type moduleRejoue struct {
	info      Info
	etat      State
	installé  bool
	vus       []string
	installer func() error
}

func (m *moduleRejoue) Info() Info                           { return m.info }
func (m *moduleRejoue) State(context.Context, Env) State     { return m.etat }
func (m *moduleRejoue) Uninstall(context.Context, Env) error { return nil }

func (m *moduleRejoue) Install(_ context.Context, env Env) error {
	m.installé = true
	// Le module doit recevoir SON identifiant : les réglages sont rangés là.
	m.vus = append(m.vus, env.ModuleID)
	if m.installer != nil {
		return m.installer()
	}
	return nil
}

// TestUnModuleInstalleEstRejoue: that is the whole point — an installed module
// follows the binary on an upgrade.
func TestUnModuleInstalleEstRejoue(t *testing.T) {
	rec := &moduleRejoue{info: Info{ID: "recording", Kind: Optional}, etat: State{Status: Installed}}
	if err := RejouerInstalles(context.Background(), []Module{rec}, Env{Out: io.Discard}, nil); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !rec.installé {
		t.Error("an installed optional module must be replayed")
	}
	if len(rec.vus) != 1 || rec.vus[0] != "recording" {
		t.Errorf("ModuleID = %v, expected the module's own id", rec.vus)
	}
}

// TestUnModuleAbsentNEstPasInstalle: replaying must never INSTALL something the
// operator did not ask for — an upgrade is not an installation.
func TestUnModuleAbsentNEstPasInstalle(t *testing.T) {
	for _, etat := range []State{{Status: Absent}, {Status: Degraded}, {Status: Installing}, {Status: Unknown}} {
		rec := &moduleRejoue{info: Info{ID: "capture", Kind: Optional}, etat: etat}
		if err := RejouerInstalles(context.Background(), []Module{rec}, Env{Out: io.Discard}, nil); err != nil {
			t.Fatalf("replay: %v", err)
		}
		if rec.installé {
			t.Errorf("state %q: a module that is not installed must not be installed by an upgrade", etat.Status)
		}
	}
}

// TestUnModuleCoreNEstPasRejoueIci: the core layers belong to Redeployer; a
// second replay from here would deploy them twice.
func TestUnModuleCoreNEstPasRejoueIci(t *testing.T) {
	rec := &moduleRejoue{info: Info{ID: "files", Kind: Core}, etat: State{Status: Installed}}
	if err := RejouerInstalles(context.Background(), []Module{rec}, Env{Out: io.Discard}, nil); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rec.installé {
		t.Error("a core module is replayed by Redeployer, not here")
	}
}

// TestUneErreurDeRejeuSArrete: a module that fails must stop the upgrade, not be
// skipped silently — the operator has to learn it.
func TestUneErreurDeRejeuSArrete(t *testing.T) {
	cassé := &moduleRejoue{info: Info{ID: "capture", Kind: Optional}, etat: State{Status: Installed},
		installer: func() error { return errors.New("boom") }}
	suivant := &moduleRejoue{info: Info{ID: "recording", Kind: Optional}, etat: State{Status: Installed}}

	err := RejouerInstalles(context.Background(), []Module{cassé, suivant}, Env{Out: io.Discard}, nil)
	if err == nil {
		t.Fatal("a failing module must stop the replay")
	}
	if !strings.Contains(err.Error(), "capture") {
		t.Errorf("error = %v, the module must be named", err)
	}
	if suivant.installé {
		t.Error("the replay must stop at the first failure")
	}
}
