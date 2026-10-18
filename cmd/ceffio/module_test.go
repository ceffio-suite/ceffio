// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// Tests of the registry-driven selection logic of `ceffio install` and of
// the layer list derived from the registry. They exercise the REAL registry
// (internal/modules is imported through module.go), so they also act as a
// guardrail: a module added to the registry that breaks the selection rules
// fails here.

import (
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

func idsOf(modules []module.Module) []string {
	out := []string{}
	for _, m := range modules {
		out = append(out, m.Info().ID)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSelectedOptionalModulesDefaut: with no flag, the Default Optional
// modules are selected (recording today) and nothing else.
func TestSelectedOptionalModulesDefaut(t *testing.T) {
	got, err := selectedOptionalModules(&installOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// THE EXPECTED LIST IS WRITTEN OUT, NOT DERIVED FROM THE REGISTRY.
	//
	// Deriving it (walking module.All() for Optional+Default) made the test
	// unable to fail: flipping a module's Default changed the code AND the
	// expectation in the same move, so the assertion held either way. A
	// default install is a promise to the operator — recording is part of
	// it, HaRP and live transcription are not — and a promise is verified
	// against what was promised, not against what the code happens to do.
	want := []string{"recording"}
	if !equalStrings(idsOf(got), want) {
		t.Errorf("default selection = %v, want %v: this list is what `ceffio install` promises to deploy", idsOf(got), want)
	}
}

// TestSelectedOptionalModulesSans: --without recording drops it.
func TestSelectedOptionalModulesSans(t *testing.T) {
	got, err := selectedOptionalModules(&installOptions{without: []string{"recording"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The assertion is NOT "recording is absent": an empty selection would
	// satisfy that, and an empty selection is precisely the failure worth
	// catching — `--without recording` means "everything else still applies",
	// not "install nothing". The two cases are named separately.
	for _, id := range idsOf(got) {
		if id == "recording" {
			t.Error("--without recording still selected recording")
		}
	}
	if len(got) != 0 {
		t.Errorf("--without recording selected %v: recording is the only default optional module, "+
			"so excluding it must leave nothing — a non-empty list here means a module became "+
			"default without this test being updated", idsOf(got))
	}
}

// TestSelectedOptionalModulesAvecDependance: --with live-transcription pulls
// its dependency exapps-daemon in, and the registry order puts the
// dependency FIRST.
func TestSelectedOptionalModulesAvecDependance(t *testing.T) {
	got, err := selectedOptionalModules(&installOptions{with: []string{"live-transcription"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := idsOf(got)

	var posDaemon, posTranscription = -1, -1
	for i, id := range ids {
		switch id {
		case "exapps-daemon":
			posDaemon = i
		case "live-transcription":
			posTranscription = i
		}
	}
	if posDaemon < 0 {
		t.Fatalf("exapps-daemon was not added as a dependency: %v", ids)
	}
	if posTranscription < 0 {
		t.Fatalf("live-transcription missing from the selection: %v", ids)
	}
	if posDaemon > posTranscription {
		t.Errorf("dependency order violated: %v (exapps-daemon must come first)", ids)
	}
}

// TestSelectedOptionalModulesAliasDeprecie: the old boolean flag selects the
// same module as --with live-transcription.
func TestSelectedOptionalModulesAliasDeprecie(t *testing.T) {
	got, err := selectedOptionalModules(&installOptions{liveTranscription: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, id := range idsOf(got) {
		if id == "live-transcription" {
			found = true
		}
	}
	if !found {
		t.Errorf("--live-transcription did not select live-transcription: %v", idsOf(got))
	}
}

// TestSelectedOptionalModulesInconnu: an unknown ID is an error, whatever
// the flag — a typo must not silently drop a feature.
func TestSelectedOptionalModulesInconnu(t *testing.T) {
	if _, err := selectedOptionalModules(&installOptions{with: []string{"nope"}}); err == nil {
		t.Error("--with nope: expected an error")
	}
	if _, err := selectedOptionalModules(&installOptions{without: []string{"nope"}}); err == nil {
		t.Error("--without nope: expected an error")
	}
	if _, err := selectedOptionalModules(&installOptions{with: []string{"talk"}}); err == nil {
		t.Error("--with talk (core): expected an error")
	}
	if _, err := selectedOptionalModules(&installOptions{
		with: []string{"recording"}, without: []string{"recording"},
	}); err == nil {
		t.Error("--with X --without X: expected an error")
	}
}

// TestRegistryLayers: every namespace declared by the registry appears
// exactly once (the invariant stack.Collect relies on), and the namespaces
// the old hardcoded table missed are now present.
func TestRegistryLayers(t *testing.T) {
	layers := registryLayers()

	seen := map[string]bool{}
	for _, l := range layers {
		if seen[l.Namespace] {
			t.Errorf("namespace %q listed twice (pods would be double-counted)", l.Namespace)
		}
		seen[l.Namespace] = true
		if l.Name == "" {
			t.Errorf("layer for %q has an empty name", l.Namespace)
		}
	}

	// Declared by the registry (verified in internal/modules/*/module.go)
	// and ABSENT from the former stack.Layers table: their absence from
	// `ceffio status` is exactly the bug this derivation fixes.
	for _, ns := range []string{"ceffio-mail", "ceffio-exapps", "ceffio-vault", "cert-manager", "cnpg-system"} {
		if !seen[ns] {
			t.Errorf("namespace %q declared by the registry is missing from the layers", ns)
		}
	}

	// Completeness against the registry itself, not a hardcoded list.
	for _, m := range module.All() {
		for _, ns := range m.Info().Namespaces {
			if !seen[ns] {
				t.Errorf("namespace %q of module %q missing from the layers", ns, m.Info().ID)
			}
		}
	}
}

// TestNamespaceOnlyOptional: the severity rule of doctor, driven by Kind.
func TestNamespaceOnlyOptional(t *testing.T) {
	// ceffio-exapps: exapps-daemon and live-transcription, both Optional.
	if !namespaceOnlyOptional("ceffio-exapps") {
		t.Error("ceffio-exapps should be optional-only")
	}
	// ceffio-video: talk is Core and lives there — never optional-only,
	// even though recording (Optional) shares the namespace.
	if namespaceOnlyOptional("ceffio-video") {
		t.Error("ceffio-video should NOT be optional-only (talk is Core)")
	}
	// An unknown namespace is not claimed by anything: not optional-only.
	if namespaceOnlyOptional("ceffio-rien") {
		t.Error("an unclaimed namespace should not be optional-only")
	}
}

// TestPlanInstallation: the closure of live-transcription contains its
// dependency, in registry order.
func TestPlanInstallation(t *testing.T) {
	plan := planInstallation("live-transcription")
	ids := idsOf(plan)
	if len(ids) != 2 || ids[0] != "exapps-daemon" || ids[1] != "live-transcription" {
		t.Errorf("plan = %v, want [exapps-daemon live-transcription]", ids)
	}
	// A module without dependencies plans alone.
	if ids := idsOf(planInstallation("recording")); len(ids) != 1 || ids[0] != "recording" {
		t.Errorf("recording plan = %v, want [recording]", ids)
	}
}
