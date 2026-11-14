// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests for `module check` and for the DNS host filter that decides which
// declared names are expected to exist.
//
// WHAT EACH TEST REFUSES:
//
//   - TestVerifierModuleCheckRefuseUnModuleSansCheck: a command that prints
//     nothing and exits 0 for a module that declares no check — the empty
//     success a verification command must never produce.
//   - TestVerifierModuleCheckCompteLesBloquants: the exit code living in the
//     printing code (a warning would fail the command, or a blocking check
//     would not) and the fix being dropped from the output.
//   - TestAfficherChecksIndenteLeFix: a multi-line fix printed flush left,
//     which reads as several checks instead of one copyable block.
//   - TestFiltrerAbsentsGardeLInconnu: an empty, reassuring host list when the
//     cluster could not be read (every state is Unknown then).
//   - TestFiltrerAbsentsRetireLAbsent: a missing record reported for a module
//     the operator never installed.
package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// fauxVerif is a module whose checks are canned. It deliberately does NOT
// declare Checks on the embedded base type, so one test can use it as a module
// without checks and another as a Checker.
type fauxVerifBase struct{ info module.Info }

func (f *fauxVerifBase) Info() module.Info { return f.info }
func (f *fauxVerifBase) Install(context.Context, module.Env) error {
	return nil
}
func (f *fauxVerifBase) Uninstall(context.Context, module.Env) error {
	return nil
}
func (f *fauxVerifBase) State(context.Context, module.Env) module.State {
	return module.State{Status: module.Installed}
}

type fauxVerifie struct {
	fauxVerifBase
	checks []module.Check
}

func (f *fauxVerifie) Checks(context.Context, module.Env) []module.Check { return f.checks }

// TestVerifierModuleCheckRefuseUnModuleSansCheck: refusal, not an empty success.
func TestVerifierModuleCheckRefuseUnModuleSansCheck(t *testing.T) {
	m := &fauxVerifBase{info: module.Info{ID: "nu", Title: "Nu"}}
	var out bytes.Buffer
	bloquants, err := verifierModuleCheck(context.Background(), m, module.Env{}, &out)
	if err == nil {
		t.Fatalf("a module without checks was accepted (output: %q): silence reads as "+
			"\"everything verified\"", out.String())
	}
	if !strings.Contains(err.Error(), "declares no check") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if bloquants != 0 {
		t.Errorf("refusal returned %d blocking checks, expected 0", bloquants)
	}
}

// TestVerifierModuleCheckCompteLesBloquants: only `blocking` counts, and every
// field of the contract reaches the output.
func TestVerifierModuleCheckCompteLesBloquants(t *testing.T) {
	m := &fauxVerifie{
		fauxVerifBase: fauxVerifBase{info: module.Info{ID: "verif", Title: "Vérifié"}},
		checks: []module.Check{
			{ID: "mx", Label: "MX record", Level: module.CheckOK, Detail: "mail.example.org"},
			{ID: "ptr", Label: "Reverse DNS", Level: module.CheckWarning, Detail: "absent"},
			{ID: "relay", Label: "Relay", Level: module.CheckNotApplicable, Detail: "direct"},
			{ID: "tls", Label: "Certificate", Level: module.CheckBlocking,
				Detail: "self-signed", Fix: "ceffio module install verif"},
		},
	}
	var out bytes.Buffer
	bloquants, err := verifierModuleCheck(context.Background(), m, module.Env{}, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bloquants != 1 {
		t.Errorf("%d blocking checks counted, expected 1: warnings and not-applicable "+
			"checks describe a decision, not a fault", bloquants)
	}
	texte := out.String()
	for _, attendu := range []string{
		"MX record", "mail.example.org", // label and the measurement
		"Reverse DNS", "Relay", "direct",
		"Certificate", "self-signed",
		"ceffio module install verif", // the fix
		"1 blocking",                  // the summary
		"✗", "⚠", "·", "✓",            // one mark per level, never a silent level
	} {
		if !strings.Contains(texte, attendu) {
			t.Errorf("output does not contain %q:\n%s", attendu, texte)
		}
	}
}

// TestVerifierModuleCheckSansBloquantReussit: a warning alone does not fail.
func TestVerifierModuleCheckSansBloquantReussit(t *testing.T) {
	m := &fauxVerifie{
		fauxVerifBase: fauxVerifBase{info: module.Info{ID: "avert", Title: "Avertissement"}},
		checks: []module.Check{
			{ID: "volume", Label: "Volume", Level: module.CheckWarning, Detail: "80 % used"},
		},
	}
	var out bytes.Buffer
	bloquants, err := verifierModuleCheck(context.Background(), m, module.Env{}, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bloquants != 0 {
		t.Errorf("%d blocking checks counted, expected 0", bloquants)
	}
	if !strings.Contains(out.String(), "no blocking check") {
		t.Errorf("the success is not stated: an empty summary and a skipped check look "+
			"the same:\n%s", out.String())
	}
}

// TestAfficherChecksIndenteLeFix: a multi-line fix stays one indented block.
func TestAfficherChecksIndenteLeFix(t *testing.T) {
	var out bytes.Buffer
	bloquants := afficherChecks(&out, []module.Check{{
		ID: "records", Label: "DNS records", Level: module.CheckBlocking,
		Fix: "example.org. IN MX 10 mail.example.org.\nmail.example.org. IN A 192.0.2.10",
	}})
	if bloquants != 1 {
		t.Fatalf("%d blocking checks counted, expected 1", bloquants)
	}
	lignes := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lignes) != 3 {
		t.Fatalf("%d output lines, expected 3 (check + two fix lines):\n%s", len(lignes), out.String())
	}
	for i, ligne := range lignes[1:] {
		if !strings.HasPrefix(ligne, "              ") {
			t.Errorf("fix line %d is not indented: %q — a flush-left fix reads as another "+
				"check, and a copy would take the wrong lines", i, ligne)
		}
	}
}

// TestFiltrerAbsentsGardeLInconnu: without a cluster every state is Unknown,
// and the list must not become empty.
func TestFiltrerAbsentsGardeLInconnu(t *testing.T) {
	hotess := []hoteDNS{
		{Hote: "mail.example.org", Declare: "mail"},
		{Hote: "office.example.org", Declare: "office"},
	}
	etats := map[string]module.State{
		"mail":   {Status: module.Unknown},
		"office": {Status: module.Unknown},
	}
	if got := filtrerAbsents(hotess, etats); len(got) != 2 {
		t.Errorf("%d hosts kept, expected 2: an unreadable cluster must not turn the "+
			"check into an empty, reassuring list", len(got))
	}
}

// TestFiltrerAbsentsRetireLAbsent: a host of an uninstalled module is skipped.
func TestFiltrerAbsentsRetireLAbsent(t *testing.T) {
	hotess := []hoteDNS{
		{Hote: "mail.example.org", Declare: "mail"},
		{Hote: "office.example.org", Declare: "office"},
	}
	etats := map[string]module.State{
		"mail":   {Status: module.Installed},
		"office": {Status: module.Absent},
	}
	got := filtrerAbsents(hotess, etats)
	if len(got) != 1 || got[0].Hote != "mail.example.org" {
		t.Errorf("filtered hosts = %v, expected only mail.example.org: a record is not "+
			"missing for a module the operator never installed", got)
	}
	// A removal in progress counts as absent: the module is on its way out, and
	// asking for its record while it goes would race the operator.
	got = filtrerAbsents(hotess, map[string]module.State{"mail": {Status: module.Installed},
		"office": {Status: module.Removing}})
	if len(got) != 1 {
		t.Errorf("%d hosts kept during a removal, expected 1", len(got))
	}
}
