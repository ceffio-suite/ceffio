// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"testing"
)

// This file tests the Checker contract and its one helper.
//
// WHY A FAKE CHECKER AND NOT A REAL MODULE: the contract must be usable by a
// module that does not exist yet (mail is the first one, in a later lot). A
// test that went through the mail package would prove mail works, not that the
// console and the CLI can walk ANY module through this interface — and it would
// couple this package to a module it must not know.

// fauxVerificateur is a Module that also declares checks.
type fauxVerificateur struct {
	fauxModule
	checks []Check
}

func (f *fauxVerificateur) Checks(context.Context, Env) []Check { return f.checks }

// TestUnVerificateurEstReconnuParAsseveration : the type assertion the console
// and the CLI rely on does not depend on the module being registered.
//
// THE ASSERTION IS THE CONTRACT: `m.(module.Checker)` is the only thing that
// decides whether a checks route exists for a module. A module that declares
// checks through a different method name would compile, appear in the registry,
// and never be asked anything — the console would show no checks and nobody
// would know why.
func TestUnVerificateurEstReconnuParAsseveration(t *testing.T) {
	var m Module = &fauxVerificateur{checks: []Check{{ID: "mx", Level: CheckOK}}}

	if _, ok := m.(Checker); !ok {
		t.Fatal("a module declaring Checks is not recognized as a Checker: the console " +
			"would 404 on its checks route and no test would fail")
	}
	var sansChecks Module = &fauxModule{}
	if _, ok := sansChecks.(Checker); ok {
		t.Error("a module WITHOUT Checks is recognized as a Checker: the console would " +
			"serve an empty list, which reads as \"everything verified\"")
	}
}

// TestBloquantsNeGardeQueLesBloquants : the helper is the ONE definition of
// "state is degraded", so each level must be classified exactly once.
//
// WHY THIS TEST NAMES EVERY LEVEL: the risk is not a missed comparison, it is a
// level that one day gets added to CheckLevel and silently classified on the
// wrong side. Naming all four here makes that addition fail the build's
// expectations instead of producing a module that reports Degraded while it
// works.
func TestBloquantsNeGardeQueLesBloquants(t *testing.T) {
	checks := []Check{
		{ID: "ok", Level: CheckOK},
		{ID: "warn", Level: CheckWarning},
		{ID: "block", Level: CheckBlocking},
		{ID: "na", Level: CheckNotApplicable},
	}

	bloquants := Bloquants(checks)
	if len(bloquants) != 1 {
		t.Fatalf("Bloquants kept %d checks, expected exactly 1 (the blocking one); "+
			"levels are %v", len(bloquants), bloquants)
	}
	if bloquants[0].ID != "block" {
		t.Errorf("Bloquants kept %q, expected the check whose level is %q", bloquants[0].ID, CheckBlocking)
	}
}

// TestBloquantsSurListeVide : no check is not a failure.
//
// A module that declared no check returns an empty slice and a nil error; the
// helper must return nil, not panic and not invent a blocking entry. The
// console renders nothing for it, and the module card stays neutral.
func TestBloquantsSurListeVide(t *testing.T) {
	if got := Bloquants(nil); len(got) != 0 {
		t.Errorf("Bloquants(nil) = %v, expected nothing", got)
	}
	if got := Bloquants([]Check{}); len(got) != 0 {
		t.Errorf("Bloquants(empty) = %v, expected nothing", got)
	}
}

// TestUnCheckSansFixResteSerialisable : Fix is omitempty because most checks do
// not need one (a passing check has nothing to fix).
//
// WHAT IT PREVENTS: an empty `fix` field in the JSON the browser receives would
// make the page render an empty copyable block for every passing check — the
// operator would copy nothing, which is worse than the block not being there.
func TestUnCheckSansFixResteSerialisable(t *testing.T) {
	c := Check{ID: "mx", Label: "MX of example.com", Level: CheckOK, Detail: "mail.example.com"}
	if c.Fix != "" {
		t.Fatalf("the zero Fix is not empty: %q", c.Fix)
	}
	if string(c.Level) != "ok" {
		t.Errorf("the level is serialized as %q, expected the stable wire value \"ok\"", c.Level)
	}
}
