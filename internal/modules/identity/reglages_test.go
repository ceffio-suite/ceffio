// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestLeGroupeDeConnexionEstDeclare : two fields, both closed lists, both required.
//
// A FREE-TEXT THEME NAME IS THE TRAP THIS AVOIDS: it accepts a typo, the realm then
// points at a theme that does not exist, and Keycloak answers by silently serving its
// default. The operator saves "ceffio_" and sees no change, with nothing to read.
func TestLeGroupeDeConnexionEstDeclare(t *testing.T) {
	m := &identityModule{}
	groupes := m.Settings()
	if len(groupes) != 1 {
		t.Fatalf("%d group(s), expected exactly one", len(groupes))
	}
	g := groupes[0]
	if g.ID != "login_page" {
		t.Errorf("group ID = %q, expected login_page: it appears in the console route "+
			"and the storage path, so it must be stable", g.ID)
	}

	champs := map[string]module.Field{}
	for _, f := range g.Fields {
		champs[f.Key] = f
	}
	for _, cle := range []string{"theme", "default_locale"} {
		f, ok := champs[cle]
		if !ok {
			t.Errorf("%s is not declared", cle)
			continue
		}
		if f.Type != module.Choice {
			t.Errorf("%s is a %s, expected a Choice: a free-text value accepts a typo "+
				"and Keycloak silently ignores an unknown theme", cle, f.Type)
		}
		if !f.Required {
			t.Errorf("%s is not Required", cle)
		}
		if len(f.Options) < 2 {
			t.Errorf("%s offers %d option(s), expected at least the Ceffio one and the "+
				"way back", cle, len(f.Options))
		}
	}

	// THE WAY BACK MUST EXIST: "keycloak.v2" is how an operator tells a theming
	// problem from a sign-in problem.
	var retour bool
	for _, o := range champs["theme"].Options {
		if o.Value == "keycloak.v2" {
			retour = true
		}
	}
	if !retour {
		t.Error("no way back to Keycloak's default theme: without it an operator " +
			"cannot tell whether a broken sign-in page comes from the theme or from " +
			"the flow")
	}
}

// TestAppliquerRefuseUnThemeInvente : the API is reachable by any administrator, so
// the value is validated against the DECLARATION rather than trusted.
func TestAppliquerRefuseUnThemeInvente(t *testing.T) {
	m := &identityModule{}
	err := m.Apply(context.Background(), module.Env{}, "login_page",
		module.Values{"theme": "ceffio_", "default_locale": "fr"})
	if err == nil {
		t.Fatal("an invented theme was accepted: the realm would point at a theme that " +
			"does not exist, and Keycloak serves its default silently")
	}
	if !strings.Contains(err.Error(), "ceffio_") {
		t.Errorf("the error does not name the rejected value: %v", err)
	}

	err = m.Apply(context.Background(), module.Env{}, "login_page",
		module.Values{"theme": "ceffio", "default_locale": "de"})
	if err == nil {
		t.Fatal("an unsupported locale was accepted: Keycloak would ignore it and " +
			"serve its own default")
	}
}

// TestAppliquerRefuseUnGroupeInconnu : a group the module does not declare is a
// programming error, not an empty success.
func TestAppliquerRefuseUnGroupeInconnu(t *testing.T) {
	m := &identityModule{}
	if err := m.Apply(context.Background(), module.Env{}, "nope", nil); err == nil {
		t.Error("an unknown group was accepted")
	}
	if _, err := m.Current(context.Background(), module.Env{}, "nope"); err == nil {
		t.Error("an unknown group was read")
	}
}

// TestLeTestNeMentPas : the console shows a "test" button for groups that can be
// tested. A bare success would teach the operator that the button means nothing —
// there is nothing to probe here, and saying so is the honest answer.
func TestLeTestNeMentPas(t *testing.T) {
	m := &identityModule{}
	r := m.Test(context.Background(), module.Env{}, "login_page", module.Values{})
	if !r.OK {
		t.Error("the test failed on a group that cannot fail")
	}
	if r.Detail == "" {
		t.Error("the test says nothing: the operator is left wondering whether it ran")
	}
	if !strings.Contains(strings.ToLower(r.Detail), "nothing to test") {
		t.Errorf("the test claims to have verified something it cannot verify: %q",
			r.Detail)
	}
}

// TestLesChampsDuGroupeSontCoherents : the declaration must survive the contract's
// own verification, which runs at registration.
func TestLesChampsDuGroupeSontCoherents(t *testing.T) {
	for _, g := range (&identityModule{}).Settings() {
		// The contract's verifier is what registration runs; calling it here turns a
		// startup crash into a test failure that names the group.
		if err := module.VerifierGroupesPourTest("identity", []module.Group{g}); err != nil {
			t.Errorf("group %s is incoherent: %v", g.ID, err)
		}
	}
}
