// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests for GET /api/modules/{id}/checks (the module.Checker route).
//
// WHAT EACH TEST REFUSES — the rule it would catch broken:
//
//   - TestLesChecksSontServisSansNomDeModule: a handler that knows the module
//     names, or that drops the level/Detail/Fix the page displays. The route is
//     the only thing between a future module and the page; if it special-cases
//     one, the next module silently gets nothing.
//   - TestUnModuleSansChecksRepond404: a module that declares no check being
//     served an EMPTY LIST, which the page would read as "everything verified".
//   - TestLeDrapeauCheckableSuitLInterface: the page deciding on its own which
//     modules to ask. It cannot ask "does this implement an interface?", so the
//     flag must come from the registry.
//   - TestLesChecksRecoiventUnEnvComplet: checks measuring an external
//     prerequisite need the domain and the cluster client; a nil Env would
//     panic in a goroutine on the first real check instead of here.
package console

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// moduleVerifie is a module that declares checks and records the Env it got.
type moduleVerifie struct {
	fakeModule
	recu   *module.Env
	checks []module.Check
}

func (m *moduleVerifie) Checks(_ context.Context, env module.Env) []module.Check {
	if m.recu != nil {
		*m.recu = env
	}
	return m.checks
}

// TestLesChecksSontServisSansNomDeModule: the handler serves ANY module's
// checks, keeps every field of the contract, and answers an empty list as [].
func TestLesChecksSontServisSansNomDeModule(t *testing.T) {
	mod := &moduleVerifie{
		fakeModule: fakeModule{info: module.Info{ID: "verif-mod", Title: "Verified",
			Kind: module.Optional}},
		checks: []module.Check{
			{ID: "mx", Label: "MX record", Level: module.CheckOK, Detail: "mail.example.com"},
			{ID: "ptr", Label: "Reverse DNS", Level: module.CheckWarning,
				Detail: "no PTR", Fix: "example.com. IN PTR mail.example.com."},
			{ID: "relay", Label: "Relay", Level: module.CheckNotApplicable,
				Detail: "direct mode"},
			{ID: "tls", Label: "Certificate", Level: module.CheckBlocking,
				Detail: "self-signed", Fix: "ceffio module install verif-mod"},
		},
	}
	avec := &moduleVerifie{fakeModule: fakeModule{info: module.Info{ID: "sans-check",
		Title: "No checks", Kind: module.Optional}}}
	withFakeRegistry(t, mod, avec)

	rec := doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules/verif-mod/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET checks -> %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var out struct {
		Module string         `json:"module"`
		Checks []module.Check `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable JSON: %v", err)
	}
	if out.Module != "verif-mod" {
		t.Errorf("module = %q, expected the one asked for", out.Module)
	}
	if len(out.Checks) != 4 {
		t.Fatalf("%d checks served, want 4", len(out.Checks))
	}
	// Every level goes through verbatim: the page maps them to a symbol, and a
	// level the API renamed would render every check as "ok" or as nothing.
	attendus := map[string]module.CheckLevel{
		"mx": module.CheckOK, "ptr": module.CheckWarning,
		"relay": module.CheckNotApplicable, "tls": module.CheckBlocking,
	}
	for _, c := range out.Checks {
		if attendus[c.ID] != c.Level {
			t.Errorf("check %q has level %q, expected %q", c.ID, c.Level, attendus[c.ID])
		}
	}
	// Detail and Fix are different: the page shows the first as text and the
	// second in a copyable block. A handler that merged them would offer a fix
	// containing the observation.
	for _, c := range out.Checks {
		if c.ID == "ptr" {
			if c.Detail != "no PTR" || !strings.Contains(c.Fix, "PTR") {
				t.Errorf("ptr check lost its Detail/Fix split: %+v", c)
			}
		}
	}

	// A module that returns no check must answer with an empty array, not null.
	rec = doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules/sans-check/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET checks of a Checker with no check -> %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"checks":[]`) {
		t.Errorf("an empty check list is served as %s, expected an empty array: null makes "+
			"the page guard for a value instead of rendering nothing", body)
	}
}

// TestUnModuleSansChecksRepond404: 404, not an empty list.
func TestUnModuleSansChecksRepond404(t *testing.T) {
	mod := &fakeModule{info: module.Info{ID: "no-check", Title: "No", Kind: module.Optional}}
	withFakeRegistry(t, mod)

	rec := doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules/no-check/checks", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET checks of a module without checks -> %d, want 404 (body: %s); "+
			"an empty list reads as \"everything verified\"", rec.Code, rec.Body.String())
	}

	rec = doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules/inconnu/checks", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET checks of an unknown module -> %d, want 404", rec.Code)
	}
}

// TestLeDrapeauCheckableSuitLInterface: the module view tells the page which
// cards carry checks, resolved from the same registry.
func TestLeDrapeauCheckableSuitLInterface(t *testing.T) {
	oui := &moduleVerifie{fakeModule: fakeModule{info: module.Info{ID: "avec", Title: "Avec"}}}
	non := &fakeModule{info: module.Info{ID: "sans", Title: "Sans"}}
	withFakeRegistry(t, oui, non)

	rec := doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/modules -> %d, want 200", rec.Code)
	}
	var out struct {
		Modules []map[string]any `json:"modules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable JSON: %v", err)
	}
	if len(out.Modules) != 2 {
		t.Fatalf("%d modules listed, want 2", len(out.Modules))
	}
	// The registry order is the fake order; read by id rather than by position
	// so the assertion does not depend on it.
	for _, m := range out.Modules {
		checkable, _ := m["checkable"].(bool)
		voulu := m["id"] == "avec"
		if checkable != voulu {
			t.Errorf("module %v has checkable=%v, expected %v: the page asks for checks "+
				"based on this flag alone", m["id"], checkable, voulu)
		}
	}
}

// TestLesChecksRecoiventUnEnvComplet: the same Env contract as Install, minus
// the journal, plus the module id.
func TestLesChecksRecoiventUnEnvComplet(t *testing.T) {
	cs := fake.NewSimpleClientset()
	s := newTestServer(cs)
	cm := &cmFactice{donnees: map[string]string{}}
	sec := &secFactice{donnees: map[string]map[string]string{}}
	s.settingsCM, s.settingsSec = cm, sec

	var recu module.Env
	mod := &moduleVerifie{
		fakeModule: fakeModule{info: module.Info{ID: "env-mod", Title: "Env"}},
		recu:       &recu,
	}
	withFakeRegistry(t, mod)

	rec := doReq(t, s.Handler(), http.MethodGet, "/api/modules/env-mod/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET checks -> %d, want 200", rec.Code)
	}
	if recu.Domain != s.Domain {
		t.Errorf("Domain = %q, expected %q", recu.Domain, s.Domain)
	}
	if recu.Kube != cs {
		t.Error("Kube is not the server's client: a check reading the cluster would panic")
	}
	if recu.ModuleID != "env-mod" {
		t.Errorf("ModuleID = %q, expected the module being checked", recu.ModuleID)
	}
	if recu.Settings == nil || recu.Secrets == nil {
		t.Error("Settings or Secrets is nil: a check reading a setting would panic")
	}
	// Out is a discard: a read must not write to the operation journal, which
	// exists to show what an install did.
	if recu.Out == nil {
		t.Error("Out is nil: a check that logs its progress would panic")
	}
}
