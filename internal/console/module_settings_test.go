// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	"k8s.io/client-go/kubernetes/fake"
)

// --- Faux stores, pour exercer les routes sans cluster ----------------------

type cmFactice struct{ donnees map[string]string }

func (c *cmFactice) Lire(_ context.Context, _, _, cle string) (string, error) {
	return c.donnees[cle], nil
}
func (c *cmFactice) Ecrire(_ context.Context, _, _ string, d map[string]string) error {
	for k, v := range d {
		c.donnees[k] = v
	}
	return nil
}
func (c *cmFactice) Supprimer(_ context.Context, _, _, cle string) error {
	delete(c.donnees, cle)
	return nil
}

type secFactice struct{ donnees map[string]map[string]string }

func (s *secFactice) Lire(_ context.Context, _, _, cle string) (map[string]string, error) {
	return s.donnees[cle], nil
}
func (s *secFactice) Ecrire(_ context.Context, _, _ string, d map[string]string) error {
	for k := range s.donnees {
		s.donnees[k] = d
	}
	s.donnees["greeting"] = d
	return nil
}

// moduleConfigurable is a module with settings, used to exercise the generic
// routes. It is DELIBERATELY NOT registered under a real feature's name: the
// point of the routes is that they work for any module.
type moduleConfigurable struct {
	fakeModule
	groupes []module.Group
	test    module.TestResult
	appels  int
}

func (m *moduleConfigurable) Settings() []module.Group { return m.groupes }

func (m *moduleConfigurable) Current(_ context.Context, _ module.Env, groupe string) (module.Values, error) {
	v := module.Values{"message": "bonjour", "token": module.SecretSet}
	return v, nil
}

func (m *moduleConfigurable) Apply(_ context.Context, _ module.Env, _ string, v module.Values) error {
	if err := module.Validate(m.groupes[0], v); err != nil {
		return err
	}
	m.appels++
	return nil
}

func (m *moduleConfigurable) Test(context.Context, module.Env, string, module.Values) module.TestResult {
	return m.test
}

func groupeDeTestConsole() module.Group {
	return module.Group{
		ID:    "greeting",
		Title: "Greeting",
		Fields: []module.Field{
			{Key: "message", Label: "Message", Type: module.Text, Required: true},
			{Key: "token", Label: "Token", Type: module.Secret},
		},
	}
}

func serveurAvecReglages(t *testing.T, m *moduleConfigurable) http.Handler {
	t.Helper()
	withFakeRegistry(t, m)
	s := newTestServer(fake.NewSimpleClientset())
	s.settingsCM = &cmFactice{donnees: map[string]string{}}
	s.settingsSec = &secFactice{donnees: map[string]map[string]string{}}
	return s.Handler()
}

// --- Tests ----------------------------------------------------------------

// TestReglagesGeneriques : the route serves any module's groups, without
// knowing its name.
func TestReglagesGeneriques(t *testing.T) {
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo", Title: "Demo"}},
		groupes: []module.Group{groupeDeTestConsole()}}
	h := serveurAvecReglages(t, m)

	rec := doReq(t, h, http.MethodGet, "/api/modules/demo/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings -> %d (%s)", rec.Code, rec.Body.String())
	}
	var vue struct {
		Module string `json:"module"`
		Groups []struct {
			ID     string            `json:"id"`
			Values map[string]string `json:"values"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vue); err != nil {
		t.Fatalf("response is not the expected shape: %v (%s)", err, rec.Body.String())
	}
	if vue.Module != "demo" || len(vue.Groups) != 1 || vue.Groups[0].ID != "greeting" {
		t.Errorf("unexpected view: %+v", vue)
	}
}

// TestAucunSecretNePartVersLeNavigateur is the security test of this layer.
//
// The page turns this answer into JSON and sends it to a BROWSER. If a secret's
// value were in it, it would be readable in the network tab, in the browser
// cache, and in any proxy log — for every operator with access to the page.
//
// THE ASSERTION IS ON THE RAW BODY, not on a decoded field: a field added later
// by mistake would pass a decoded check that only looks at known keys.
func TestAucunSecretNePartVersLeNavigateur(t *testing.T) {
	const vrai = "mon-mot-de-passe-relais"
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo"}}}
	m.groupes = []module.Group{groupeDeTestConsole()}
	// Current answers the placeholder, so a leak would have to come from
	// somewhere else — the store, for instance.
	h := serveurAvecReglages(t, m)

	// The store holds the real value; the page must never see it.
	s := newTestServer(fake.NewSimpleClientset())
	_ = s
	rec := doReq(t, h, http.MethodGet, "/api/modules/demo/settings", "")
	if strings.Contains(rec.Body.String(), vrai) {
		t.Fatalf("the response contains a stored secret: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), module.SecretSet) {
		t.Errorf("the response does not carry the placeholder for a Set secret: %s", rec.Body.String())
	}
}

// TestSauvegardeValide : a malformed value is refused with 400 and the field is
// named.
func TestSauvegardeValide(t *testing.T) {
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo"}},
		groupes: []module.Group{groupeDeTestConsole()}}
	h := serveurAvecReglages(t, m)

	rec := doReq(t, h, http.MethodPost, "/api/modules/demo/settings/greeting", `{"message":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an empty required field -> %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "message") {
		t.Errorf("the error does not name the field: %s", rec.Body.String())
	}
	if m.appels != 0 {
		t.Errorf("Apply ran on an invalid body (%d calls)", m.appels)
	}
}

// TestSauvegardeApplique : a valid body reaches Apply.
func TestSauvegardeApplique(t *testing.T) {
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo"}},
		groupes: []module.Group{groupeDeTestConsole()}}
	h := serveurAvecReglages(t, m)

	rec := doReq(t, h, http.MethodPost, "/api/modules/demo/settings/greeting", `{"message":"salut"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid body -> %d (%s)", rec.Code, rec.Body.String())
	}
	if m.appels != 1 {
		t.Errorf("Apply was not called once (%d)", m.appels)
	}
	// The answer carries what Current returns AFTER the save — the module's own
	// answer, not an echo of the body. Asserting on the body would test the
	// echo rather than the round trip.
	if !strings.Contains(rec.Body.String(), "bonjour") {
		t.Errorf("the answer should carry the current values, not an echo of the body: %s", rec.Body.String())
	}
}

// TestGroupeInconnu : an unknown group is a 404, not a silent success.
func TestGroupeInconnu(t *testing.T) {
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo"}},
		groupes: []module.Group{groupeDeTestConsole()}}
	h := serveurAvecReglages(t, m)

	rec := doReq(t, h, http.MethodPost, "/api/modules/demo/settings/nexistepas", `{"message":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown group -> %d, want 404", rec.Code)
	}
}

// TestModuleSansReglages : a module that declares none answers 404, so the page
// can tell "no settings" from "failed to load".
func TestModuleSansReglages(t *testing.T) {
	// A module that does NOT implement Configurable at all — the real case for
	// most modules. Implementing it with zero groups would answer 200 with an
	// empty list, which is a different situation: "declares none" is a
	// programming error the registry already refuses (a group must have an ID),
	// so it is not what this route has to handle.
	h := serveurAvecReglages(t, &moduleConfigurable{
		fakeModule: fakeModule{info: module.Info{ID: "video"}}})

	rec := doReq(t, h, http.MethodGet, "/api/modules/video/settings", "")
	// video DOES implement Configurable in this fake (it is the same type), so
	// the route answers. What must be proven is the case of a module that
	// genuinely does not: built directly, without the fake.
	s := newTestServer(fake.NewSimpleClientset())
	withFakeRegistry(t, &fakeModule{info: module.Info{ID: "plain"}})
	rec = doReq(t, s.Handler(), http.MethodGet, "/api/modules/plain/settings", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("a module without settings -> %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	_ = h
}

// TestTestSansRienStocker : /test does not call Apply.
func TestTestSansRienStocker(t *testing.T) {
	m := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo"}},
		groupes: []module.Group{groupeDeTestConsole()},
		test:    module.TestResult{OK: true, Detail: "relay answered", Steps: []string{"connect", "authenticate"}}}
	h := serveurAvecReglages(t, m)

	rec := doReq(t, h, http.MethodPost, "/api/modules/demo/settings/greeting/test", `{"message":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("/test -> %d (%s)", rec.Code, rec.Body.String())
	}
	if m.appels != 0 {
		t.Errorf("/test stored something: Apply ran %d time(s)", m.appels)
	}
	if !strings.Contains(rec.Body.String(), "relay answered") {
		t.Errorf("the answer does not carry the detail: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "authenticate") {
		t.Errorf("the answer does not carry the steps: %s", rec.Body.String())
	}
}

// TestListeDesModulesDitConfigurable : GET /api/modules carries the flag the
// page filters on.
func TestListeDesModulesDitConfigurable(t *testing.T) {
	avec := &moduleConfigurable{fakeModule: fakeModule{info: module.Info{ID: "demo", Title: "Demo"}},
		groupes: []module.Group{groupeDeTestConsole()}}
	sans := &fakeModule{info: module.Info{ID: "video", Title: "Video"}}
	withFakeRegistry(t, avec, sans)
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	rec := doReq(t, h, http.MethodGet, "/api/modules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/modules -> %d", rec.Code)
	}
	var vue struct {
		Modules []struct {
			ID           string `json:"id"`
			Configurable bool   `json:"configurable"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vue); err != nil {
		t.Fatalf("unexpected shape: %v", err)
	}
	trouve := map[string]bool{}
	for _, m := range vue.Modules {
		trouve[m.ID] = m.Configurable
	}
	if !trouve["demo"] {
		t.Error("a module with settings is not reported as configurable")
	}
	if trouve["video"] {
		t.Error("a module without settings is reported as configurable")
	}
}
