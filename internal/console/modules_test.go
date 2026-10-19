// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests for the generic module API (batch B5).
//
// WHAT EACH TEST REFUSES — the rule it would catch broken:
//
//   - TestModulesListSansPermissions: a browser-facing listing that leaks
//     the cluster RBAC rules (Info.Permissions) or forgets State/Blocked.
//   - TestModuleAction202Puis409: a synchronous handler (proxy cut on a
//     minutes-long install), or two operations running on one module.
//   - TestModuleCoreUninstall403: the console uninstalling a Core module,
//     i.e. taking the product apart under the operator.
//   - TestStatusInclutMailVaultExapps: the regression this batch fixes —
//     pods of ceffio-mail, ceffio-vault and ceffio-exapps were invisible
//     because the namespace list was hand-written.
//
// The registry seam is the package variable moduleAll: each test swaps it
// for a fake list and restores it afterwards (no t.Parallel here — the
// variable is process-wide).
package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// fakeModule is a controllable module.Module: canned Info/State, and an
// Install that can be held open on a channel to observe the 409 window.
type fakeModule struct {
	info     module.Info
	state    module.State
	release  chan struct{} // Install blocks until closed (nil = immediate)
	started  chan struct{} // closed when Install begins (nil = not observed)
	installN int
}

func (f *fakeModule) Info() module.Info { return f.info }
func (f *fakeModule) State(context.Context, module.Env) module.State {
	return f.state
}
func (f *fakeModule) Install(ctx context.Context, env module.Env) error {
	f.installN++
	if f.started != nil {
		close(f.started)
	}
	if f.release != nil {
		<-f.release
	}
	if env.Out != nil {
		fmt.Fprintln(env.Out, "fake install wrote to the journal")
	}
	return nil
}
func (f *fakeModule) Uninstall(ctx context.Context, env module.Env) error {
	if env.Out != nil {
		fmt.Fprintln(env.Out, "fake uninstall wrote to the journal")
	}
	return nil
}

// withFakeRegistry swaps moduleAll for the given modules and restores it.
func withFakeRegistry(t *testing.T, mods ...module.Module) {
	t.Helper()
	prev := moduleAll
	moduleAll = func() []module.Module { return mods }
	t.Cleanup(func() { moduleAll = prev })
}

// newTestServer builds an authenticated Server over a fake clientset.
func newTestServer(cs *fake.Clientset) *Server {
	return &Server{
		Domain: "ceffio.example.com",
		APIKey: "test-key",
		kube:   cs,
		ops:    newOpsManager(),
	}
}

func doReq(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestModulesListSansPermissions refuses a listing that leaks the RBAC
// rules or omits the observed state and the blocking reason.
func TestModulesListSansPermissions(t *testing.T) {
	mod := &fakeModule{
		info: module.Info{
			ID:          "opt-mod",
			Title:       "Optional module",
			Description: "does things",
			Kind:        module.Optional,
			Namespaces:  []string{"ceffio-opt"},
			Resources:   "~1 GB",
			Warning:     "careful",
			Permissions: []module.Permission{{Namespace: "ceffio-opt"}},
		},
		state: module.State{Status: module.Absent},
	}
	// "child" requires an ID absent from the REAL global registry, so
	// module.Blocked must report it: the listing has to carry the reason,
	// not make the browser recompute dependencies.
	child := &fakeModule{
		info: module.Info{ID: "child", Title: "Child", Kind: module.Optional,
			Requires: []string{"not-registered-anywhere"}},
	}
	withFakeRegistry(t, mod, child)

	rec := doReq(t, newTestServer(fake.NewSimpleClientset()).Handler(),
		http.MethodGet, "/api/modules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/modules -> %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "permissions") {
		t.Error("the listing exposes Permissions: the RBAC rules are an installer concern, not browser display data")
	}

	var out struct {
		Modules []map[string]any `json:"modules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable JSON: %v", err)
	}
	if len(out.Modules) != 2 {
		t.Fatalf("%d modules in the listing, want 2", len(out.Modules))
	}
	first := out.Modules[0]
	if first["kind"] != "optional" || first["title"] != "Optional module" {
		t.Errorf("Info not carried through the listing: %v", first)
	}
	state, ok := first["state"].(map[string]any)
	if !ok || state["status"] != "absent" {
		t.Errorf("state missing or wrong: %v", first["state"])
	}
	if _, ok := first["blocked"]; ok {
		t.Errorf("absent module reported a blocking reason: %v", first["blocked"])
	}
	if got := out.Modules[1]["blocked"]; got == "" || !strings.Contains(fmt.Sprint(got), "not-registered-anywhere") {
		t.Errorf("blocked reason missing for the unsatisfied dependency: %v", got)
	}
}

// TestModuleAction202Puis409 refuses a synchronous handler and a second
// concurrent operation on the same module.
func TestModuleAction202Puis409(t *testing.T) {
	mod := &fakeModule{
		info:    module.Info{ID: "slow-mod", Title: "Slow", Kind: module.Optional},
		state:   module.State{Status: module.Absent},
		release: make(chan struct{}),
		started: make(chan struct{}),
	}
	withFakeRegistry(t, mod)
	s := newTestServer(fake.NewSimpleClientset())
	h := s.Handler()

	rec := doReq(t, h, http.MethodPost, "/api/modules/slow-mod", `{"action":"install"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first POST -> %d, want 202: a synchronous handler would hold the request for minutes and the ingress proxy would cut it", rec.Code)
	}

	select {
	case <-mod.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the operation never started")
	}

	// While it runs, the module must refuse a second operation.
	rec2 := doReq(t, h, http.MethodPost, "/api/modules/slow-mod", `{"action":"install"}`)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second POST during the operation -> %d, want 409: two concurrent installs would interleave their Kubernetes writes", rec2.Code)
	}

	// State must read "installing" while the operation runs, WITHOUT
	// touching the cluster.
	recState := doReq(t, h, http.MethodGet, "/api/modules/slow-mod", "")
	if !strings.Contains(recState.Body.String(), `"installing"`) {
		t.Errorf("state during the operation is not installing: %s", recState.Body.String())
	}

	close(mod.release)

	// The journal (last operation) is exposed by GET /api/modules/{id}.
	deadline := time.Now().Add(5 * time.Second)
	var detail map[string]any
	for {
		recD := doReq(t, h, http.MethodGet, "/api/modules/slow-mod", "")
		_ = json.Unmarshal(recD.Body.Bytes(), &detail)
		op, _ := detail["operation"].(map[string]any)
		if op != nil && op["running"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation never finished; last detail: %s", recD.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	op := detail["operation"].(map[string]any)
	if op["success"] != true {
		t.Errorf("finished operation not successful: %v", op)
	}
	journal, _ := op["journal"].([]any)
	found := false
	for _, l := range journal {
		if strings.Contains(fmt.Sprint(l), "fake install wrote to the journal") {
			found = true
		}
	}
	if !found {
		t.Errorf("env.Out was not routed into the journal: %v", journal)
	}
}

// TestModuleCoreUninstall403 refuses uninstalling a Core module from the
// console: Core IS the product.
func TestModuleCoreUninstall403(t *testing.T) {
	core := &fakeModule{info: module.Info{ID: "core-mod", Title: "Core", Kind: module.Core}}
	opt := &fakeModule{info: module.Info{ID: "opt-mod", Title: "Opt", Kind: module.Optional}}
	withFakeRegistry(t, core, opt)
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	rec := doReq(t, h, http.MethodPost, "/api/modules/core-mod", `{"action":"uninstall"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("uninstall of a Core module -> %d, want 403", rec.Code)
	}
	// The refusal must not depend on the page: the same rule applies to a
	// direct API call. Conversely, Optional modules are NOT refused here
	// (they may still hit 409/404 rules — anything but 403).
	rec2 := doReq(t, h, http.MethodPost, "/api/modules/opt-mod", `{"action":"uninstall"}`)
	if rec2.Code == http.StatusForbidden {
		t.Errorf("uninstall of an Optional module refused with 403")
	}
}

// TestModuleActionInconnu400 / unknown module 404: cheap contract checks.
func TestModuleActionInconnu(t *testing.T) {
	mod := &fakeModule{info: module.Info{ID: "opt-mod", Title: "Opt", Kind: module.Optional}}
	withFakeRegistry(t, mod)
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	if rec := doReq(t, h, http.MethodPost, "/api/modules/opt-mod", `{"action":"reboot"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action -> %d, want 400", rec.Code)
	}
	if rec := doReq(t, h, http.MethodPost, "/api/modules/nope", `{"action":"install"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown module -> %d, want 404", rec.Code)
	}
	// Without the token, the middleware must refuse before the registry is
	// even consulted.
	r := httptest.NewRequest(http.MethodGet, "/api/modules", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/modules -> %d, want 401", w.Code)
	}
}

// pod builds a ready pod in a namespace, as the status page counts them.
func pod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name + "-7d9f8c6b5-abcde"},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Ready: true}},
		},
	}
}

// TestStatusInclutMailVaultExapps refuses the regression this batch fixes:
// with the hand-written namespace list ("data, identity, files, office,
// video, system"), the pods of ceffio-mail, ceffio-vault and ceffio-exapps
// never appeared in /api/status — a mail server outage was invisible on the
// dashboard.
func TestStatusInclutMailVaultExapps(t *testing.T) {
	mail := &fakeModule{info: module.Info{ID: "mail", Kind: module.Core, Namespaces: []string{"ceffio-mail"}}}
	vault := &fakeModule{info: module.Info{ID: "vault", Kind: module.Core, Namespaces: []string{"ceffio-vault"}}}
	exapps := &fakeModule{info: module.Info{ID: "exapps-daemon", Kind: module.Optional, Namespaces: []string{"ceffio-exapps"}}}
	files := &fakeModule{info: module.Info{ID: "files", Kind: module.Core, Namespaces: []string{"ceffio-files"},
		Services: []module.Service{{Sub: "cloud", Name: "Nextcloud", Role: "Files", SSO: true,
			PodPrefixes: []string{"nextcloud"}}}}}
	withFakeRegistry(t, files, mail, vault, exapps)

	cs := fake.NewSimpleClientset(
		pod("ceffio-mail", "stalwart"),
		pod("ceffio-vault", "openbao-0"),
		pod("ceffio-exapps", "harp"),
		pod("ceffio-files", "nextcloud"),
	)
	s := newTestServer(cs)

	rec := doReq(t, s.Handler(), http.MethodGet, "/api/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/status -> %d (body: %s)", rec.Code, rec.Body.String())
	}

	var out struct {
		Stack []struct {
			Name  string `json:"name"`
			Total int    `json:"total"`
			Ready int    `json:"ready"`
		} `json:"stack"`
		Services  []ServicePublic `json:"services"`
		PodsTotal int             `json:"podsTotal"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unreadable JSON: %v", err)
	}

	// The three previously invisible namespaces must be listed AND counted.
	parNS := map[string]int{}
	for _, l := range out.Stack {
		parNS[l.Name] = l.Total
	}
	for _, ns := range []string{"ceffio-mail", "ceffio-vault", "ceffio-exapps"} {
		if parNS[ns] != 1 {
			t.Errorf("namespace %s: %d pods in the stack layer, want 1 — the hand-written list made it invisible", ns, parNS[ns])
		}
	}
	if out.PodsTotal != 4 {
		t.Errorf("podsTotal = %d, want 4 (mail, vault, exapps and files pods)", out.PodsTotal)
	}

	// The service catalogue comes from the registry too: module.Service.SSO
	// must land in ServicePublic.SSO.
	if len(out.Services) != 1 || out.Services[0].Nom != "Nextcloud" || !out.Services[0].SSO {
		t.Errorf("registry-built catalogue wrong: %+v", out.Services)
	}
	if out.Services[0].Sante != "ok" || out.Services[0].PodsReady != 1 {
		t.Errorf("Nextcloud health not computed from its pods: %+v", out.Services[0])
	}
}
