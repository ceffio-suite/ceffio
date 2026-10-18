//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// INTEGRATION TEST OF THE MODULARISATION PLAN — the executable proof of the
// claim: "adding a feature to Ceffio means writing a Go package that
// implements module.Module; the installer, the CLI and the console do not
// change."
//
// WHY IT BUILDS REAL BINARIES instead of only walking module.All()
// in-process: this test file lives in the demo package's external test
// package, so the demo package is LINKED into the test binary no matter
// what — its init() registers the module even if internal/modules/
// all_demo.go lost its blank import. An in-process registry check would
// therefore PASS on a broken wiring. Compiling ./cmd/ceffio exactly like
// production does removes the blind spot: the tagged binary sees demo ONLY
// through the import chain cmd/ceffio → internal/modules → all_demo.go →
// demo, so deleting that one line makes the CLI assertions fail; and the
// UNTAGGED binary must NOT see demo at all (build-tag guarantee).
//
// WHAT IS CHECKED, against the real registry and real binaries — never a
// hand-written module list:
//  1. `install --help`: the --with help is generated from the registry
//     (optionalModulesHelp), so demo must appear in it;
//  2. `module list` prints demo with its kind;
//  3. GET /api/modules (the real console server, spawned as the production
//     binary does) returns demo with its title, description and state;
//  4. GET /api/status: the state catalog (registryNamespaces) contains
//     every namespace demo declares;
//  5. console.AdminRights() (the B6 sum) contains every RBAC tuple demo
//     declares in Info.Permissions;
//  6. the UNTAGGED production binary knows nothing about demo.
//
// WHY A FAKE KUBECONFIG pointing at an unreachable address: every command
// here reads cluster state. A dangling-but-valid kubeconfig makes the
// client construction succeed and every API call fail FAST (connection
// refused), so modules honestly report "unknown" and the test needs no
// cluster — while a MISSING kubeconfig would take a different code path
// (nil client) than production.
package demo_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ceffio-suite/ceffio/internal/console"
	"github.com/ceffio-suite/ceffio/internal/module"
	// Blank import: the aggregation point, exactly as cmd/ceffio imports it.
	// WITH the demo tag, all_demo.go joins this build and wires the demo
	// module into the registry — the in-process checks below (AdminRights,
	// module.Get) run against that real registry.
	_ "github.com/ceffio-suite/ceffio/internal/modules"
)

// fakeKubeconfig is a valid kubeconfig whose server answers nothing: the
// clients build, the API calls fail fast (see the package comment).
const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: unreachable
  cluster:
    server: https://127.0.0.1:1
contexts:
- name: unreachable
  context:
    cluster: unreachable
    user: nobody
current-context: unreachable
users:
- name: nobody
  user: {}
`

// repoRoot walks up from this file to the directory holding go.mod — the
// same identification rule as the registry guardrail test, so moving files
// around cannot silently point the builds elsewhere.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unreadable: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found: the test is not running inside the repository")
		}
		dir = parent
	}
}

// buildCLI compiles ./cmd/ceffio, with or without the demo tag, and returns
// the binary path. This is the production build command (Makefile), plus
// the tag — nothing test-specific is compiled in.
func buildCLI(t *testing.T, root, name string, withDemoTag bool) string {
	t.Helper()
	args := []string{"build"}
	if withDemoTag {
		args = append(args, "-tags", "demo")
	}
	out := filepath.Join(t.TempDir(), name)
	args = append(args, "-o", out, "./cmd/ceffio")

	// Generous timeout: a cold module cache makes the first build slow,
	// and a hung build must fail the test, not the CI job.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %v: %v\n%s", args, err, combined)
	}
	return out
}

// clusterlessEnv returns the process environment with KUBECONFIG pointing
// at the fake file (any inherited KUBECONFIG is filtered out: a real
// cluster on the developer's machine must not change what the test sees).
func clusterlessEnv(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(fakeKubeconfig), 0o600); err != nil {
		t.Fatalf("writing the fake kubeconfig: %v", err)
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "KUBECONFIG=") {
			env = append(env, kv)
		}
	}
	return append(env, "KUBECONFIG="+path)
}

// runCLI runs the binary and returns its combined output.
func runCLI(t *testing.T, bin string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// freePort reserves an ephemeral port and releases it for the console
// subprocess. The tiny window between closing and rebinding is acceptable:
// a collision fails loudly on the readiness poll below, never silently.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// ---------------------------------------------------------------------------
// The proof: one tagged binary, every frontend, demo visible everywhere.
// ---------------------------------------------------------------------------

func TestDemoModuleEstBranchePartout(t *testing.T) {
	root := repoRoot(t)
	env := clusterlessEnv(t)
	bin := buildCLI(t, root, "ceffio-demo", true)

	// The module under test is read from the REAL registry — the same
	// registry every assertion below is derived from. If demo were not
	// registered, the very first line fails and nothing after it can lie.
	demoMod, ok := module.Get("demo")
	if !ok {
		t.Fatal(`module "demo" is not in the registry: the blank import in internal/modules/all_demo.go is missing (or lost its //go:build demo tag)`)
	}
	info := demoMod.Info()

	// 1. THE INSTALLER'S HELP. optionalModulesHelp walks module.All():
	// no installer file names demo, yet demo must be documented under
	// --with. This is "the installer does not change", proven by output.
	help := runCLI(t, bin, env, "install", "--help")
	if !strings.Contains(help, "demo") {
		t.Errorf("install --help does not mention demo — the --with help is generated from the registry, so a registered Optional module MUST appear in it.\nHelp output:\n%s", help)
	}
	// Sanity: the help really is the registry catalog, not some string
	// that happens to contain "demo".
	if !strings.Contains(help, "live-transcription") || !strings.Contains(help, "recording") {
		t.Errorf("install --help does not list the other optional modules — is the registry-driven help broken?\nHelp output:\n%s", help)
	}

	// 2. THE CLI CATALOG. `module list` walks module.All() and reads each
	// state; demo must appear as an optional module.
	list := runCLI(t, bin, env, "module", "list")
	found := false
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "demo" {
			found = true
			if fields[1] != "optional" {
				t.Errorf("module list shows demo as %q, expected \"optional\"", fields[1])
			}
		}
	}
	if !found {
		t.Errorf("module list does not return demo — the CLI catalog comes from the registry.\nOutput:\n%s", list)
	}

	// 3+4. THE CONSOLE. Spawned exactly as production does (`ceffio
	// console`), over the unreachable cluster: the API must still serve
	// the full catalog from the registry.
	port := freePort(t)
	srv := exec.Command(bin, "console",
		"--domain", "demo.test",
		"--addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--key", consoleKey)
	srv.Env = env
	if err := srv.Start(); err != nil {
		t.Fatalf("starting the console: %v", err)
	}
	t.Cleanup(func() {
		srv.Process.Kill()
		srv.Wait()
	})

	client := &http.Client{Timeout: 10 * time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// 3. GET /api/modules returns demo with title, description and state.
	var modulesResp struct {
		Modules []moduleViewJSON `json:"modules"`
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := getAuth(client, base+"/api/modules")
		if err == nil {
			if decErr := json.Unmarshal(resp, &modulesResp); decErr != nil {
				t.Fatalf("GET /api/modules: unreadable JSON: %v\n%s", decErr, resp)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("console never became ready on %s: %v", base, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	var seen *moduleViewJSON
	for i := range modulesResp.Modules {
		if modulesResp.Modules[i].ID == "demo" {
			seen = &modulesResp.Modules[i]
		}
	}
	if seen == nil {
		t.Fatalf("GET /api/modules does not return demo (%d modules listed) — the console reads the registry through the moduleAll seam, no console change should have been needed", len(modulesResp.Modules))
	}
	if seen.Title != info.Title || seen.Title == "" {
		t.Errorf("API title = %q, registry title = %q", seen.Title, info.Title)
	}
	if seen.Description != info.Description || seen.Description == "" {
		t.Errorf("API description does not match the registry Info.Description")
	}
	if seen.Kind != "optional" {
		t.Errorf("API kind = %q, expected \"optional\"", seen.Kind)
	}
	// The state is OBSERVED (cluster unreachable here): the honest answer
	// is unknown, and what matters is that the endpoint carries a state
	// at all rather than omitting demo's.
	if seen.State.Status == "" {
		t.Error("API response for demo carries no state")
	}

	// 4. GET /api/status: the state catalog is built from the namespaces
	// the registry declares (registryNamespaces). Every namespace demo
	// declares must appear as a layer — no status-page change was made
	// for demo, which is exactly the point.
	statusBody, err := getAuth(client, base+"/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	var statusResp struct {
		Stack []struct {
			Name string `json:"name"`
		} `json:"stack"`
	}
	if err := json.Unmarshal(statusBody, &statusResp); err != nil {
		t.Fatalf("GET /api/status: unreadable JSON: %v\n%s", err, statusBody)
	}
	layers := map[string]bool{}
	for _, l := range statusResp.Stack {
		layers[l.Name] = true
	}
	for _, ns := range info.Namespaces {
		if !layers[ns] {
			t.Errorf("state catalog does not contain namespace %q declared by demo (layers: %v) — the catalog is registry-derived, so a declared namespace must appear without touching status.go", ns, keysOf(layers))
		}
	}

	// 5. RBAC. AdminRights is the SUM of the registered modules'
	// Info.Permissions (batch B6): every tuple demo declares must be in
	// the grant, with no console/deploy.go change. Checked in-process
	// against the real registry and the real exported function.
	rights, err := console.AdminRights()
	if err != nil {
		t.Fatalf("console.AdminRights: %v", err)
	}
	granted := map[string]bool{}
	for _, r := range rights {
		for _, rule := range r.Rules {
			for _, g := range rule.APIGroups {
				for _, res := range rule.Resources {
					for _, verb := range rule.Verbs {
						granted[tupleKey(r.Namespace, g, res, verb)] = true
					}
				}
			}
		}
	}
	for _, p := range info.Permissions {
		for _, rule := range p.Rules {
			for _, g := range rule.APIGroups {
				for _, res := range rule.Resources {
					for _, verb := range rule.Verbs {
						if !granted[tupleKey(p.Namespace, g, res, verb)] {
							t.Errorf("AdminRights is missing demo's tuple (%s, %q, %s, %s) — the RBAC sum must follow the registry with no change in deploy.go",
								p.Namespace, g, res, verb)
						}
					}
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The build-tag guarantee: the PRODUCTION binary knows nothing about demo.
// ---------------------------------------------------------------------------

func TestDemoAbsentDuBinaireDeProduction(t *testing.T) {
	root := repoRoot(t)
	env := clusterlessEnv(t)
	// The exact production build: NO tag. Every file of the demo package
	// and its wiring (all_demo.go) carry //go:build demo, so the linker
	// never sees them — and the registry init() never runs.
	bin := buildCLI(t, root, "ceffio-prod", false)

	list := runCLI(t, bin, env, "module", "list")
	for _, line := range strings.Split(list, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "demo" {
			t.Fatalf("the UNTAGGED production binary lists demo — the build tag failed to exclude it:\n%s", list)
		}
	}

	help := runCLI(t, bin, env, "install", "--help")
	if strings.Contains(help, "demo") {
		t.Fatalf("the UNTAGGED production binary's --with help mentions demo — the build tag failed to exclude it:\n%s", help)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// moduleViewJSON mirrors internal/console.moduleView (unexported): the JSON
// shape of GET /api/modules. Declared here rather than exported from the
// console package, which the batch must not modify.
type moduleViewJSON struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Kind        string       `json:"kind"`
	State       module.State `json:"state"`
}

// consoleKey is the admin token the spawned console is started with and
// every request authenticates with (declared once so the two cannot drift).
const consoleKey = "testkey"

func getAuth(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+consoleKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s -> %d: %s", url, resp.StatusCode, body)
	}
	return body, nil
}

func tupleKey(ns, group, res, verb string) string {
	return ns + "|" + group + "|" + res + "|" + verb
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
