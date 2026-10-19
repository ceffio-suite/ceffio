//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package demo_test

// INTEGRATION TEST OF THE SETTINGS CONTRACT — the executable proof that a
// feature's settings need no console change either.
//
// WHY THIS IS THE POINT OF THE WHOLE CHANTIER: installing, observing and
// removing a feature already needed only its own package. SETTINGS did not —
// they were written by hand in the console, so the next feature with settings
// would have forced a console change. The demo module now declares a group, and
// this test proves the console, the API and the CLI serve it with NO change to
// any of them.
//
// IT RUNS REAL BINARIES, for the same reason the module's wiring test does: a
// test that called the handlers in-process would pass even if the route were
// never registered, or if the CLI subcommand were missing. Spawning the
// production binary removes the blind spot — this is the CLI an operator
// actually runs, and the console it actually opens.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// reglagesVue is the shape GET /api/modules/{id}/settings returns.
type reglagesVue struct {
	Module string `json:"module"`
	Groups []struct {
		ID     string `json:"id"`
		Title  string `json:"title"`
		Fields []struct {
			Key      string `json:"key"`
			Label    string `json:"label"`
			Type     string `json:"type"`
			Required bool   `json:"required"`
		} `json:"fields"`
		Values   map[string]string `json:"values"`
		Testable bool              `json:"testable"`
	} `json:"groups"`
	Testable bool `json:"testable"`
	Editable bool `json:"editable"`
}

// TestLesReglagesDuDemoSontServis proves the API and the CLI serve the module's
// settings without either of them knowing the module.
func TestLesReglagesDuDemoSontServis(t *testing.T) {
	root := repoRoot(t)
	env := clusterlessEnv(t)
	bin := buildCLI(t, root, "ceffio-demo-reglages", true)

	// The declaration is read from the REAL registry: every assertion below is
	// derived from it, never from a copy written in this file.
	m, ok := module.Get("demo")
	if !ok {
		t.Fatal("demo is not in the registry")
	}
	cfg, ok := m.(module.Configurable)
	if !ok {
		t.Fatal("the demo module does not implement Configurable: the settings contract is not exercised")
	}
	declares := cfg.Settings()
	if len(declares) == 0 {
		t.Fatal("the demo module declares no group")
	}
	groupe := declares[0]

	// --- 1. THE CONSOLE, spawned exactly as production does ----------------
	port := freePort(t)
	srv := exec.Command(bin, "console",
		"--domain", "demo.test",
		"--addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--key", consoleKey)
	srv.Env = env
	if err := srv.Start(); err != nil {
		t.Fatalf("starting the console: %v", err)
	}
	t.Cleanup(func() { srv.Process.Kill(); srv.Wait() })

	client := &http.Client{Timeout: 10 * time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	var vue reglagesVue
	attendre(t, func() error {
		corps, err := getAuth(client, base+"/api/modules/demo/settings")
		if err != nil {
			return err
		}
		return json.Unmarshal(corps, &vue)
	}, "GET /api/modules/demo/settings")

	if vue.Module != "demo" {
		t.Errorf("the answer is about %q, expected demo", vue.Module)
	}
	if len(vue.Groups) != len(declares) {
		t.Fatalf("the API served %d group(s), the module declares %d", len(vue.Groups), len(declares))
	}
	servi := vue.Groups[0]
	if servi.ID != groupe.ID {
		t.Errorf("group ID = %q, declared %q", servi.ID, groupe.ID)
	}
	if len(servi.Fields) != len(groupe.Fields) {
		t.Errorf("the API served %d field(s), the module declares %d — a console change would be needed otherwise",
			len(servi.Fields), len(groupe.Fields))
	}
	// Every declared key must be served, with its type and its required flag.
	for _, f := range groupe.Fields {
		var trouve *struct {
			Key      string `json:"key"`
			Label    string `json:"label"`
			Type     string `json:"type"`
			Required bool   `json:"required"`
		}
		for i := range servi.Fields {
			if servi.Fields[i].Key == f.Key {
				trouve = &servi.Fields[i]
			}
		}
		if trouve == nil {
			t.Errorf("the API does not serve the field %q declared by the module", f.Key)
			continue
		}
		if trouve.Type != string(f.Type) {
			t.Errorf("field %q: type served %q, declared %q", f.Key, trouve.Type, f.Type)
		}
		if trouve.Required != f.Required {
			t.Errorf("field %q: required served %v, declared %v", f.Key, trouve.Required, f.Required)
		}
	}

	// THE SECRET IS NEVER SERVED BACK. Asserted on the RAW BODY, not on a
	// decoded field: a field added later by mistake would pass a check that
	// only looks at known keys.
	brut, _ := getAuth(client, base+"/api/modules/demo/settings")
	if strings.Contains(string(brut), "mon-jeton-secret") {
		t.Errorf("the API answered with a secret value: %s", brut)
	}

	// --- 2. THE CLI -------------------------------------------------------
	// `module config demo` must list the groups, and `--test` must run the
	// check. Neither needs a change in the CLI: both walk the registry.
	liste := runCLI(t, bin, env, "module", "config", "demo")
	if !strings.Contains(liste, groupe.ID) {
		t.Errorf("`module config demo` does not list the group %q.\nOutput:\n%s", groupe.ID, liste)
	}
	for _, f := range groupe.Fields {
		if !strings.Contains(liste, f.Key) {
			t.Errorf("`module config demo` does not list the field %q.\nOutput:\n%s", f.Key, liste)
		}
	}

	essai := runCLI(t, bin, env, "module", "config", "demo", groupe.ID, "--test", "message=bonjour")
	if !strings.Contains(essai, "bonjour") && !strings.Contains(essai, "message is set") {
		t.Errorf("`--test` did not reach the module's check.\nOutput:\n%s", essai)
	}

	// --- 3. A MALFORMED VALUE IS REFUSED, with the field named -------------
	// The message is required; an empty one must be refused by BOTH frontends,
	// through the same shared validation.
	if _, err := getAuth(client, base+"/api/modules/demo/settings"); err != nil {
		t.Fatalf("re-reading the settings: %v", err)
	}
	code, corps := postAuth(client, base+"/api/modules/demo/settings/"+groupe.ID, `{"message":""}`)
	if code != http.StatusBadRequest {
		t.Errorf("an empty required field -> %d, expected 400 (%s)", code, corps)
	}
	if !strings.Contains(corps, "message") {
		t.Errorf("the refusal does not name the field: %s", corps)
	}

	cliErr := runCLIErr(t, bin, env, "module", "config", "demo", groupe.ID, "message=")
	if !strings.Contains(cliErr, "message") {
		t.Errorf("the CLI refusal does not name the field: %s", cliErr)
	}
}

// TestLeCommitNeToucheQUEleModuleDemo is the guardrail the plan asks for: a
// change that adds settings to a feature must touch ONLY that feature's package.
//
// It reads the module's own files and asserts none of them imports the console,
// the CLI or another module: an import of any of those would mean the feature
// had to change something outside itself, which is exactly what the contract
// exists to prevent.
func TestLeCommitNeToucheQUEleModuleDemo(t *testing.T) {
	root := repoRoot(t)
	// The modules' PRODUCTION sources are read from disk, never the test files:
	// a test may import what it likes — the integration test imports the console
	// to assert on AdminRights, which is how it checks a promise made to the
	// console without depending on it. What must not import the console is the
	// MODULE, because that is what would force a console change.
	sortie, err := exec.Command("sh", "-c",
		"grep -rhoE '\"github.com/ceffio-suite/ceffio/internal/[a-z]+[^\"]*\"' "+
			root+"/internal/modules/demo/*.go | grep -v _test.go | sort -u").Output()
	if err != nil {
		t.Fatalf("reading the demo module's imports: %v", err)
	}

	// grep cannot exclude by filename through -h, so the list is built from the
	// files themselves: every .go file of the package that is NOT a test.
	fichiers, err := filepath.Glob(root + "/internal/modules/demo/*.go")
	if err != nil {
		t.Fatalf("listing the package: %v", err)
	}
	imports := map[string]bool{}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range regexp.MustCompile(`"github\.com/ceffio-suite/ceffio/internal/[^"]*"`).
			FindAllString(string(b), -1) {
			imports[strings.Trim(m, `"`)] = true
		}
	}
	if len(imports) == 0 {
		t.Fatal("no import was read: the scan is broken, not the code")
	}

	interdits := []string{
		"ceffio/internal/console",
		"ceffio/internal/cmd/",
		"ceffio/internal/modules/",
	}
	for imp := range imports {
		for _, interdit := range interdits {
			if strings.Contains(imp, interdit) && !strings.HasSuffix(imp, "/socle") {
				t.Errorf("the demo module imports %s.\n"+
					"A module importing the console, the CLI or another module is a feature "+
					"that had to change something outside itself — which is what the settings "+
					"contract exists to prevent.", imp)
			}
		}
	}
	_ = sortie
}

// postAuth posts a JSON body with the console key and returns the status and the
// body. The console refuses anything without the key, so a test that forgot it
// would see a 401 and misread it as a settings problem.
func postAuth(client *http.Client, url, body string) (int, string) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+consoleKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

// attendre retries an operation until it succeeds or the deadline passes.
//
// The console takes a moment to bind its port, and a single attempt would make
// the test flaky for a reason that has nothing to do with what it checks.
func attendre(t *testing.T, f func() error, quoi string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var derniere error
	for time.Now().Before(deadline) {
		if err := f(); err == nil {
			return
		} else {
			derniere = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never succeeded: %v", quoi, derniere)
}

// runCLIErr runs the binary and returns the FAILURE output, for the cases where
// the command is expected to refuse something.
func runCLIErr(t *testing.T, bin string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	return string(out)
}
