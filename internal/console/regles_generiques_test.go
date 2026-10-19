// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// This file is the GUARDRAIL of the settings contract.
//
// The promise is: a feature that has settings is added by writing only its own
// package — the console draws, validates and applies them without change. A
// promise nobody checks is an intention, and the way it fails is quiet: someone
// needs one special case, adds one route, and the next feature copies the
// special case instead of the contract.
//
// TWO CHECKS, and neither searches for module IDs by name: `files`, `data`,
// `mail` and `console` are ordinary English words, so looking for them in the
// page would produce false positives on the first line of prose. What is checked
// is the SHAPE:
//
//  1. every route registered on the console's mux belongs to a closed list of
//     generic routes;
//  2. the page calls no `/api/modules/<id>` URL literally, and contains no
//     module ID as a quoted string.

// routesAutorisees is the CLOSED list of routes the console may serve.
//
// WHY A CLOSED LIST AND NOT A REGEX: a regex like `/api/modules/[^/]+/settings`
// would accept a route named after one module, which is exactly what must be
// refused. The list names every route, so adding one is a deliberate act visible
// in a diff — and the reason beside each says what it is for.
var routesAutorisees = map[string]string{
	"/":                                  "the page itself",
	"/favicon.ico":                       "icon",
	"/favicon.svg":                       "icon",
	"/favicon-32.png":                    "icon",
	"/apple-touch-icon.png":              "icon",
	"/api/":                              "404 for unknown API paths",
	"/api/status":                        "cluster state",
	"/api/users":                         "account management",
	"/api/users/":                        "one account",
	"/api/modules":                       "module list",
	"/api/modules/{id}":                  "one module, read and actions",
	"/api/modules/{id}/settings":         "GENERIC settings read",
	"/api/modules/{id}/settings/{group}": "GENERIC settings save",
	"/api/modules/{id}/settings/{group}/test": "GENERIC settings check",
	"/api/admin":        "administration account",
	"/api/admin/rotate": "password rotation",
	"/api/tls":          "certificates",
	"/api/monitoring":   "the machine: node consumption, volumes, storage",
}

// routesEnregistrees reads the routes the console declares.
//
// WHY THE SOURCE AND NOT THE MUX: Go's ServeMux is not introspectable, so there
// is no list to ask for. The whole package is scanned rather than one file,
// because a route declared in a file nobody expected is exactly what should be
// caught.
func routesEnregistrees(t *testing.T) []string {
	t.Helper()
	fichiers, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("reading the package: %v", err)
	}
	// Matches both mux.HandleFunc("GET /api/…", …) and mux.HandleFunc("/…", …).
	motif := regexp.MustCompile(`HandleFunc\(\s*(?:"(?:[A-Z]+ )?([^"]+)"|` + "`" + `([^` + "`" + `]+)` + "`" + `)`)
	vus := map[string]bool{}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range motif.FindAllStringSubmatch(string(b), -1) {
			route := m[1]
			if route == "" {
				route = m[2]
			}
			vus[route] = true
		}
	}
	out := make([]string, 0, len(vus))
	for r := range vus {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// indexHTML returns the console page as served.
//
// It reads the embedded file through the same variable the server uses, so the
// test cannot pass on a stale copy on disk: what is asserted is what a browser
// receives.
func indexHTML(t *testing.T) []byte {
	t.Helper()
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("reading the embedded page: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("the embedded page is empty")
	}
	return b
}

// TestRoutesConsoleAppartiennentALAListeFermee : no route is registered outside
// the list.
func TestRoutesConsoleAppartiennentALAListeFermee(t *testing.T) {
	routes := routesEnregistrees(t)
	if len(routes) == 0 {
		t.Fatal("no route found: the scan is broken, not the code")
	}
	for _, route := range routes {
		if _, ok := routesAutorisees[route]; !ok {
			t.Errorf("route %q is not in the closed list.\n"+
				"A route outside the list is a console change made for one feature — the "+
				"drift the settings contract exists to prevent. If it is genuinely generic, "+
				"add it to routesAutorisees with its reason; if it serves one module, "+
				"declare it in that module instead.", route)
		}
	}
}

// TestListeFermeeEstExhaustive : the closed list and the registered routes hold
// the same set.
//
// Without this the two would drift: a route removed from the mux but left in the
// list would keep a reason for something that no longer exists, and the check
// above would pass while a route is silently missing.
func TestListeFermeeEstExhaustive(t *testing.T) {
	enregistrees := map[string]bool{}
	for _, r := range routesEnregistrees(t) {
		enregistrees[r] = true
	}
	var manquantes []string
	for r := range routesAutorisees {
		if !enregistrees[r] {
			manquantes = append(manquantes, r)
		}
	}
	if len(manquantes) > 0 {
		sort.Strings(manquantes)
		t.Errorf("the closed list describes routes that are not registered: %v", manquantes)
	}
}

// TestLaPageNAppelleAucunModuleEnDur : index.html calls no module-specific URL
// and mentions no module ID as a quoted string.
//
// WHY NOT A SEARCH FOR KNOWN IDs: `files`, `data`, `mail` and `console` are
// ordinary words — a search for them would flag prose. What is checked is that
// the page builds its URLs from what the API returns, which is what makes it
// generic.
func TestLaPageNAppelleAucunModuleEnDur(t *testing.T) {
	page := string(indexHTML(t))

	// 1. No literal /api/modules/<something>: the page must interpolate.
	motif := regexp.MustCompile(`/api/modules/[A-Za-z0-9_-]+`)
	if m := motif.FindAllString(page, -1); len(m) > 0 {
		t.Errorf("index.html calls module URLs literally: %v.\n"+
			"The page must build them from the module list the API returns, otherwise "+
			"it knows a feature's name and stops being generic.", m)
	}

	// 2. No module ID as a quoted string, for every module the REGISTRY knows.
	//    Read from module.All() so a module added later is covered without
	//    touching this test.
	for _, mod := range module.All() {
		id := mod.Info().ID
		// A module ID that is a common word would produce false positives on
		// prose. Requiring a hyphen OR a length >= 5 keeps the check on
		// identifiers that read as identifiers.
		if !strings.Contains(id, "-") && len(id) < 5 {
			continue
		}
		for _, q := range []string{`"`, `'`, "`"} {
			if strings.Contains(page, q+id+q) {
				t.Errorf("index.html contains the module ID %q in quotes.\n"+
					"A module name in the page is a feature the console knows by name; "+
					"the list must come from /api/modules.", id)
			}
		}
	}
}
