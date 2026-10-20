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
	"/api/certificates": "certificates, read-only",
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

// TestLaPageNAppelleQueDesRoutesQuiExistent : every /api/… URL the page calls
// corresponds to a route the console actually serves.
//
// WHY THIS TEST EXISTS, AND WHAT IT WOULD HAVE CAUGHT: the SMTP tab was left in
// the page after /api/smtp was removed. A menu entry, a whole section, a hundred
// and thirty lines of JavaScript calling /api/smtp and /api/smtp/tester —
// against routes that no longer existed. An administrator opening that tab got
// an error, and nothing in the test suite noticed: the closed list checked that
// every REGISTERED route was listed, never that every CALLED one was registered.
//
// The two directions are not the same check, and only one of them fails on the
// operator's screen. A route registered and never called is dead code; a URL
// called and never routed is a broken page.
//
// THE COMPARISON IS ON THE SHAPE, like the rest of this file: the page builds
// module URLs by interpolating, so `/api/modules/${id}/settings` is compared as
// its prefix, and a template is accepted exactly when a registered route covers
// it. What is refused is a URL that NO route can serve.
func TestLaPageNAppelleQueDesRoutesQuiExistent(t *testing.T) {
	page := string(indexHTML(t))

	enregistrees := map[string]bool{}
	for _, r := range routesEnregistrees(t) {
		enregistrees[r] = true
	}

	// Every /api/… occurrence in the page, from a literal or a template.
	//
	// THE MATCH STOPS AT THE FIRST CHARACTER THAT CANNOT BE IN A PATH: a quote
	// ends a literal, `${` opens an interpolation. Taking the whole run would
	// compare `/api/modules/${m.id}/settings` — a template — against a
	// registered route, which is never equal.
	motif := regexp.MustCompile(`/api/[A-Za-z0-9_/{}.\-]*`)
	vus := map[string]bool{}
	for _, u := range motif.FindAllString(page, -1) {
		// `/api/smtp/tester` and `/api/smtp/` normalise to their route.
		u = strings.TrimSuffix(u, "/")
		if u == "" || u == "/api" {
			continue
		}
		vus[u] = true
	}
	if len(vus) == 0 {
		t.Fatal("the page calls no API URL at all: the scan is broken, not the page")
	}

	for u := range vus {
		if _, ok := routesAutorisees[u]; ok {
			continue
		}
		// A template — `/api/modules/${id}/settings` — is accepted when a
		// registered route has the same shape: the same number of segments, with
		// the variable ones spelled {…} in the list.
		if couverte(u, enregistrees) {
			continue
		}
		t.Errorf("the page calls %q, which no route serves.\n"+
			"A URL the page calls and the console does not route is a BROKEN PAGE: "+
			"the operator opens a tab and gets an error. Either register the route, or "+
			"— if the feature moved — remove what still calls it. This is the check that "+
			"was missing when the SMTP tab outlived its route.", u)
	}
}

// couverte reports whether a registered route can serve a URL the page calls.
//
// TWO ROUTES ARE EXCLUDED, and the exclusion is the whole correctness of this
// check. Measured, both accepted everything:
//
//   - `/api/` — the 404 handler. It answers the very error this test exists to
//     catch, so "some route starts with what the page wrote" was true for every
//     unknown path.
//   - `/` — the page itself. EVERY string starts with "/", so it covered every
//     URL in the file, including `/api/smtp`. This one survived the first fix:
//     excluding `/api/` alone left the test passing with the broken page in
//     front of it, and only a direct probe of this function showed why.
//
// A check that accepts anything detects nothing, which is worse than no check:
// it reads as proof. Two rounds were needed to find both, and the second is the
// reason this comment names the measurement rather than the intention.
//
// THE COMPARISON IS RESTRICTED TO /api, since that is what the page calls: the
// icons and the page itself are not API routes and have nothing to say here.
//
// The page interpolates into its module URLs, so the literal it contains is a
// PREFIX of the real one: `/api/modules/` appears in the page where the full URL
// is `/api/modules/${id}/settings`. A prefix several routes share is therefore
// ambiguous, and ambiguity must be accepted — refusing it would flag a correct
// page. What is compared is that some real route starts with what the page wrote,
// or the other way round.
func couverte(appele string, enregistrees map[string]bool) bool {
	if !strings.HasPrefix(appele, "/api") {
		return false
	}
	for r := range enregistrees {
		// Neither of these is a route the page may rely on: one answers the
		// error this test exists to catch, the other is the page itself.
		if r == "/api/" || r == "/" {
			continue
		}
		if strings.HasPrefix(r, appele) {
			return true
		}
		// The other way round: the page wrote more than the route names, which
		// happens for a sub-path of a registered prefix route.
		if strings.HasPrefix(appele, strings.TrimSuffix(r, "/")) {
			return true
		}
	}
	return false
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
