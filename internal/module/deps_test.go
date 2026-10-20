// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAucuneDependanceInterne : internal/module imports no other internal
// package — WITHOUT EXCEPTION.
//
// WHY THIS IS A RULE AND NOT A PREFERENCE: every module imports this package, so
// anything imported here becomes a dependency of EVERY module. Importing
// internal/console would let a module reach the console; importing internal/acme
// would let a module reach one feature's types. Both would break the promise the
// module system makes — that a feature is added without touching anything but its
// own package.
//
// THE CHECK IS STRICT, and it used to tolerate one package. While the ACME
// settings were still carried by Env, internal/acme was the single tolerated
// entry and the test SKIPPED on it — a debt made visible rather than a rule
// forgotten. That debt is settled: the ingress module declares those settings now,
// so the tolerance is removed and any internal package at all fails here.
//
// A TOLERATED ENTRY IS A RULE THAT EXPIRES SILENTLY. The skip named D5, and a
// reader who arrived after D5 would have found a test that skips for a reason no
// longer true — then added the next exception beside it. Removing it is the point
// of this lot, not a detail of it.
//
// The check runs `go list -deps`, the same command the plan asks for in the
// report, so the test and the reported evidence cannot disagree.
func TestAucuneDependanceInterne(t *testing.T) {
	const soiMeme = "github.com/ceffio-suite/ceffio/internal/module"

	sortie, err := exec.Command("go", "list", "-deps", "./").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	var intrus []string
	for _, ligne := range strings.Split(string(sortie), "\n") {
		p := strings.TrimSpace(ligne)
		if !strings.Contains(p, "ceffio/internal/") {
			continue
		}
		if p == soiMeme {
			continue
		}
		intrus = append(intrus, p)
	}

	// A scan that finds nothing to scan is a broken scan, not a clean package:
	// without this, a change to the module path would make the test pass on an
	// empty list. The package itself must appear in its own dependencies.
	if !strings.Contains(string(sortie), soiMeme) {
		t.Fatalf("the package does not list itself in `go list -deps`: the scan read nothing, "+
			"and the check below would pass on an empty result.\nOutput: %.300s", sortie)
	}

	if len(intrus) > 0 {
		t.Errorf("internal/module depends on %d other internal package(s):\n  %s\n"+
			"Every module imports this package, so each of these becomes a dependency of "+
			"every module — including on packages modules must not reach. There is NO "+
			"exception: if a value must cross this boundary, declare it here as an "+
			"interface the way Settings and Secrets are, rather than importing the "+
			"package that produces it.",
			len(intrus), strings.Join(intrus, "\n  "))
	}
}