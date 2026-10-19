// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestFlagsSansEffetSontMasques : the three flags that never did anything stay
// accepted for one minor release, out of the help output.
//
// WHY THEY ARE KEPT AT ALL: a deployment script written against the previous
// version passes --mail=false, and would fail on an unknown flag. Hiding them
// keeps the script running; removing them outright would break it for no gain.
// The removal date is stated so this does not become permanent by neglect.
func TestFlagsSansEffetSontMasques(t *testing.T) {
	c := newInstallCmd()
	for _, nom := range []string{"mail", "office", "monitoring"} {
		f := c.Flags().Lookup(nom)
		if f == nil {
			t.Errorf("--%s is gone: an existing script would fail on an unknown flag", nom)
			continue
		}
		if !f.Hidden {
			t.Errorf("--%s is still listed in --help while it does nothing", nom)
		}
	}
}

// TestResumeListeLesModulesDuRegistre : the install summary reads the registry
// rather than flags that claim a state.
//
// WHY THIS IS THE POINT: the summary used to print "Mail: no" from an option
// that had no effect, while Stalwart — a Core module — was being installed. The
// output meant to inform the operator was the one misleading them. The test
// asserts that what is printed comes from the registry, so a module added
// tomorrow appears without touching the summary.
func TestResumeListeLesModulesDuRegistre(t *testing.T) {
	// The command must not be run: this checks the flag surface and the module
	// list the summary consumes, not the deployment.
	var buf bytes.Buffer
	ecrireResumeModules(&buf, []string{"socle", "identity"}, []string{"recording"})
	sortie := buf.String()

	if !strings.Contains(sortie, "socle, identity") {
		t.Errorf("the Core modules are not listed: %q", sortie)
	}
	if !strings.Contains(sortie, "recording") {
		t.Errorf("the optional modules are not listed: %q", sortie)
	}
	// The old lines must be gone.
	for _, mort := range []string{"Mail:", "Office:", "Monitoring:"} {
		if strings.Contains(sortie, mort) {
			t.Errorf("the summary still prints %q, which came from a flag with no effect", mort)
		}
	}
}

// TestResumeSansModuleOptionnel : an installation that selects nothing must say
// so, not print an empty line.
func TestResumeSansModuleOptionnel(t *testing.T) {
	var buf bytes.Buffer
	ecrireResumeModules(&buf, []string{"socle"}, nil)
	if !strings.Contains(buf.String(), "Optional:   none") {
		t.Errorf("a single Core module should still announce no optional one: %q", buf.String())
	}
}
