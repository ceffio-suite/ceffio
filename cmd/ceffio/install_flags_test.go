// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestFlagsSansEffetSontMasques : the two flags that never did anything stay
// accepted for one minor release, out of the help output.
//
// WHY THEY ARE KEPT AT ALL: a deployment script written against the previous
// version passes --office=false, and would fail on an unknown flag. Hiding them
// keeps the script running; removing them outright would break it for no gain.
// The removal date is stated so this does not become permanent by neglect.
//
// --mail IS NO LONGER AMONG THEM: it was the misleading one, and mail is now a
// real Optional module selected with --with/--without. A third spelling, inert
// this time, would be worse than the flag it replaced.
func TestFlagsSansEffetSontMasques(t *testing.T) {
	c := newInstallCmd()
	for _, nom := range []string{"office", "monitoring"} {
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

// TestNomsAttendusSuitLaSelection: the DNS preflight checks exactly the hosts
// the installation will serve.
//
// WHY THIS REPLACES A TEST IN internal/bootstrap: that one compared a constant
// to itself ("const attendu = 7; if attendu != 7"), so it could not fail, and
// the list it described moved here where nomsAttendus lives. A preflight that
// asks for a record the installation does not need sends the operator hunting
// for a host that will never exist; one that forgets a host lets the
// installation finish with a certificate that is never issued.
func TestNomsAttendusSuitLaSelection(t *testing.T) {
	sans := nomsAttendus("example.com", false)
	if len(sans) != 6 {
		t.Errorf("%d hosts without mail, expected the six Core ones: %v", len(sans), sans)
	}
	avec := nomsAttendus("example.com", true)
	if len(avec) != 7 {
		t.Errorf("%d hosts with mail, expected seven: %v", len(avec), avec)
	}
	for _, h := range sans {
		if h == "mail.example.com" {
			t.Error("mail.example.com is required although mail is not selected")
		}
	}
	var vu bool
	for _, h := range avec {
		if h == "mail.example.com" {
			vu = true
		}
	}
	if !vu {
		t.Error("mail.example.com is missing although mail is selected")
	}
}
