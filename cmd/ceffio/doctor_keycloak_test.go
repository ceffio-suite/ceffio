// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// withArgs makes LireKeycloakArgs answer a fixed command line, and restores it
// after the test. Doctor reads the live deployment; a test must not.
func withArgs(t *testing.T, args string, err error) {
	t.Helper()
	avant := LireKeycloakArgs
	LireKeycloakArgs = func(context.Context) (string, error) { return args, err }
	t.Cleanup(func() { LireKeycloakArgs = avant })
}

// jsonpathRéel is what the kubectl call returns: one line per container, the bare
// name, then the args rendered as a bracketed, quoted list.
const jsonpathRéel = `keycloak
["/bin/bash","-c","set -a\n. /secrets/env\nset +a\nexec /opt/keycloak/bin/kc.sh start\n"]
`

// TestDoctorRefuseStartDev is the check lot K2 exists for.
//
// A PLATFORM RUNS IN DEVELOPMENT MODE WITHOUT A VISIBLE SYMPTOM: pods are Ready,
// realms resolve, SSO signs users in. What is lost is silent — the caches,
// including the theme cache, and protections nobody looks at. That is precisely
// the kind of fault a doctor should catch, because nothing else will.
func TestDoctorRefuseStartDev(t *testing.T) {
	withArgs(t, `keycloak
["/bin/bash","-c","set -a\n. /secrets/env\nset +a\nexec /opt/keycloak/bin/kc.sh start-dev\n"]
`, nil)

	f := VerifierKeycloakProduction(context.Background())
	if len(f) != 1 {
		t.Fatalf("%d finding(s), expected exactly one", len(f))
	}
	if f[0].Severity != "error" {
		t.Errorf("severity = %q, expected error: start-dev is a mode Keycloak's own "+
			"documentation forbids in production, not a preference", f[0].Severity)
	}
	if !strings.Contains(f[0].Title, "development") {
		t.Errorf("title = %q, expected it to name the development mode", f[0].Title)
	}
	// THE ACTION SAYS WHAT TO DO, not just what is wrong. `ceffio install` is the
	// command that reapplies the manifest, and an operator who has to guess it
	// will restart the pod instead — which changes nothing.
	if !strings.Contains(f[0].Action, "ceffio install") {
		t.Errorf("action = %q, expected it to name the command that reapplies the "+
			"manifest", f[0].Action)
	}
}

// TestDoctorSilenceEnProduction : the check says nothing when the platform is
// right. A doctor that reports a healthy platform trains its reader to ignore it.
func TestDoctorSilenceEnProduction(t *testing.T) {
	withArgs(t, jsonpathRéel, nil)
	if f := VerifierKeycloakProduction(context.Background()); len(f) != 0 {
		t.Errorf("%d finding(s) on a production manifest, expected none: %+v", len(f), f)
	}
}

// TestDoctorNeConfondPasUnCommentaireEtUneCommande : the manifest carries COMMENTS,
// and one of them explains why start-dev was dropped. A substring search would read
// that comment as the fault it describes, and a check that cries wolf gets turned
// off — which is worse than no check.
func TestDoctorNeConfondPasUnCommentaireEtUneCommande(t *testing.T) {
	withArgs(t, `keycloak
["/bin/bash","-c","# we no longer use start-dev here\nexec /opt/keycloak/bin/kc.sh start\n"]
`, nil)
	if f := VerifierKeycloakProduction(context.Background()); len(f) != 0 {
		t.Errorf("%d finding(s), expected none: the word appears in a COMMENT, not in "+
			"the command. %+v", len(f), f)
	}
}

// TestDoctorIgnoreUneIdentiteAbsente : no deployment means no identity layer, which
// the layer diagnostics already report. Saying it a second time buries the first
// message, and the reader cannot tell which one to act on.
func TestDoctorIgnoreUneIdentiteAbsente(t *testing.T) {
	withArgs(t, "", nil)
	if f := VerifierKeycloakProduction(context.Background()); len(f) != 0 {
		t.Errorf("%d finding(s) with no deployment, expected none", len(f))
	}
}

// TestDoctorSignaleUneLectureImpossible : if kubectl cannot be read, the check
// cannot conclude. Reporting silence would be a lie by omission — the operator
// would read "no problem" where the truth is "not verified".
func TestDoctorSignaleUneLectureImpossible(t *testing.T) {
	withArgs(t, "", errors.New("connection refused by the API server"))

	f := VerifierKeycloakProduction(context.Background())
	if len(f) != 1 {
		t.Fatalf("%d finding(s), expected one warning", len(f))
	}
	if f[0].Severity != "warning" {
		t.Errorf("severity = %q, expected warning: an unreadable cluster is not itself "+
			"a defect, but it must not read as a clean bill", f[0].Severity)
	}
}

// TestContientMotCle covers the tokeniser on the shapes a real kubectl output
// takes, including the shell line where the command is glued to a separator.
func TestContientMotCle(t *testing.T) {
	for _, cas := range []struct {
		args     string
		mot      string
		attendu  bool
		pourquoi string
	}{
		{`["/bin/bash","-c","exec kc.sh start-dev"]`, "start-dev", true,
			"the usual shape"},
		{"-c\nset -a\nexec /opt/keycloak/bin/kc.sh start-dev\n", "start-dev", true,
			"the shell line, one token per word after splitting"},
		{`["/bin/bash","-c","exec kc.sh start"]`, "start-dev", false,
			"production mode mentions start, not start-dev"},
		{"# we dropped start-dev\nkc.sh start", "start-dev", false,
			"a comment is not a command"},
		{`["start-dev-something"]`, "start-dev", false,
			"a longer word is not the word"},
	} {
		if got := contientMotCle(cas.args, cas.mot); got != cas.attendu {
			t.Errorf("contientMotCle(%q, %q) = %v, expected %v (%s)",
				cas.args, cas.mot, got, cas.attendu, cas.pourquoi)
		}
	}
}
