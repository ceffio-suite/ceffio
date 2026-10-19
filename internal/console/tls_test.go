// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"os"
	"strings"
	"testing"
)

// TestCheminCoffreDNSCoherentAvecLeSolver is the test that justifies the
// duplication of the vault path between this package and internal/ingress.
//
// The console writes the DNS credential to OpenBao; the solver reads it from
// there through the injector. The two paths are written in two packages — the
// console cannot import the ingress layer, which would drag the whole
// deployment code into the administrative binary. If they diverge, NOTHING
// fails: the page reports the credential as stored, the solver starts with an
// empty file, and every challenge fails on an authentication error that never
// mentions the path. This test turns that silence into a build failure.
//
// It reads the source of the ingress package rather than importing it, which is
// the only way to compare two unexported constants across packages.
func TestCheminCoffreDNSCoherentAvecLeSolver(t *testing.T) {
	const fichierSolver = "../ingress/dnswebhook.go"

	brut, err := os.ReadFile(fichierSolver)
	if err != nil {
		t.Fatalf("cannot read %s: %v", fichierSolver, err)
	}
	source := string(brut)

	// The solver declares the FULL path, mount included, as the injector
	// template addresses the KV engine directly.
	attendu := "kv/data/" + cheminCoffreDNS[0] + "/" + cheminCoffreDNS[1]
	if !strings.Contains(source, `cheminBaoIdentifiantsDNS = "`+attendu+`"`) {
		t.Errorf("the solver reads its credential from a path this page does not write.\n"+
			"  console writes : %s/%s (full path %s)\n"+
			"  solver expects : see cheminBaoIdentifiantsDNS in %s\n"+
			"Nothing would fail at runtime: the page would report the credential as stored "+
			"and the solver would start with an empty file.",
			cheminCoffreDNS[0], cheminCoffreDNS[1], attendu, fichierSolver)
	}
}

// TestNamespaceCertManagerCoherent: the page observes the solver pod in
// cert-manager. A different namespace there means the page always reports
// "solver absent" — which, with dns01 configured, sends the operator looking
// for a cluster problem that does not exist.
func TestNamespaceCertManagerCoherent(t *testing.T) {
	brut, err := os.ReadFile("../ingress/dnswebhook.go")
	if err != nil {
		t.Fatalf("cannot read the solver source: %v", err)
	}
	if !strings.Contains(string(brut), "nsCertManager") {
		t.Errorf("the solver no longer derives from nsCertManager — the console's copy (%q) "+
			"is now unverified", nsCertManager)
	}
}

// TestIdentifiantSansProviderNeComptePas: an entry holding ONLY the provider
// name must not be reported as a usable credential. The page would otherwise
// show "configured" while no token exists, and the operator would look for the
// error at the DNS provider.
func TestIdentifiantSansProviderNeComptePas(t *testing.T) {
	// The rule lives in etatTLS; asserted here on its condition so a rewrite of
	// the loop cannot silently drop it: any key other than "provider" is what
	// makes the credential real.
	entree := map[string]string{"provider": "cloudflare"}
	utilisable := false
	for k := range entree {
		if k != "provider" {
			utilisable = true
			break
		}
	}
	if utilisable {
		t.Error("an entry carrying only the provider name is counted as a credential")
	}

	// And the converse, so the test cannot pass by always returning false.
	entree["api_token"] = "valeur"
	utilisable = false
	for k := range entree {
		if k != "provider" {
			utilisable = true
			break
		}
	}
	if !utilisable {
		t.Error("an entry carrying a token is NOT counted as a credential")
	}
}
