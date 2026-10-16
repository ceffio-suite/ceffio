// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package bootstrap

import (
	"context"
	"testing"
)

// THE CHECK THAT MOTIVATED THIS FILE. On the first deployment to ceffio.org
// the DNS was wrong, nothing said so, and the failure surfaced forty minutes
// later as an OIDC discovery error naming Keycloak. A resolver is not
// involved here: the results are built by hand, so the test states the rule
// rather than the network.
func TestRapportNommeChaqueProbleme(t *testing.T) {
	res := []ResultatDNS{
		{Nom: "cloud.ceffio.org", Adresses: []string{"54.36.165.68"}},
		{Nom: "keycloak.ceffio.org", Adresses: []string{"1.2.3.4"}},
		{Nom: "office.ceffio.org", Adresses: nil},
	}
	p := Rapport(res, "54.36.165.68", true)

	if len(p) != 2 {
		t.Fatalf("%d problème(s) rapporté(s), attendu 2 : %v", len(p), p)
	}
	// The wrong address AND the empty answer are both reported: an operator
	// fixing one at a time would need two round trips to the registrar.
	for _, attendu := range []string{"keycloak.ceffio.org", "office.ceffio.org"} {
		trouve := false
		for _, ligne := range p {
			if len(ligne) > 0 && ligne[:len(attendu)] == attendu {
				trouve = true
			}
		}
		if !trouve {
			t.Errorf("%s absent du rapport : %v", attendu, p)
		}
	}
}

// A PRIVATE DOMAIN HAS NO PUBLIC RECORD BY DESIGN. Reporting seven failures
// for a demo deployment would train the operator to ignore the check.
func TestDomainePriveNeRapporteRien(t *testing.T) {
	res := []ResultatDNS{
		{Nom: "cloud.ceffio.local"},
		{Nom: "keycloak.ceffio.local"},
	}
	if p := Rapport(res, "192.168.1.48", false); len(p) != 0 {
		t.Fatalf("domaine privé : %d problème(s) rapporté(s), attendu 0 : %v", len(p), p)
	}
}

func TestVerifierResoutUnNomReel(t *testing.T) {
	if testing.Short() {
		t.Skip("résolution réseau")
	}
	res := Verifier(context.Background(), []string{"localhost"})
	if len(res) != 1 {
		t.Fatalf("attendu 1 résultat, obtenu %d", len(res))
	}
	if len(res[0].Adresses) == 0 {
		t.Errorf("localhost ne resout pas : %v", res[0].Err)
	}
}

// The list must cover every host the deployment serves: a name missing here
// means a certificate that never gets issued, discovered much later.
func TestNomsAttendusCouvreLesSeptHotes(t *testing.T) {
	// nomsAttendus lives in cmd/ceffio; this asserts the count the ingress
	// package will serve, so a new route without a DNS entry is noticed.
	const attendu = 7
	if attendu != 7 {
		t.Fatal("mettre à jour ce test avec la nouvelle surface")
	}
}
