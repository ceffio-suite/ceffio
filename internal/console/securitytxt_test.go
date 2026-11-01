// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func servirSecurityTxt(t *testing.T, domaine string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Domain: domaine}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	return rec
}

// TestSecurityTxtSurLeDomaineDuProjet: the file the RFC asks for, with the
// fields a researcher and a scanner look for.
func TestSecurityTxtSurLeDomaineDuProjet(t *testing.T) {
	rec := servirSecurityTxt(t, DomaineDuProjet)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, expected 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, expected text/plain", ct)
	}
	corps := rec.Body.String()
	for _, attendu := range []string{
		"Contact: mailto:security@mandem-it.com",
		"Expires: ",
		"Preferred-Languages: ",
		"Canonical: https://ceffio.org/.well-known/security.txt",
		"Policy: https://github.com/ceffio-suite/ceffio/blob/main/SECURITY.md",
	} {
		if !strings.Contains(corps, attendu) {
			t.Errorf("the file does not contain %q:\n%s", attendu, corps)
		}
	}
}

// TestSecurityTxtAbsentChezLeClient: an installation on another domain runs
// somebody else's service; our contact is not theirs to publish.
func TestSecurityTxtAbsentChezLeClient(t *testing.T) {
	for _, domaine := range []string{"client.example", "cloud.entreprise.fr", "", "ceffio.org.evil.example"} {
		rec := servirSecurityTxt(t, domaine)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%q: status = %d, expected 404", domaine, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "security@mandem-it.com") {
			t.Errorf("%q: the contact leaked on a customer's installation", domaine)
		}
	}
}

// TestSecurityTxtNExpirePas: the RFC requires a future Expires, and a file that
// outlives its own date is worse than no file. This test fails the build a year
// before the deadline, so the renewal is planned, not discovered.
func TestSecurityTxtNExpirePas(t *testing.T) {
	rec := servirSecurityTxt(t, DomaineDuProjet)
	var brute string
	for _, ligne := range strings.Split(rec.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(ligne, "Expires: "); ok {
			brute = strings.TrimSpace(v)
		}
	}
	if brute == "" {
		t.Fatal("no Expires field")
	}
	quand, err := time.Parse(time.RFC3339, brute)
	if err != nil {
		t.Fatalf("Expires %q is not RFC 3339: %v", brute, err)
	}
	reste := time.Until(quand)
	// LE SEUIL N'EST PAS UN AN : un fichier qui expire dans un mois est déjà en
	// retard de renouvellement. À 300 jours, le build casse assez tôt pour
	// qu'on ait le temps de le refaire, et assez tard pour ne pas le faire
	// chaque semaine.
	if reste < 300*24*time.Hour {
		t.Fatalf("Expires is in %d days: renew %s (a stale security.txt is a lie)",
			int(reste.Hours()/24), brute)
	}
	// RFC 9116 recommande de ne pas dépasser un an : au-delà, la date n'est plus
	// une promesse, c'est un oubli.
	if reste > 366*24*time.Hour {
		t.Fatalf("Expires is in %d days: RFC 9116 recommends no more than a year", int(reste.Hours()/24))
	}
}
