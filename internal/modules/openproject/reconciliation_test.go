// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/sso"
)

// TestComptesDuRealmIgnoreCeQuIlNePeutPasRepresenter: the reconciliation
// creates an account for every person of the realm and NOTHING for the rest —
// a client's service account, the administrator (step 6 decides it), a disabled
// identity. Each skip that costs a person their sign-in is SAID OUT LOUD,
// because the page they will land on names nothing.
func TestComptesDuRealmIgnoreCeQuIlNePeutPasRepresenter(t *testing.T) {
	var sortie bytes.Buffer
	comptes := comptesDuRealm([]sso.UtilisateurRealm{
		{Login: compteAdmin, Mail: mailAdmin, Enabled: true},
		{Login: "service-account-console", Mail: "", Enabled: true},
		{Login: "desactive", Mail: "desactive@example.org", Enabled: false},
		{Login: "a b", Mail: "a@example.org", Enabled: true},
		{Login: "sans.mail", Mail: "", Enabled: true},
		{Login: "amina", Mail: "amina@example.org", Enabled: true},
		{Login: "merouane.agar", Mail: "merouane@example.org", Enabled: true},
	}, &sortie)

	if len(comptes) != 2 {
		t.Fatalf("%d accounts kept (%+v), want 2", len(comptes), comptes)
	}
	if comptes[0].Login != "amina" || comptes[0].Mail != "amina@example.org" ||
		comptes[1].Login != "merouane.agar" {
		t.Errorf("unexpected accounts kept: %+v", comptes)
	}
	for _, nom := range []string{"desactive", "sans.mail"} {
		if !strings.Contains(sortie.String(), nom) {
			t.Errorf("the warning about %q is missing from:\n%s", nom, sortie.String())
		}
	}
	// THE SERVICE ACCOUNT AND THE ADMINISTRATOR ARE NOT WARNED ABOUT: there is
	// nothing to fix, and a wall of warnings hides the two that matter.
	for _, nom := range []string{"service-account-console", compteAdmin} {
		if strings.Contains(sortie.String(), nom) {
			t.Errorf("%q must be skipped silently:\n%s", nom, sortie.String())
		}
	}
}

// TestComptesDuRealmSansCompte: an empty realm is not an error, and the step
// says what it read instead of leaving a blank line.
func TestComptesDuRealmSansCompte(t *testing.T) {
	var sortie bytes.Buffer
	if comptes := comptesDuRealm(nil, &sortie); len(comptes) != 0 {
		t.Errorf("%d accounts kept from an empty realm", len(comptes))
	}
	if sortie.Len() != 0 {
		t.Errorf("an empty realm produced output: %q", sortie.String())
	}
}

// TestLeScriptDesComptesEstUnSeulPassage: the reconciliation ensures every
// account in ONE Rails boot, and writes the auth source ONCE — a source written
// per account would be a hundred redundant writes, and two different sources
// would split the accounts across two lookups.
func TestLeScriptDesComptesEstUnSeulPassage(t *testing.T) {
	s, err := scriptComptes([]compteOP{
		{Login: "amina", Mail: "amina@example.org"},
		{Login: "okba", Mail: "okba@example.org"},
	})
	if err != nil {
		t.Fatalf("rendering the batch script: %v", err)
	}
	if n := strings.Count(s, `find_or_initialize_by(name: "Ceffio SSO")`); n != 1 {
		t.Errorf("the auth source is initialised %d times, want 1:\n%s", n, s)
	}
	if n := strings.Count(s, "src.save!"); n != 1 {
		t.Errorf("the auth source is saved %d times, want 1:\n%s", n, s)
	}
	for _, attendu := range []string{
		"cs.each do |c|",   // one boot, one loop
		"rescue => e",      // one failure does not stop the others
		"echecs << (c[",    // the failure names the account
		"CEFFIO_ECHEC ",    // and is reported to the caller
		"CEFFIO_COMPTES ",  // with a summary
		`puts "CEFFIO_OK"`, // the marker every Rails call is checked against
		"<<~'CEFFIO'",      // the data cannot become Ruby code
		"src.onthefly_register = false",
	} {
		if !strings.Contains(s, attendu) {
			t.Errorf("the batch script lacks %q:\n%s", attendu, s)
		}
	}
	// EVERY ACCOUNT IS COUNTED ONCE, whichever branch it takes: a branch that
	// forgets its counter would report fewer accounts than the reconciliation
	// saw, and the installation would hide the difference.
	for _, compteur := range []string{"crees += 1", "presents += 1"} {
		if n := strings.Count(s, compteur); n != 1 {
			t.Errorf("%q appears %d times, want 1:\n%s", compteur, n, s)
		}
	}
	// THE AUTHENTICATION FILTER OF THE BATCH IS THE MODULE'S, not a second one:
	// a login outside the alphabet or without an address never reaches Ruby.
	if _, err := scriptComptes([]compteOP{{Login: "a b", Mail: "a@example.org"}}); err == nil {
		t.Error("an invalid login was accepted in a batch")
	}
	if _, err := scriptComptes([]compteOP{{Login: "okba"}}); err == nil {
		t.Error("an account without e-mail was accepted in a batch")
	}
	if _, err := scriptComptes(nil); err == nil {
		t.Error("an empty batch produced a script instead of refusing")
	}
}

// TestLireResumeComptes: the summary and the failures are read out of what the
// script printed, and ignored when absent — an installation that reports
// nothing must not invent a count.
func TestLireResumeComptes(t *testing.T) {
	sortie := `DEPRECATION WARNING: something
CEFFIO_ECHEC okba: Email has already been taken
CEFFIO_COMPTES created=1 present=3 failed=1
CEFFIO_OK
`
	resume, echecs := lireResumeComptes(sortie)
	if resume != "created=1 present=3 failed=1" {
		t.Errorf("summary read as %q", resume)
	}
	if len(echecs) != 1 || echecs[0] != "okba: Email has already been taken" {
		t.Errorf("failures read as %q", echecs)
	}

	if resume, echecs := lireResumeComptes("CEFFIO_OK\n"); resume != "" || len(echecs) != 0 {
		t.Errorf("a silent script reported %q / %q", resume, echecs)
	}
}

// TestLaSuppressionOuvreEtRefermeLeDroitDeSupprimer: OpenProject ships
// Setting.users_deletable_by_admins = false, and its delete contract checks it —
// so the account could never be deleted, with "may not be accessed." for the
// only explanation. The script opens the right for the call and RESTORES it,
// even when the deletion raises.
func TestLaSuppressionOuvreEtRefermeLeDroitDeSupprimer(t *testing.T) {
	s, err := scriptSuppression("merouane")
	if err != nil {
		t.Fatalf("rendering the deletion script: %v", err)
	}
	for _, attendu := range []string{
		"precedent = Setting.users_deletable_by_admins",
		"Setting.users_deletable_by_admins = true",
		"ensure",
		"Setting.users_deletable_by_admins = precedent",
		"Users::DeleteService.new(model: u, user: User.system)",
		`raise "deletion refused: #{r.errors.full_messages.join(', ')}" unless r.success?`,
		`puts "CEFFIO_OK"`,
	} {
		if !strings.Contains(s, attendu) {
			t.Errorf("the deletion script lacks %q:\n%s", attendu, s)
		}
	}
	// THE RESTORE MUST FOLLOW THE CALL, not precede it: a script that restores
	// before deleting would delete nothing and report success.
	if strings.Index(s, "Setting.users_deletable_by_admins = precedent") <
		strings.Index(s, "Users::DeleteService.new") {
		t.Error("the setting is restored before the deletion runs")
	}
	if _, err := scriptSuppression("a b"); err == nil {
		t.Error("an invalid login was accepted for deletion")
	}
}
