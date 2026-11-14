// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the Nextcloud Mail side of an internal user's mailbox (§4.7,
// §9.J): the account is created with the positional arguments the Mail app
// expects, an account already carrying the address is adopted, and the deletion
// removes EVERY duplicate.
//
// WHY THESE TESTS EXIST: `occ mail:account:create-imap` fails on a wrong
// argument ORDER or on an SSL mode the app does not know, and the failure only
// shows up at runtime, in a user's mailbox, after the Stalwart account was
// already created. The argument list is therefore pinned verbatim. The adoption
// and duplicate assertions exist because the operation is replayed: creating a
// second Mail account for the same address makes the user's Inbox appear twice,
// and leaving a duplicate behind on deletion keeps a dead mailbox polled.
package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fauxOcc stands in for the `php occ` closure: it records every command and
// answers the export with the accounts a test seeded.
type fauxOcc struct {
	comptes []compteNextcloud
	appels  [][]string
	// echouer decides, per command line, whether the command fails.
	echouer func(args []string) error
	// exportPanne makes the export itself fail.
	exportPanne error
}

func (f *fauxOcc) occ(args ...string) (string, error) {
	f.appels = append(f.appels, args)
	if f.echouer != nil {
		if err := f.echouer(args); err != nil {
			return "", err
		}
	}
	switch args[0] {
	case "mail:account:export":
		if f.exportPanne != nil {
			return "", f.exportPanne
		}
		return exporterJSON(f.comptes), nil
	case "mail:account:create-imap":
		f.comptes = append(f.comptes, compteNextcloud{
			ID: len(f.comptes) + 1, Email: args[3], Name: args[2],
		})
		return "", nil
	case "mail:account:delete":
		return "", nil
	}
	return "", nil
}

// installerOcc substitutes the occ seam and restores it after the test.
func installerOcc(t *testing.T, f *fauxOcc) {
	t.Helper()
	remplacer(t, &commandeOcc, func(context.Context) (func(args ...string) (string, error), error) {
		return f.occ, nil
	})
}

// TestAssurerCompteNextcloudMailCreeAvecLesArgumentsAttendus pins the exact
// positional list: user, display name, address, then the SAME host and login
// twice with the SAME app password, `ssl` on both sides, and `password` as the
// authentication method.
func TestAssurerCompteNextcloudMailCreeAvecLesArgumentsAttendus(t *testing.T) {
	f := &fauxOcc{}
	installerOcc(t, f)

	err := AssurerCompteNextcloudMail(context.Background(), "alice", "Alice", "alice@example.com",
		"mail.example.com", "alice@ceffio.local", "secret")
	if err != nil {
		t.Fatalf("AssurerCompteNextcloudMail: %v", err)
	}
	if len(f.appels) != 2 {
		t.Fatalf("commands are %v, expected an export and one create", f.appels)
	}
	cree := f.appels[1]
	attendus := []string{
		"mail:account:create-imap",
		"alice", "Alice", "alice@example.com",
		"mail.example.com", portIMAP, modeSSL, "alice@ceffio.local", "secret",
		"mail.example.com", portSMTP, modeSSL, "alice@ceffio.local", "secret",
		methodeAuthCompte,
	}
	if strings.Join(cree, " ") != strings.Join(attendus, " ") {
		t.Errorf("create command is\n  %v\nexpected\n  %v", cree, attendus)
	}
}

// TestAssurerCompteNextcloudMailAdopteLeCompteExistant: an account already
// carrying the address is left alone, whatever the case of the address.
func TestAssurerCompteNextcloudMailAdopteLeCompteExistant(t *testing.T) {
	f := &fauxOcc{comptes: []compteNextcloud{{ID: 7, Email: "Alice@Example.com", Name: "Alice"}}}
	installerOcc(t, f)

	if err := AssurerCompteNextcloudMail(context.Background(), "alice", "Alice", "alice@example.com",
		"mail.example.com", "alice@ceffio.local", "secret"); err != nil {
		t.Fatalf("AssurerCompteNextcloudMail: %v", err)
	}
	for _, appel := range f.appels {
		if appel[0] == "mail:account:create-imap" {
			t.Fatalf("a second Mail account was created for the same address: %v", f.appels)
		}
	}
}

// TestAssurerCompteNextcloudMailIgnoreUneAutreAdresse: an account of the same
// user carrying ANOTHER address belongs to them, not to this feature; the
// platform address is still created.
func TestAssurerCompteNextcloudMailIgnoreUneAutreAdresse(t *testing.T) {
	f := &fauxOcc{comptes: []compteNextcloud{{ID: 1, Email: "alice@example.company", Name: "Work"}}}
	installerOcc(t, f)

	if err := AssurerCompteNextcloudMail(context.Background(), "alice", "Alice", "alice@example.com",
		"mail.example.com", "alice@ceffio.local", "secret"); err != nil {
		t.Fatalf("AssurerCompteNextcloudMail: %v", err)
	}
	if len(f.comptes) != 2 {
		t.Errorf("the platform account was not created: %v", f.comptes)
	}
}

// TestSupprimerCompteNextcloudMailSupprimeTousLesDoublons: every account
// carrying the address is deleted, and the user's other accounts are kept.
func TestSupprimerCompteNextcloudMailSupprimeTousLesDoublons(t *testing.T) {
	f := &fauxOcc{comptes: []compteNextcloud{
		{ID: 1, Email: "alice@example.com", Name: "Doublon"},
		{ID: 2, Email: "alice@example.com", Name: "Doublon"},
		{ID: 3, Email: "alice@example.company", Name: "Work"},
	}}
	installerOcc(t, f)

	if err := SupprimerCompteNextcloudMail(context.Background(), "alice", "alice@example.com"); err != nil {
		t.Fatalf("SupprimerCompteNextcloudMail: %v", err)
	}
	var supprimes []string
	for _, appel := range f.appels {
		if appel[0] == "mail:account:delete" {
			supprimes = append(supprimes, appel[1])
		}
	}
	if strings.Join(supprimes, ",") != "1,2" {
		t.Errorf("deleted accounts are %v, expected 1,2 (and not the user's other account)", supprimes)
	}
}

// TestSupprimerCompteNextcloudMailRapporteLaDerniereErreur: a failed deletion
// is reported so the caller can warn instead of claiming success.
func TestSupprimerCompteNextcloudMailRapporteLaDerniereErreur(t *testing.T) {
	f := &fauxOcc{comptes: []compteNextcloud{{ID: 1, Email: "alice@example.com"}}}
	f.echouer = func(args []string) error {
		if args[0] == "mail:account:delete" {
			return errors.New("exit status 2")
		}
		return nil
	}
	installerOcc(t, f)

	err := SupprimerCompteNextcloudMail(context.Background(), "alice", "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("expected the deletion error, got %v", err)
	}
}

// TestCompterNextcloudIgnoreLesLignesDeLog: `occ` prints bootstrap warnings on
// stdout before the JSON array, so the array is located rather than expected at
// the first byte.
func TestCompterNextcloudIgnoreLesLignesDeLog(t *testing.T) {
	occ := func(args ...string) (string, error) {
		return "Nextcloud is not installed - prints a warning\nAn uncaught error\n[" +
			`{"id":4,"email":"alice@example.com","name":"Alice"}` + "]", nil
	}
	comptes, err := compterNextcloud(context.Background(), occ, "alice")
	if err != nil {
		t.Fatalf("compterNextcloud: %v", err)
	}
	if len(comptes) != 1 || comptes[0].ID != 4 || comptes[0].Email != "alice@example.com" {
		t.Errorf("read accounts are %v, expected id 4 and alice@example.com", comptes)
	}
}

// TestCompterNextcloudRefuseUneSortieSansJSON: an export that holds no array is
// an error, not an empty list — otherwise a broken command would look like a
// user without accounts and the create step would duplicate one.
func TestCompterNextcloudRefuseUneSortieSansJSON(t *testing.T) {
	occ := func(args ...string) (string, error) { return "no json here", nil }
	if _, err := compterNextcloud(context.Background(), occ, "alice"); err == nil {
		t.Fatal("expected an error for an export without a JSON array")
	}
}

// exporterJSON renders the accounts the way `mail:account:export` does.
func exporterJSON(comptes []compteNextcloud) string {
	if len(comptes) == 0 {
		return "[]"
	}
	parties := make([]string, 0, len(comptes))
	for _, compte := range comptes {
		parties = append(parties, fmt.Sprintf(`{"id":%d,"email":%q,"name":%q}`, compte.ID, compte.Email, compte.Name))
	}
	return "[" + strings.Join(parties, ",") + "]"
}
