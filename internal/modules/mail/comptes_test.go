// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the mail module's participation in the Users page (§4.7): the two
// fields it adds to the creation form, the order of the refusals, the
// provisioning it chains, and the actions it offers on an existing mailbox.
//
// WHY THESE TESTS EXIST: this file is the CONTRACT between the console and the
// mail server, and its failure modes are ordering bugs, not crashes. A refusal
// that runs after the Keycloak user was created leaves an account nobody can use
// and no mailbox behind; a provisioning that creates the Nextcloud Mail account
// before the app password stores a client row that can never authenticate; an
// `AccountInfos` that reads the server once per user turns a page load into
// dozens of JMAP calls. Every one of those behaves "fine" on a single user with
// a healthy server, which is exactly what a test must not assume.
package mail

import (
	"context"
	"errors"
	"strings"
	"testing"

	mailcore "github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// remplacerCompte swaps one seam for the duration of the test.
func remplacerCompte[T any](t *testing.T, cible *T, valeur T) {
	t.Helper()
	ancien := *cible
	*cible = valeur
	t.Cleanup(func() { *cible = ancien })
}

// fauxBoites is the mail server seen from the module: every account operation
// recorded, every answer seeded.
type fauxBoites struct {
	comptes []mailcore.CompteCourriel
	// pris maps an address to the account already holding it.
	pris map[string]string
	// checks is the answer of the checks tab.
	checks []module.Check
	// erreurs makes one seam fail, keyed by its name.
	erreurs map[string]error
	// appels records every seam call, in order.
	appels []string
	// lectures counts the account-list reads.
	lectures int
}

func nouveauFauxBoites() *fauxBoites {
	return &fauxBoites{pris: map[string]string{}, erreurs: map[string]error{}}
}

func (f *fauxBoites) note(appel string) error {
	f.appels = append(f.appels, appel)
	if err, ok := f.erreurs[appel[:strings.IndexByte(appel+":", ':')]]; ok {
		return err
	}
	return nil
}

func (f *fauxBoites) aEteAppele(methode string) bool {
	for _, appel := range f.appels {
		if strings.HasPrefix(appel, methode+":") {
			return true
		}
	}
	return false
}

// installerBoites replaces every seam of the module layer.
func installerBoites(t *testing.T, f *fauxBoites) {
	t.Helper()
	remplacerCompte(t, &lireComptesCourriel, func(context.Context) ([]mailcore.CompteCourriel, error) {
		f.lectures++
		return f.comptes, f.erreurs["lireComptesCourriel"]
	})
	remplacerCompte(t, &adressePriseCourriel, func(_ context.Context, adresse string) (string, bool, error) {
		f.appels = append(f.appels, "adressePriseCourriel:"+adresse)
		if err, ok := f.erreurs["adressePriseCourriel"]; ok {
			return "", false, err
		}
		titulaire, prise := f.pris[strings.ToLower(adresse)]
		return titulaire, prise, nil
	})
	remplacerCompte(t, &assurerCompteCourriel, func(_ context.Context, nom, domaine string, quota int) (mailcore.CompteCourriel, error) {
		f.appels = append(f.appels, "assurerCompteCourriel:"+nom+":"+domaine+":"+itoaTest(quota))
		if err, ok := f.erreurs["assurerCompteCourriel"]; ok {
			return mailcore.CompteCourriel{}, err
		}
		return mailcore.CompteCourriel{ID: "u-" + nom, Nom: nom, Domaine: mailcore.DomaineComptes, Adresse: nom + "@ceffio.local"}, nil
	})
	remplacerCompte(t, &assurerMotDePasseCompte, func(_ context.Context, nom, adresse, idCompte string) (string, error) {
		f.appels = append(f.appels, "assurerMotDePasseCompte:"+nom+":"+adresse+":"+idCompte)
		if err, ok := f.erreurs["assurerMotDePasseCompte"]; ok {
			return "", err
		}
		return "secret-de-" + nom, nil
	})
	remplacerCompte(t, &supprimerCompteCourriel, func(_ context.Context, nom string) error {
		f.appels = append(f.appels, "supprimerCompteCourriel:"+nom)
		return f.erreurs["supprimerCompteCourriel"]
	})
	remplacerCompte(t, &reglerQuotaCompte, func(_ context.Context, nom string, quota int) error {
		f.appels = append(f.appels, "reglerQuotaCompte:"+nom+":"+itoaTest(quota))
		return f.erreurs["reglerQuotaCompte"]
	})
	remplacerCompte(t, &suspendreCompte, func(_ context.Context, nom string) error {
		f.appels = append(f.appels, "suspendreCompte:"+nom)
		return f.erreurs["suspendreCompte"]
	})
	remplacerCompte(t, &reprendreCompte, func(_ context.Context, nom string) error {
		f.appels = append(f.appels, "reprendreCompte:"+nom)
		return f.erreurs["reprendreCompte"]
	})
	remplacerCompte(t, &assurerMailNextcloud, func(_ context.Context, utilisateur, nomAffiche, adresse, hote, login, motDePasse string) error {
		f.appels = append(f.appels, "assurerMailNextcloud:"+strings.Join([]string{utilisateur, nomAffiche, adresse, hote, login, motDePasse}, "|"))
		return f.erreurs["assurerMailNextcloud"]
	})
	remplacerCompte(t, &supprimerMailNextcloud, func(_ context.Context, utilisateur, adresse string) error {
		f.appels = append(f.appels, "supprimerMailNextcloud:"+utilisateur+":"+adresse)
		return f.erreurs["supprimerMailNextcloud"]
	})
	remplacerCompte(t, &checksMessagerie, func(context.Context, string) []module.Check {
		return f.checks
	})
}

// itoaTest formats the small integers the recorded calls carry.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	return string(chiffres)
}

// envCompte builds the Env of a user-creation request.
func envCompte(sortie *strings.Builder) module.Env {
	env := module.Env{Domain: "example.com", Out: sortie}
	return env
}

// utilisateur is a directory user as the console passes it.
func utilisateur(id, nom, email string) module.User {
	return module.User{ID: id, Username: nom, Email: email}
}

// --- Fields ---------------------------------------------------------------

// TestLesChampsDeCompteSontCeuxDuPlan: the two fields, their defaults, and the
// fact that the mailbox field REPLACES the email input (the address is built
// from the username, so letting the operator type both invites a mismatch).
func TestLesChampsDeCompteSontCeuxDuPlan(t *testing.T) {
	champs := (&mailModule{}).AccountFields(context.Background(), envCompte(&strings.Builder{}))
	if len(champs) != 2 {
		t.Fatalf("%d fields declared, expected the mailbox switch and the quota", len(champs))
	}
	boite, quota := champs[0], champs[1]
	if boite.Key != cleBoite || boite.Type != module.Bool || boite.Default != "true" || !boite.Required {
		t.Errorf("mailbox field is %+v, expected a required bool defaulting to true", boite.Field)
	}
	if !boite.ReplacesEmail {
		t.Error("the mailbox field does not replace the email input: the address is derived from the username")
	}
	if !strings.Contains(boite.Help, "example.com") {
		t.Errorf("the mailbox help does not name the domain: %q", boite.Help)
	}
	if quota.Key != cleQuotaGio || quota.Type != module.Number || quota.Default != "1" || !quota.Required {
		t.Errorf("quota field is %+v, expected a required number defaulting to the stored default", quota.Field)
	}
	if quota.ReplacesEmail {
		t.Error("the quota field replaces the email input, which it does not")
	}
}

// TestLeQuotaParDefautVientDesReglages: the form's default is the operator's
// stored default quota, not the built-in constant. Otherwise every user created
// from the page departs from the platform's own policy.
func TestLeQuotaParDefautVientDesReglages(t *testing.T) {
	store := nouveauMagasin(map[string]string{
		mailcore.CleServeur: `{"envoi":"direct","volume_gio":30,"quota_defaut_gio":3,"clients_externes":true}`,
	})
	champs := (&mailModule{}).AccountFields(context.Background(), module.Env{Domain: "example.com", Settings: store})
	if champs[1].Default != "3" {
		t.Errorf("default quota is %q, expected the stored 3", champs[1].Default)
	}
}

// TestLeQuotaParDefautTolereUnReglageIllisible: a broken setting falls back to
// the built-in default instead of failing the page — the quota is still bounded
// at validation.
func TestLeQuotaParDefautTolereUnReglageIllisible(t *testing.T) {
	store := nouveauMagasin(map[string]string{mailcore.CleServeur: `{not json`})
	champs := (&mailModule{}).AccountFields(context.Background(), module.Env{Domain: "example.com", Settings: store})
	if champs[1].Default != "1" {
		t.Errorf("default quota is %q, expected the built-in 1", champs[1].Default)
	}
}

// --- Validation -----------------------------------------------------------

// TestValidationRefuseUnNomLocalInvalide: every shape the mail server would
// accept and the address book would not, or that the server itself refuses, is
// caught before anything exists.
func TestValidationRefuseUnNomLocalInvalide(t *testing.T) {
	cas := map[string]string{
		"":                      "required",
		"Alice":                 "lower-case",
		".alice":                "starting and ending",
		"alice.":                "starting and ending",
		"-alice":                "starting and ending",
		"alice..bob":            "consecutive dots",
		"alice bob":             "lower-case letters",
		"alice+bob":             "lower-case letters",
		strings.Repeat("a", 65): "1 to 64 characters",
	}
	for nom, attendu := range cas {
		t.Run(nom, func(t *testing.T) {
			f := nouveauFauxBoites()
			installerBoites(t, f)
			err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
				utilisateur("id", nom, ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
			if err == nil {
				t.Fatalf("the username %q was accepted", nom)
			}
			if !errors.Is(err, module.ErrInvalidSettings) {
				t.Errorf("error is not ErrInvalidSettings: %v", err)
			}
			if !strings.Contains(err.Error(), attendu) {
				t.Errorf("error %q does not mention %q", err, attendu)
			}
			if len(f.appels) != 0 {
				t.Errorf("the server was called for an invalid username: %v", f.appels)
			}
		})
	}
}

// TestValidationRefuseUnNomReserve: `postmaster`, `abuse` and the other
// operational addresses are refused before the server is asked.
func TestValidationRefuseUnNomReserve(t *testing.T) {
	for nom := range nomsReserves {
		t.Run(nom, func(t *testing.T) {
			f := nouveauFauxBoites()
			installerBoites(t, f)
			err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
				utilisateur("id", nom, ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("the reserved name %q was not refused: %v", nom, err)
			}
		})
	}
}

// TestValidationRefuseUneAdresseDejaPrise: the collision is looked up on BOTH
// addresses of the user — the directory one and the public alias — because an
// address that is only an alias already receives somebody's mail.
func TestValidationRefuseUneAdresseDejaPrise(t *testing.T) {
	f := nouveauFauxBoites()
	f.pris["alice@example.com"] = "bob"
	installerBoites(t, f)
	err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
	if err == nil || !strings.Contains(err.Error(), "alice@example.com") || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("expected a refusal naming the address and its holder, got %v", err)
	}

	// The directory address is checked too, and before the public one.
	f2 := nouveauFauxBoites()
	f2.pris["alice@ceffio.local"] = "carol"
	installerBoites(t, f2)
	err = (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
	if err == nil || !strings.Contains(err.Error(), "alice@ceffio.local") {
		t.Fatalf("expected a refusal on the directory address, got %v", err)
	}
}

// TestValidationRefuseUnCheckBloquant: a blocking deployment problem (no MX,
// port 25 closed) is a reason NOT to create a mailbox, and the error lists the
// checks so the operator does not have to open the checks tab to know why.
func TestValidationRefuseUnCheckBloquant(t *testing.T) {
	f := nouveauFauxBoites()
	f.checks = []module.Check{
		{ID: "mx", Level: module.CheckBlocking, Detail: "no MX record for example.com"},
		{ID: "imaps", Level: module.CheckOK},
	}
	installerBoites(t, f)
	err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
	if err == nil || !strings.Contains(err.Error(), "mx") || !strings.Contains(err.Error(), "no MX record") {
		t.Fatalf("expected a refusal listing the blocking check, got %v", err)
	}
	if strings.Contains(err.Error(), "imaps") {
		t.Errorf("the error lists a passing check: %v", err)
	}
}

// TestValidationBorneLeQuotaParLeVolume: §4.7's rule, checked again here
// because the volume can have been shrunk since the user was created.
func TestValidationBorneLeQuotaParLeVolume(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	for _, quota := range []string{"0", "21", "1000"} {
		err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
			utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: quota})
		if err == nil || !strings.Contains(err.Error(), "between 1 and 20") {
			t.Errorf("the quota %s was not bounded by the volume: %v", quota, err)
		}
	}
	err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "1.5"})
	if err == nil || !strings.Contains(err.Error(), cleQuotaGio) {
		t.Errorf("a fractional quota was not refused as a field problem: %v", err)
	}
}

// TestValidationRefuseUneBoiteSansBooleenLisible: the switch is a bool, and a
// garbled value must not be read as "false" — or as "true".
func TestValidationRefuseUneBoiteSansBooleenLisible(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "yes"})
	if err == nil || !strings.Contains(err.Error(), "true or false") {
		t.Fatalf("expected a refusal naming the accepted values, got %v", err)
	}
}

// TestValidationAccepteUnUtilisateurExterne: without a mailbox the user keeps
// their own address, and no mail seam is called at all.
func TestValidationAccepteUnUtilisateurExterne(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	err := (&mailModule{}).ValidateAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", "alice@elsewhere.example"), module.Values{cleBoite: "false"})
	if err != nil {
		t.Fatalf("an external user with an outside address was refused: %v", err)
	}
	if len(f.appels) != 0 {
		t.Errorf("the mail server was called for an external user: %v", f.appels)
	}
}

// TestValidationRefuseUnExterneSansAdresseOuSurLeDomaine: an external user
// needs an address, and it cannot be on the platform domain — that domain is
// what internal mailboxes serve, and an address there that no mailbox owns
// receives nothing.
func TestValidationRefuseUnExterneSansAdresseOuSurLeDomaine(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	env := envCompte(&strings.Builder{})

	if err := (&mailModule{}).ValidateAccount(context.Background(), env,
		utilisateur("id", "alice", ""), module.Values{cleBoite: "false"}); err == nil ||
		!strings.Contains(err.Error(), "needs an email address") {
		t.Errorf("an external user without an address was accepted: %v", err)
	}
	if err := (&mailModule{}).ValidateAccount(context.Background(), env,
		utilisateur("id", "alice", "alice@example.com"), module.Values{cleBoite: "false"}); err == nil ||
		!strings.Contains(err.Error(), "platform domain") {
		t.Errorf("an external user on the platform domain was accepted: %v", err)
	}
}

// --- EnsureAccount --------------------------------------------------------

// TestEnsureAccountProvisionneDansLOrdre: the account, then its credential,
// then the Nextcloud Mail account that authenticates with it — with the LOGIN
// on the directory address and the ADDRESS SHOWN on the public one.
func TestEnsureAccountProvisionneDansLOrdre(t *testing.T) {
	t.Setenv("CEFFIO_MAIL_DOMAIN", "")
	f := nouveauFauxBoites()
	installerBoites(t, f)
	sortie := &strings.Builder{}

	res, err := (&mailModule{}).EnsureAccount(context.Background(), envCompte(sortie),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "2"})
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if res.Email != "alice@example.com" {
		t.Errorf("result email is %q, expected the public address", res.Email)
	}
	if res.Attributes[attributInterne] != valeurInterne {
		t.Errorf("attributes are %v, expected the internal marker", res.Attributes)
	}
	attendus := []string{
		"assurerCompteCourriel:alice:example.com:2",
		"assurerMotDePasseCompte:alice:alice@ceffio.local:u-alice",
		"assurerMailNextcloud:" + strings.Join([]string{
			"alice", "alice@example.com", "alice@example.com", "mail.example.com",
			"alice@ceffio.local", "secret-de-alice",
		}, "|"),
	}
	if strings.Join(f.appels, "\n") != strings.Join(attendus, "\n") {
		t.Errorf("calls are\n  %v\nexpected, in order\n  %v", f.appels, attendus)
	}
	if !strings.Contains(sortie.String(), "alice@example.com ready") {
		t.Errorf("the operation log does not say the mailbox is ready: %q", sortie.String())
	}
}

// TestEnsureAccountStoppeSiLeMotDePasseEchoue: no Nextcloud Mail account is
// created without a credential — a client row that can never authenticate is
// worse than no row, because it fails silently in the user's face.
func TestEnsureAccountStoppeSiLeMotDePasseEchoue(t *testing.T) {
	f := nouveauFauxBoites()
	f.erreurs["assurerMotDePasseCompte"] = errors.New("the vault is unavailable")
	installerBoites(t, f)

	_, err := (&mailModule{}).EnsureAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", ""), module.Values{cleBoite: "true", cleQuotaGio: "1"})
	if err == nil || !strings.Contains(err.Error(), "vault") {
		t.Fatalf("expected the credential error, got %v", err)
	}
	if f.aEteAppele("assurerMailNextcloud") {
		t.Error("a Nextcloud Mail account was created although the credential failed")
	}
}

// TestEnsureAccountSansBoiteNeProvisionneRien: an external user gets no
// mailbox, no marker, and no call.
func TestEnsureAccountSansBoiteNeProvisionneRien(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	res, err := (&mailModule{}).EnsureAccount(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("id", "alice", "alice@elsewhere.example"), module.Values{cleBoite: "false"})
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if res.Email != "" || len(res.Attributes) != 0 {
		t.Errorf("an external user got mailbox data: %+v", res)
	}
	if len(f.appels) != 0 {
		t.Errorf("the server was called for an external user: %v", f.appels)
	}
}

// --- AccountInfos ---------------------------------------------------------

// TestAccountInfosLitLeServeurUneFois: the page passes every user of the
// installation, and the answer must cost ONE server read — not one per user.
func TestAccountInfosLitLeServeurUneFois(t *testing.T) {
	f := nouveauFauxBoites()
	f.comptes = []mailcore.CompteCourriel{{
		ID: "u1", Nom: "alice", Adresse: "alice@example.com",
		Quota: 1 << 30, Utilise: 312 << 20,
	}}
	installerBoites(t, f)
	env := envCompte(&strings.Builder{})
	env.Domain = "example.com"
	users := []module.User{
		utilisateur("1", "alice", "alice@example.com"),
		{ID: "2", Username: "bob", Attributes: map[string]string{attributInterne: valeurInterne}},
		utilisateur("3", "carol", "carol@elsewhere.example"),
		utilisateur("4", "dave", "dave@example.com"),
	}

	infos, err := (&mailModule{}).AccountInfos(context.Background(), env, users)
	if err != nil {
		t.Fatalf("AccountInfos: %v", err)
	}
	if f.lectures != 1 {
		t.Errorf("the server was read %d time(s), expected exactly 1", f.lectures)
	}

	alice := infos["1"]
	if !alice.Present || alice.Suspended {
		t.Errorf("alice is %+v, expected present and active", alice)
	}
	if !strings.Contains(alice.Summary, "alice@example.com") ||
		!strings.Contains(alice.Summary, "312 MiB") || !strings.Contains(alice.Summary, "1.0 GiB") {
		t.Errorf("alice's summary %q does not show the address and the usage", alice.Summary)
	}
	if ids := idsActions(alice); strings.Join(ids, ",") != "suspend,quota,delete-mailbox" {
		t.Errorf("alice's actions are %v, expected suspend, quota, delete-mailbox", ids)
	}

	bob := infos["2"]
	if bob.Present {
		t.Error("bob reads as present although the server has no account")
	}
	if strings.Join(idsActions(bob), ",") != "recreate-mailbox" {
		t.Errorf("bob's actions are %v, expected the recreation", idsActions(bob))
	}
	if !strings.Contains(bob.Summary, "missing") {
		t.Errorf("bob's summary %q does not say the mailbox is missing", bob.Summary)
	}

	carol := infos["3"]
	if carol.Present || len(carol.Actions) != 0 {
		t.Errorf("an external user got mailbox state: %+v", carol)
	}

	dave := infos["4"]
	if dave.Present || strings.Join(idsActions(dave), ",") != "recreate-mailbox" {
		t.Errorf("a user whose address is on the platform domain was read as external: %+v", dave)
	}

	suspendu := nouveauFauxBoites()
	suspendu.comptes = []mailcore.CompteCourriel{{ID: "u2", Nom: "alice", Adresse: "alice@example.com", Suspendu: true}}
	installerBoites(t, suspendu)
	infosSuspendu, err := (&mailModule{}).AccountInfos(context.Background(), env, users[:1])
	if err != nil {
		t.Fatalf("AccountInfos: %v", err)
	}
	if !infosSuspendu["1"].Suspended || strings.Join(idsActions(infosSuspendu["1"]), ",") != "resume,quota,delete-mailbox" {
		t.Errorf("a suspended mailbox is %+v, expected the resume action first", infosSuspendu["1"])
	}
}

// idsActions is the action ids of one info, in declaration order.
func idsActions(info module.AccountInfo) []string {
	ids := make([]string, 0, len(info.Actions))
	for _, action := range info.Actions {
		ids = append(ids, action.ID)
	}
	return ids
}

// TestAccountInfosRefuseUneLectureEnEchec: a broken server read fails the call
// rather than reporting every user as external — which would offer "create a
// mailbox" on mailboxes that exist.
func TestAccountInfosRefuseUneLectureEnEchec(t *testing.T) {
	f := nouveauFauxBoites()
	f.erreurs["lireComptesCourriel"] = errors.New("connection refused")
	installerBoites(t, f)
	if _, err := (&mailModule{}).AccountInfos(context.Background(), envCompte(&strings.Builder{}),
		[]module.User{utilisateur("1", "alice", "")}); err == nil {
		t.Fatal("a failed read was reported as a list without accounts")
	}
}

// --- Actions --------------------------------------------------------------

// TestActionSuspendPuisReprend: the two actions act on the mailbox of the user
// and tolerate its absence, because the console calls every module for every
// user.
func TestActionSuspendPuisReprend(t *testing.T) {
	f := nouveauFauxBoites()
	f.comptes = []mailcore.CompteCourriel{{ID: "u1", Nom: "alice", Adresse: "alice@example.com"}}
	installerBoites(t, f)
	sortie := &strings.Builder{}
	env := envCompte(sortie)
	u := utilisateur("1", "alice", "")

	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "suspend", nil); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if strings.Join(f.appels, ",") != "suspendreCompte:alice" {
		t.Errorf("suspend calls are %v", f.appels)
	}
	if !strings.Contains(sortie.String(), "suspended") {
		t.Errorf("the log does not say the mailbox was suspended: %q", sortie.String())
	}

	f.appels = nil
	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "resume", nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if strings.Join(f.appels, ",") != "reprendreCompte:alice" {
		t.Errorf("resume calls are %v", f.appels)
	}

	f.appels = nil
	f.comptes = nil
	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "suspend", nil); err != nil {
		t.Fatalf("suspend without mailbox: %v", err)
	}
	if f.aEteAppele("suspendreCompte") {
		t.Error("a mailbox that does not exist was suspended")
	}
}

// TestActionQuotaBorneEtApplique: the quota action re-checks the volume bound
// and writes the new value.
func TestActionQuotaBorneEtApplique(t *testing.T) {
	f := nouveauFauxBoites()
	f.comptes = []mailcore.CompteCourriel{{ID: "u1", Nom: "alice", Adresse: "alice@example.com"}}
	installerBoites(t, f)
	env := envCompte(&strings.Builder{})
	u := utilisateur("1", "alice", "")

	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "quota", module.Values{cleBoite: "true", cleQuotaGio: "4"}); err != nil {
		t.Fatalf("quota: %v", err)
	}
	if strings.Join(f.appels, ",") != "reglerQuotaCompte:alice:4" {
		t.Errorf("quota calls are %v", f.appels)
	}

	f.appels = nil
	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "quota", module.Values{cleBoite: "true", cleQuotaGio: "21"}); err == nil {
		t.Fatal("a quota above the volume was accepted")
	}
	if len(f.appels) != 0 {
		t.Errorf("the server was called with an out-of-bound quota: %v", f.appels)
	}
}

// TestActionSupprimerLaBoite: both sides are removed, and the address is said
// to stay reserved (the marker and the email are the console's).
func TestActionSupprimerLaBoite(t *testing.T) {
	f := nouveauFauxBoites()
	f.comptes = []mailcore.CompteCourriel{{ID: "u1", Nom: "alice", Adresse: "alice@example.com"}}
	installerBoites(t, f)
	sortie := &strings.Builder{}
	env := envCompte(sortie)
	u := utilisateur("1", "alice", "")

	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "delete-mailbox", nil); err != nil {
		t.Fatalf("delete-mailbox: %v", err)
	}
	attendus := []string{"supprimerMailNextcloud:alice:alice@example.com", "supprimerCompteCourriel:alice"}
	if strings.Join(f.appels, ",") != strings.Join(attendus, ",") {
		t.Errorf("delete calls are %v, expected %v", f.appels, attendus)
	}
	if !strings.Contains(sortie.String(), "stays reserved") {
		t.Errorf("the log does not say the address stays reserved: %q", sortie.String())
	}

	// A FAILING NEXTCLOUD SIDE WARNS BUT DOES NOT BLOCK: the mailbox is the
	// object the address refers to, the Mail row is only a client of it.
	f.appels = nil
	f.erreurs["supprimerMailNextcloud"] = errors.New("occ failed")
	sortie.Reset()
	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "delete-mailbox", nil); err != nil {
		t.Fatalf("delete-mailbox with a failing Nextcloud side: %v", err)
	}
	if !strings.Contains(sortie.String(), "could not be removed") {
		t.Errorf("the Nextcloud failure was not reported as a warning: %q", sortie.String())
	}
	if !f.aEteAppele("supprimerCompteCourriel") {
		t.Error("the mailbox was not deleted because the Nextcloud side failed")
	}

	// AN ABSENT MAILBOX IS NOT AN ERROR: the deletion already happened, or
	// never had anything to delete.
	f.appels = nil
	f.comptes = nil
	if err := (&mailModule{}).AccountAction(context.Background(), env, u, "delete-mailbox", nil); err != nil {
		t.Fatalf("delete-mailbox without mailbox: %v", err)
	}
	if len(f.appels) != 0 {
		t.Errorf("a deletion was attempted on a mailbox that does not exist: %v", f.appels)
	}
}

// TestActionRecreerLaBoite: the recreation runs the same three steps as a
// creation, with a narrative that says it is a recreation.
func TestActionRecreerLaBoite(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	sortie := &strings.Builder{}
	err := (&mailModule{}).AccountAction(context.Background(), envCompte(sortie),
		utilisateur("1", "alice", ""), "recreate-mailbox", module.Values{cleQuotaGio: "2"})
	if err != nil {
		t.Fatalf("recreate-mailbox: %v", err)
	}
	if len(f.appels) != 3 || !strings.HasPrefix(f.appels[0], "assurerCompteCourriel:alice:example.com:2") {
		t.Errorf("recreation calls are %v, expected the three provisioning steps", f.appels)
	}
	if !strings.Contains(sortie.String(), "recreating") {
		t.Errorf("the log does not say the mailbox is being recreated: %q", sortie.String())
	}
}

// TestActionInconnueEstUneErreur: the page and the module disagreeing about an
// action id is a bug, and doing nothing would hide it behind a success.
func TestActionInconnueEstUneErreur(t *testing.T) {
	f := nouveauFauxBoites()
	installerBoites(t, f)
	err := (&mailModule{}).AccountAction(context.Background(), envCompte(&strings.Builder{}),
		utilisateur("1", "alice", ""), "archive-mailbox", nil)
	if err == nil || !strings.Contains(err.Error(), "archive-mailbox") {
		t.Fatalf("an unknown action was not refused: %v", err)
	}
}

// TestLesAppelsDeCycleDeVieDeleguent: the console's deactivation, reactivation
// and deletion paths go through the same mailbox operations as the page's own
// actions — one implementation, so a fix reaches both.
func TestLesAppelsDeCycleDeVieDeleguent(t *testing.T) {
	f := nouveauFauxBoites()
	f.comptes = []mailcore.CompteCourriel{{ID: "u1", Nom: "alice", Adresse: "alice@example.com"}}
	installerBoites(t, f)
	ctx := context.Background()
	env := envCompte(&strings.Builder{})
	u := utilisateur("1", "alice", "")
	m := &mailModule{}

	if err := m.SuspendAccount(ctx, env, u); err != nil {
		t.Fatalf("SuspendAccount: %v", err)
	}
	if err := m.ResumeAccount(ctx, env, u); err != nil {
		t.Fatalf("ResumeAccount: %v", err)
	}
	if err := m.DeleteAccount(ctx, env, u); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	attendus := "suspendreCompte:alice,reprendreCompte:alice,supprimerMailNextcloud:alice:alice@example.com,supprimerCompteCourriel:alice"
	if strings.Join(f.appels, ",") != attendus {
		t.Errorf("lifecycle calls are %v, expected %v", f.appels, attendus)
	}
}

// TestTailleLisible: the summary's human units. A wrong unit makes the page
// show a mailbox as full or as empty when it is neither.
func TestTailleLisible(t *testing.T) {
	cas := map[int64]string{
		0:          "0 B",
		512:        "512 B",
		1 << 20:    "1.0 MiB",
		10 << 20:   "10 MiB",
		312 << 20:  "312 MiB",
		1 << 30:    "1.0 GiB",
		3 << 30:    "3.0 GiB",
		1024 << 30: "1.0 TiB",
	}
	for octets, attendu := range cas {
		if rendu := tailleLisible(octets); rendu != attendu {
			t.Errorf("tailleLisible(%d) = %q, expected %q", octets, rendu, attendu)
		}
	}
}

// TestResumeCompteSansQuota: an account the SSO auto-provisioned has no quota
// yet; the summary must say so instead of "0 B / 0 B".
func TestResumeCompteSansQuota(t *testing.T) {
	rendu := resumeCompte(mailcore.CompteCourriel{Adresse: "alice@ceffio.local", Utilise: 0, Quota: 0})
	if !strings.Contains(rendu, "no quota") {
		t.Errorf("summary %q does not mention the missing quota", rendu)
	}
}
