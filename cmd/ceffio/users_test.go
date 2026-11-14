// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// WHY THESE TESTS EXIST
//
// `ceffio users` is the CLI command with the most irreversible effects: it
// creates accounts in two directories, writes to the platform directory, and
// deletes mailboxes. Its value is not what it prints but WHEN it does each
// thing — a command that deleted the Keycloak account first and the mailboxes
// afterwards would look identical in a terminal and lose data on every failure.
//
// So these tests assert the CALL SEQUENCE, not only the output: the operations
// against Keycloak and Nextcloud are seams (users_admin.go), and a fake module
// records the calls the command makes on the account contract. The refusals are
// checked with the same instruments: each of them must happen while the journal
// is EMPTY, which is the only way to prove that "refused before creating
// anything" is true rather than merely intended.
//
// The script-building helpers are not asserted as text: a test that matched
// kcadm arguments would pass while the command created the wrong user. The two
// tests at the bottom of this file do check the real Keycloak functions, because
// the adoption of an existing account and the merge of its attributes are
// behaviours a fake cannot vouch for.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// journal records the calls the command makes, in order.
type journal struct {
	appels []string
}

func (j *journal) noter(format string, args ...any) {
	j.appels = append(j.appels, fmt.Sprintf(format, args...))
}

// verifierAppels asserts the exact call sequence.
func verifierAppels(t *testing.T, j *journal, attendus ...string) {
	t.Helper()
	if len(j.appels) != len(attendus) {
		t.Fatalf("call sequence:\n got: %v\nwant: %v", j.appels, attendus)
	}
	for i := range attendus {
		if j.appels[i] != attendus[i] {
			t.Fatalf("call %d is %q, want %q\nfull sequence:\n got: %v\nwant: %v",
				i, j.appels[i], attendus[i], j.appels, attendus)
		}
	}
}

// verifierAucunAppel asserts that nothing was called: the proof a refusal
// happened before any creation, deletion or even lookup.
func verifierAucunAppel(t *testing.T, j *journal) {
	t.Helper()
	if len(j.appels) != 0 {
		t.Fatalf("no call expected, got: %v", j.appels)
	}
}

// ---------------------------------------------------------------------------
// fakes

// fauxModule is a module that manages accounts and records every contract call.
type fauxModule struct {
	id    string
	titre string
	etat  module.Status

	champs   []module.AccountField
	resultat module.AccountResult
	infos    map[string]module.AccountInfo

	refusValidation error
	refusEnsure     error
	refusInfos      error
	refusAction     error
	refusSuspendre  error
	refusSupprimer  error

	journal         *journal
	valeursVues     module.Values
	utilisateursVus []module.User
}

func (f *fauxModule) Info() module.Info { return module.Info{ID: f.id, Title: f.titre} }

func (f *fauxModule) Install(context.Context, module.Env) error { return nil }

func (f *fauxModule) State(context.Context, module.Env) module.State {
	return module.State{Status: f.etat}
}

func (f *fauxModule) Uninstall(context.Context, module.Env) error { return nil }

func (f *fauxModule) AccountFields(context.Context, module.Env) []module.AccountField {
	return f.champs
}

func (f *fauxModule) ValidateAccount(_ context.Context, _ module.Env, u module.User, v module.Values) error {
	f.journal.noter("%s.validate", f.id)
	f.valeursVues = v
	f.utilisateursVus = append(f.utilisateursVus, u)
	return f.refusValidation
}

func (f *fauxModule) EnsureAccount(_ context.Context, _ module.Env, u module.User, v module.Values) (module.AccountResult, error) {
	f.journal.noter("%s.ensure", f.id)
	f.utilisateursVus = append(f.utilisateursVus, u)
	if f.refusEnsure != nil {
		return module.AccountResult{}, f.refusEnsure
	}
	return f.resultat, nil
}

func (f *fauxModule) AccountInfos(_ context.Context, _ module.Env, users []module.User) (map[string]module.AccountInfo, error) {
	f.journal.noter("%s.infos", f.id)
	if f.refusInfos != nil {
		return nil, f.refusInfos
	}
	return f.infos, nil
}

func (f *fauxModule) AccountAction(_ context.Context, _ module.Env, _ module.User, action string, v module.Values) error {
	f.journal.noter("%s.action:%s", f.id, action)
	f.valeursVues = v
	return f.refusAction
}

func (f *fauxModule) SuspendAccount(context.Context, module.Env, module.User) error {
	f.journal.noter("%s.suspend", f.id)
	return f.refusSuspendre
}

func (f *fauxModule) ResumeAccount(context.Context, module.Env, module.User) error {
	f.journal.noter("%s.resume", f.id)
	return f.refusSuspendre
}

func (f *fauxModule) DeleteAccount(context.Context, module.Env, module.User) error {
	f.journal.noter("%s.delete", f.id)
	return f.refusSupprimer
}

// fauxSansComptes is an installed module that does NOT manage accounts: it must
// be invisible to the users commands, not an error.
type fauxSansComptes struct {
	id   string
	etat module.Status
}

func (f *fauxSansComptes) Info() module.Info                         { return module.Info{ID: f.id, Title: f.id} }
func (f *fauxSansComptes) Install(context.Context, module.Env) error { return nil }
func (f *fauxSansComptes) Uninstall(context.Context, module.Env) error {
	return nil
}
func (f *fauxSansComptes) State(context.Context, module.Env) module.State {
	return module.State{Status: f.etat}
}

// fauxRepertoire keeps the platform accounts in memory and records the calls.
//
// It replaces BOTH directories (Keycloak and Nextcloud) on purpose: the tests
// are about the ordering between them, and two separate fakes would let a test
// forget one — the journal would then show a sequence that looks right while
// the command skipped a directory.
type fauxRepertoire struct {
	journal         *journal
	comptes         map[string]comptePlateforme // key: lowercase username
	motsDePasse     map[string]string           // username -> password set at creation
	dernierResultat module.AccountResult

	refusCreer              error
	refusActiver            error
	refusSupprimer          error
	refusNextcloudCreer     error
	refusNextcloudActiver   error
	refusNextcloudSupprimer error
	refusNextcloudEmail     error
}

func nouveauFauxRepertoire(j *journal, comptes ...comptePlateforme) *fauxRepertoire {
	r := &fauxRepertoire{
		journal:     j,
		comptes:     make(map[string]comptePlateforme, len(comptes)),
		motsDePasse: map[string]string{},
	}
	for _, c := range comptes {
		r.comptes[strings.ToLower(c.Username)] = c
	}
	return r
}

func (r *fauxRepertoire) lister(context.Context) ([]comptePlateforme, error) {
	r.journal.noter("kc.list")
	out := make([]comptePlateforme, 0, len(r.comptes))
	for _, c := range r.comptes {
		out = append(out, c)
	}
	return out, nil
}

func (r *fauxRepertoire) parNom(_ context.Context, nom string) (comptePlateforme, bool, error) {
	r.journal.noter("kc.get:%s", nom)
	c, existe := r.comptes[strings.ToLower(strings.TrimSpace(nom))]
	return c, existe, nil
}

func (r *fauxRepertoire) creer(_ context.Context, u module.User, mdp string) (comptePlateforme, error) {
	r.journal.noter("kc.create:%s", u.Username)
	if r.refusCreer != nil {
		return comptePlateforme{}, r.refusCreer
	}
	// The production function adopts an existing account instead of failing:
	// the fake does the same so a test of a retry sees the real behaviour.
	if c, existe := r.comptes[strings.ToLower(u.Username)]; existe {
		return c, nil
	}
	c := comptePlateforme{
		User:  module.User{ID: "id-" + u.Username, Username: u.Username, Email: u.Email},
		Actif: true,
	}
	r.comptes[strings.ToLower(u.Username)] = c
	r.motsDePasse[u.Username] = mdp
	return c, nil
}

func (r *fauxRepertoire) activer(_ context.Context, u module.User, actif bool) error {
	r.journal.noter("kc.enabled:%s:%t", u.Username, actif)
	return r.refusActiver
}

func (r *fauxRepertoire) supprimer(_ context.Context, u module.User) error {
	r.journal.noter("kc.delete:%s", u.Username)
	if r.refusSupprimer != nil {
		return r.refusSupprimer
	}
	delete(r.comptes, strings.ToLower(u.Username))
	return nil
}

func (r *fauxRepertoire) ecrire(_ context.Context, u module.User, res module.AccountResult) error {
	r.journal.noter("kc.write:%s", u.Username)
	r.dernierResultat = res
	if c, existe := r.comptes[strings.ToLower(u.Username)]; existe && res.Email != "" {
		c.Email = res.Email
		r.comptes[strings.ToLower(u.Username)] = c
	}
	return nil
}

func (r *fauxRepertoire) ncCreer(_ context.Context, identifiant, mdp string) error {
	r.journal.noter("nc.create:%s", identifiant)
	r.motsDePasse[identifiant] = mdp
	return r.refusNextcloudCreer
}

func (r *fauxRepertoire) ncActiver(_ context.Context, identifiant string, actif bool) error {
	r.journal.noter("nc.enabled:%s:%t", identifiant, actif)
	return r.refusNextcloudActiver
}

func (r *fauxRepertoire) ncSupprimer(_ context.Context, identifiant string) error {
	r.journal.noter("nc.delete:%s", identifiant)
	return r.refusNextcloudSupprimer
}

func (r *fauxRepertoire) ncEcrireEmail(_ context.Context, identifiant, email string) error {
	r.journal.noter("nc.email:%s:%s", identifiant, email)
	return r.refusNextcloudEmail
}

// ---------------------------------------------------------------------------
// fixtures

// installerModules replaces the registry and the module environment for one
// test, and restores them afterwards.
//
// The environment is stubbed as well: the production builder reads the cluster,
// and a unit test must never need one.
func installerModules(t *testing.T, modules ...module.Module) {
	t.Helper()
	anciensModules, ancienEnv := modulesAll, envPourModule
	t.Cleanup(func() {
		modulesAll, envPourModule = anciensModules, ancienEnv
	})
	modulesAll = func() []module.Module { return modules }
	envPourModule = func(domain, id string) module.Env {
		return module.Env{Domain: domain, ModuleID: id}
	}
}

// brancherRepertoire replaces every directory operation for one test.
func brancherRepertoire(t *testing.T, r *fauxRepertoire) {
	t.Helper()
	ancienLister, ancienParNom, ancienCreer := keycloakLister, keycloakParNom, keycloakCreer
	ancienActiver, ancienSupprimer, ancienEcrire := keycloakActiver, keycloakSupprimer, keycloakEcrire
	ancienNcCreer, ancienNcActiver := nextcloudCreer, nextcloudActiver
	ancienNcSupprimer, ancienNcEmail := nextcloudSupprimer, nextcloudEcrireEmail
	t.Cleanup(func() {
		keycloakLister, keycloakParNom, keycloakCreer = ancienLister, ancienParNom, ancienCreer
		keycloakActiver, keycloakSupprimer, keycloakEcrire = ancienActiver, ancienSupprimer, ancienEcrire
		nextcloudCreer, nextcloudActiver = ancienNcCreer, ancienNcActiver
		nextcloudSupprimer, nextcloudEcrireEmail = ancienNcSupprimer, ancienNcEmail
	})
	keycloakLister = r.lister
	keycloakParNom = r.parNom
	keycloakCreer = r.creer
	keycloakActiver = r.activer
	keycloakSupprimer = r.supprimer
	keycloakEcrire = r.ecrire
	nextcloudCreer = r.ncCreer
	nextcloudActiver = r.ncActiver
	nextcloudSupprimer = r.ncSupprimer
	nextcloudEcrireEmail = r.ncEcrireEmail
}

// executerUsers executes `ceffio users …` and returns what the operator reads.
func executerUsers(t *testing.T, entree string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newUsersCmd()
	var sortie, erreur bytes.Buffer
	cmd.SetOut(&sortie)
	cmd.SetErr(&erreur)
	cmd.SetIn(strings.NewReader(entree))
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return sortie.String(), erreur.String(), err
}

// moduleMail is the fake account module every creation test uses.
func moduleMail(j *journal) *fauxModule {
	return &fauxModule{
		id:    "mail",
		titre: "Mail",
		etat:  module.Installed,
		champs: []module.AccountField{
			{Field: module.Field{Key: "boite", Type: module.Bool, Default: "true"}, ReplacesEmail: true},
			{Field: module.Field{Key: "quota_gio", Type: module.Number, Default: "2"}},
		},
		resultat: module.AccountResult{
			Email:      "alice@test.example",
			Attributes: map[string]string{"ceffio_kind": "internal"},
		},
		infos:   map[string]module.AccountInfo{},
		journal: j,
	}
}

// ---------------------------------------------------------------------------
// creation

func TestAjouterUtilisateurOrdonneValidationCreationEtEcriture(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	installerModules(t, mail)
	repertoire := nouveauFauxRepertoire(j)
	brancherRepertoire(t, repertoire)

	sortie, _, err := executerUsers(t, "", "add", "alice",
		"--email", "perso@example.org", "--set", "mail.quota_gio=5")
	if err != nil {
		t.Fatalf("add must succeed: %v", err)
	}

	// THE ORDER IS THE CONTRACT: every module validates first, then the
	// platform accounts exist, then the module provisions, then the result is
	// written back to the directory.
	verifierAppels(t, j,
		"mail.validate",
		"kc.create:alice",
		"nc.create:alice",
		"mail.ensure",
		"kc.write:alice",
		"nc.email:alice:alice@test.example",
	)

	// The module owns the address (ReplacesEmail), so --email is ignored: the
	// directory account is created without an address and receives the
	// module's one at write-back.
	if got := repertoire.comptes["alice"].Email; got != "alice@test.example" {
		t.Fatalf("Keycloak account email after write-back is %q, want the module's address %q",
			got, "alice@test.example")
	}
	if len(mail.utilisateursVus) == 0 || mail.utilisateursVus[0].Email != "" {
		t.Fatalf("validation received email %q, want it empty (a module owns the address)",
			premierEmail(mail.utilisateursVus))
	}

	// Defaults first, then the override: the module declared 2 GiB, the operator
	// asked for 5.
	if got := mail.valeursVues["quota_gio"]; got != "5" {
		t.Fatalf("quota_gio sent to the module is %q, want %q", got, "5")
	}
	if got := mail.valeursVues["boite"]; got != "true" {
		t.Fatalf("boite sent to the module is %q, want its declared default %q", got, "true")
	}

	if !strings.Contains(sortie, `User "alice" created`) {
		t.Fatalf("output does not announce the creation:\n%s", sortie)
	}
	if !strings.Contains(sortie, "Password (generated, shown once)") {
		t.Fatalf("output does not show the generated password:\n%s", sortie)
	}
}

// premierEmail returns the address the module was given, for a failure message.
func premierEmail(users []module.User) string {
	if len(users) == 0 {
		return "(no call)"
	}
	return users[0].Email
}

func TestAjouterUtilisateurRefuseLesSetInvalidesAvantToutAppel(t *testing.T) {
	cas := []struct {
		nom     string
		set     string
		attendu string
	}{
		{"module inconnu", "mystere.boite=true", `module "mystere" does not take part in user creation`},
		{"cle inconnue", "mail.quota_go=5", `unknown field "quota_go"`},
		{"forme invalide", "mail=5", "expected MODULE.KEY=VALUE"},
		{"sans signe egal", "mail.boite", "expected MODULE.KEY=VALUE"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			j := &journal{}
			installerModules(t, moduleMail(j))
			brancherRepertoire(t, nouveauFauxRepertoire(j))

			_, _, err := executerUsers(t, "", "add", "alice", "--set", c.set)
			if err == nil {
				t.Fatalf("add with --set %q must be refused", c.set)
			}
			if !strings.Contains(err.Error(), c.attendu) {
				t.Fatalf("error %q does not contain %q", err, c.attendu)
			}
			// THE WHOLE POINT: a bad value costs a message, not an account.
			verifierAucunAppel(t, j)
		})
	}
}

func TestAjouterUtilisateurRefuseUneValidationDeModule(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.refusValidation = errors.New("quota above the server limit")
	installerModules(t, mail)
	brancherRepertoire(t, nouveauFauxRepertoire(j))

	_, _, err := executerUsers(t, "", "add", "alice")
	if err == nil || !strings.Contains(err.Error(), "quota above the server limit") {
		t.Fatalf("add must report the module's refusal, got: %v", err)
	}
	// Validation happens BEFORE Keycloak: nothing was created.
	verifierAppels(t, j, "mail.validate")
}

func TestAjouterUtilisateurContinueQuandNextcloudEchoue(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleMail(j))
	repertoire := nouveauFauxRepertoire(j)
	repertoire.refusNextcloudCreer = errors.New("no Nextcloud pod")
	brancherRepertoire(t, repertoire)

	_, erreur, err := executerUsers(t, "", "add", "alice")
	if err != nil {
		t.Fatalf("a Nextcloud failure must not fail the creation (the directory account exists): %v", err)
	}
	if !strings.Contains(erreur, "its Nextcloud account does not") {
		t.Fatalf("the Nextcloud failure must be reported on stderr, got: %q", erreur)
	}
	if _, existe := repertoire.comptes["alice"]; !existe {
		t.Fatal("the Keycloak account must exist")
	}
}

func TestAjouterUtilisateurSignaleCeQuiExisteQuandUneProvisionEchoue(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.refusEnsure = errors.New("mailbox service unavailable")
	installerModules(t, mail)
	brancherRepertoire(t, nouveauFauxRepertoire(j))

	_, _, err := executerUsers(t, "", "add", "alice")
	if err == nil {
		t.Fatal("a module provisioning failure must fail the command")
	}
	for _, attendu := range []string{`user "alice" created`, "mailbox service unavailable", "run the same command again"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Fatalf("error %q does not contain %q", err, attendu)
		}
	}
}

func TestAjouterUtilisateurLitLeMotDePasseSurEntreeStandard(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleMail(j))
	repertoire := nouveauFauxRepertoire(j)
	brancherRepertoire(t, repertoire)

	sortie, _, err := executerUsers(t, "s3cret-choisi\n", "add", "alice", "--password", "-")
	if err != nil {
		t.Fatalf("add with --password - must succeed: %v", err)
	}
	if got := repertoire.motsDePasse["alice"]; got != "s3cret-choisi" {
		t.Fatalf("password set in the directory is %q, want the one read on stdin", got)
	}
	if strings.Contains(sortie, "s3cret-choisi") {
		t.Fatalf("the password read from stdin must not be echoed back:\n%s", sortie)
	}
	if strings.Contains(sortie, "Password (generated") {
		t.Fatalf("no password must be generated when one was provided:\n%s", sortie)
	}
}

// ---------------------------------------------------------------------------
// protected account and confirmations

func TestLesGestesRefusentLeCompteDAdministration(t *testing.T) {
	cas := []struct {
		nom  string
		args []string
	}{
		{"creation", []string{"add", "AdminCeffio"}},
		{"desactivation", []string{"deactivate", "adminceffio"}},
		{"reactivation", []string{"reactivate", "AdminCeffio"}},
		{"suppression", []string{"delete", "adminceffio", "--confirm", "adminceffio"}},
		{"action de module", []string{"account", "adminceffio", "mail", "vider"}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			j := &journal{}
			installerModules(t, moduleMail(j))
			brancherRepertoire(t, nouveauFauxRepertoire(j))

			_, _, err := executerUsers(t, "", c.args...)
			if err == nil {
				t.Fatalf("%v must be refused on the administration account", c.args)
			}
			if !strings.Contains(err.Error(), "administration account") {
				t.Fatalf("error %q does not name the administration account", err)
			}
			verifierAucunAppel(t, j)
		})
	}
}

func TestSupprimerUtilisateurExigeLeNomTape(t *testing.T) {
	alice := comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true}
	cas := []struct {
		nom     string
		args    []string
		attendu string
	}{
		{"confirmation absente", []string{"delete", "alice"}, "irreversible"},
		{"confirmation differente", []string{"delete", "alice", "--confirm", "bob"},
			`type the username "alice"`},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			j := &journal{}
			installerModules(t, moduleMail(j))
			brancherRepertoire(t, nouveauFauxRepertoire(j, alice))

			_, _, err := executerUsers(t, "", c.args...)
			if err == nil {
				t.Fatalf("%v must be refused", c.args)
			}
			if !strings.Contains(err.Error(), c.attendu) {
				t.Fatalf("error %q does not contain %q", err, c.attendu)
			}
			// The confirmation is checked BEFORE the lookup: a typo must not
			// cost a single request, let alone a destructive one.
			verifierAucunAppel(t, j)
		})
	}
}

// ---------------------------------------------------------------------------
// deletion and lifecycle

func TestSupprimerUtilisateurSupprimeLesModulesPuisNextcloudPuisKeycloak(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleMail(j))
	repertoire := nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true})
	brancherRepertoire(t, repertoire)

	sortie, _, err := executerUsers(t, "", "delete", "alice", "--confirm", "alice")
	if err != nil {
		t.Fatalf("delete must succeed: %v", err)
	}
	// Modules FIRST: once the directory account is gone, nothing can reach what
	// they own.
	verifierAppels(t, j, "kc.get:alice", "mail.delete", "nc.delete:alice", "kc.delete:alice")
	if !strings.Contains(sortie, `User "alice" and all its accounts deleted`) {
		t.Fatalf("output does not announce the deletion:\n%s", sortie)
	}
}

func TestSupprimerUtilisateurGardeLeCompteSiUnModuleEchoue(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.refusSupprimer = errors.New("mailbox busy")
	installerModules(t, mail)
	repertoire := nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true})
	brancherRepertoire(t, repertoire)

	_, _, err := executerUsers(t, "", "delete", "alice", "--confirm", "alice")
	if err == nil {
		t.Fatal("a module deletion failure must fail the command")
	}
	if !strings.Contains(err.Error(), "platform account was kept") {
		t.Fatalf("error %q does not say the account was kept", err)
	}
	// The account is kept, and nothing after the module was attempted: the
	// operator can run the command again.
	verifierAppels(t, j, "kc.get:alice", "mail.delete")
	if _, existe := repertoire.comptes["alice"]; !existe {
		t.Fatal("the platform account must be kept when a module fails")
	}
}

func TestDesactiverEtReactiverUtilisateurOrdreEtSuspendre(t *testing.T) {
	cas := []struct {
		nom      string
		args     []string
		actif    bool
		contrat  string
		sortieAt string
	}{
		{"desactivation", []string{"deactivate", "alice"}, false, "mail.suspend", `"alice" deactivated`},
		{"reactivation", []string{"reactivate", "alice"}, true, "mail.resume", `"alice" reactivated`},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			j := &journal{}
			installerModules(t, moduleMail(j))
			brancherRepertoire(t, nouveauFauxRepertoire(j,
				comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true}))

			sortie, _, err := executerUsers(t, "", c.args...)
			if err != nil {
				t.Fatalf("%v must succeed: %v", c.args, err)
			}
			// The directory first (it decides whether a session is possible),
			// then Nextcloud, then the modules.
			verifierAppels(t, j,
				"kc.get:alice",
				fmt.Sprintf("kc.enabled:alice:%t", c.actif),
				fmt.Sprintf("nc.enabled:alice:%t", c.actif),
				c.contrat,
			)
			if !strings.Contains(sortie, c.sortieAt) {
				t.Fatalf("output does not announce the gesture:\n%s", sortie)
			}
		})
	}
}

func TestReactiverUtilisateurSignaleLesModulesQuiRestentSuspendus(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.refusSuspendre = errors.New("mailbox still locked")
	installerModules(t, mail)
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: false}))

	_, _, err := executerUsers(t, "", "reactivate", "alice")
	if err == nil {
		t.Fatal("a module refusal must be reported")
	}
	if !strings.Contains(err.Error(), "mailbox still locked") || !strings.Contains(err.Error(), "run the same command again") {
		t.Fatalf("error %q must name the module failure and say the command converges", err)
	}
}

// ---------------------------------------------------------------------------
// module actions

func moduleAvecAction(j *journal) *fauxModule {
	m := moduleMail(j)
	m.infos = map[string]module.AccountInfo{
		"id-alice": {
			Present: true,
			Actions: []module.AccountAction{{
				ID:      "vider",
				Label:   "Vider la boîte",
				Confirm: "alice",
				Fields:  []module.Field{{Key: "quota_gio", Type: module.Number, Default: "2"}},
			}},
		},
	}
	return m
}

func TestExecuterActionCompteRefuseUnModuleInconnu(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleAvecAction(j))
	brancherRepertoire(t, nouveauFauxRepertoire(j))

	_, _, err := executerUsers(t, "", "account", "alice", "mystere", "vider")
	if err == nil {
		t.Fatal("an unknown module must be refused")
	}
	if !strings.Contains(err.Error(), `module "mystere" does not manage user accounts`) {
		t.Fatalf("error %q does not name the unknown module", err)
	}
	verifierAucunAppel(t, j)
}

func TestExecuterActionCompteRefuseUneActionNonOfferte(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleAvecAction(j))
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true}))

	_, _, err := executerUsers(t, "", "account", "alice", "mail", "supprimer-tout")
	if err == nil {
		t.Fatal("an action the module does not offer must be refused")
	}
	for _, attendu := range []string{
		`offers no action "supprimer-tout"`,
		"it offers: vider", // discoverability: the operator learns what exists
	} {
		if !strings.Contains(err.Error(), attendu) {
			t.Fatalf("error %q does not contain %q", err, attendu)
		}
	}
}

func TestExecuterActionCompteExigeLaConfirmationDeclaree(t *testing.T) {
	j := &journal{}
	installerModules(t, moduleAvecAction(j))
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true}))

	_, _, err := executerUsers(t, "", "account", "alice", "mail", "vider")
	if err == nil {
		t.Fatal("an action requiring a confirmation must be refused without it")
	}
	if !strings.Contains(err.Error(), `type "alice" to confirm`) {
		t.Fatalf("error %q does not ask for the declared confirmation", err)
	}
}

func TestExecuterActionCompteTransmetLesValeurs(t *testing.T) {
	j := &journal{}
	mail := moduleAvecAction(j)
	installerModules(t, mail)
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice"}, Actif: true}))

	sortie, _, err := executerUsers(t, "", "account", "alice", "mail", "vider", "--confirm", "alice",
		"--set", "quota_gio=5")
	if err != nil {
		t.Fatalf("the action must succeed: %v", err)
	}
	verifierAppels(t, j, "kc.get:alice", "mail.infos", "mail.action:vider")
	if got := mail.valeursVues["quota_gio"]; got != "5" {
		t.Fatalf("quota_gio sent to the action is %q, want %q", got, "5")
	}
	if !strings.Contains(sortie, `Action "vider" done`) {
		t.Fatalf("output does not announce the action:\n%s", sortie)
	}
}

// ---------------------------------------------------------------------------
// list

func TestListerUtilisateursRendUnTableauAvecLeResumeDesModules(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.infos = map[string]module.AccountInfo{
		"id-alice": {Present: true, Summary: "312 MiB / 1 GiB"},
		"id-bob":   {Present: false},
		"id-admin": {Present: true, Suspended: true, Summary: "1 GiB"},
	}
	installerModules(t, mail)
	// Deliberately unsorted: the command must sort by username, else the
	// operator has to find a line by eye in a directory that is not sorted.
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-bob", Username: "bob"}},
		comptePlateforme{User: module.User{ID: "id-admin", Username: "AdminCeffio", Email: "admin@test.example"}, Actif: true},
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice", Email: "alice@test.example"}, Actif: false},
	))

	sortie, _, err := executerUsers(t, "", "list")
	if err != nil {
		t.Fatalf("list must succeed: %v", err)
	}
	verifierAppels(t, j, "kc.list", "mail.infos")

	lignes := strings.Split(strings.TrimRight(sortie, "\n"), "\n")
	if len(lignes) != 4 {
		t.Fatalf("list must print a header and one line per user, got %d lines:\n%s", len(lignes), sortie)
	}
	if champs := strings.Fields(lignes[0]); strings.Join(champs, ",") != "USERNAME,EMAIL,STATE,MAIL" {
		t.Fatalf("header is %q, want USERNAME EMAIL STATE MAIL", lignes[0])
	}
	// Sorted by lowercase username.
	for i, nom := range []string{"AdminCeffio", "alice", "bob"} {
		if !strings.HasPrefix(lignes[i+1], nom+" ") {
			t.Fatalf("line %d is %q, want the user %q first", i+1, lignes[i+1], nom)
		}
	}
	// The states are words, not symbols: a missing account is a different
	// problem from a suspended one, and the operator must be able to tell.
	for _, attendu := range []string{
		"active (protected)", // the protected account is marked
		"suspended (1 GiB)",
		"312 MiB / 1 GiB",
		"absent",
		"disabled",
		"—", // no address
	} {
		if !strings.Contains(sortie, attendu) {
			t.Fatalf("list output does not contain %q:\n%s", attendu, sortie)
		}
	}
}

func TestListerUtilisateursSignaleUnModuleIllisibleSansLeCacher(t *testing.T) {
	j := &journal{}
	mail := moduleMail(j)
	mail.refusInfos = errors.New("pod unavailable")
	installerModules(t, mail)
	brancherRepertoire(t, nouveauFauxRepertoire(j,
		comptePlateforme{User: module.User{ID: "id-alice", Username: "alice", Email: "alice@test.example"}, Actif: true}))

	sortie, erreur, err := executerUsers(t, "", "list")
	if err != nil {
		t.Fatalf("a broken module must not fail the listing of the platform users: %v", err)
	}
	if !strings.Contains(erreur, "Mail: accounts unavailable") {
		t.Fatalf("stderr does not report the module failure: %q", erreur)
	}
	if !strings.Contains(sortie, "alice") {
		t.Fatalf("the platform user must still be printed:\n%s", sortie)
	}
}

func TestAfficherTableauAligneLesColonnes(t *testing.T) {
	var sortie bytes.Buffer
	afficherTableau(&sortie, []string{"ID", "ETAT"}, [][]string{
		{"court", "actif"},
		{"beaucoup-plus-long", "—"},
	})
	// Column 0 is 18 wide (the longest username); columns are separated by two
	// spaces and the last one is not padded.
	attendu := "ID" + strings.Repeat(" ", 18) + "ETAT\n" +
		"court" + strings.Repeat(" ", 15) + "actif\n" +
		"beaucoup-plus-long  —\n"
	if sortie.String() != attendu {
		t.Fatalf("table:\n got: %q\nwant: %q", sortie.String(), attendu)
	}
}

func TestAfficherTableauCompteLesRunes(t *testing.T) {
	// A byte-counting renderer would shift this column: "é" is two bytes and one
	// character, so padding by bytes would put one extra space after it and
	// misalign every following column.
	var sortie bytes.Buffer
	afficherTableau(&sortie, []string{"CLE", "VALEUR"}, [][]string{{"é", "1"}})
	lignes := strings.Split(strings.TrimRight(sortie.String(), "\n"), "\n")
	if len(lignes) != 2 {
		t.Fatalf("two lines expected, got %q", sortie.String())
	}
	enRunes := func(ligne, cellule string) int {
		r, c := []rune(ligne), []rune(cellule)
		for i := 0; i+len(c) <= len(r); i++ {
			if string(r[i:i+len(c)]) == cellule {
				return i
			}
		}
		return -1
	}
	if i, j := enRunes(lignes[0], "VALEUR"), enRunes(lignes[1], "1"); i != j || i < 0 {
		t.Fatalf("value column starts at rune %d in the header and %d in the row: %q / %q",
			i, j, lignes[0], lignes[1])
	}
}

// ---------------------------------------------------------------------------
// registry and contract wiring

func TestModulesComptesNeGardeQueLesModulesInstallesQuiGerentLesComptes(t *testing.T) {
	// An installed module that manages accounts takes part.
	mail := moduleMail(&journal{})
	mail.etat = module.Installed
	// An installed module that does not manage accounts is invisible.
	office := &fauxSansComptes{id: "office", etat: module.Installed}
	// An absent module is not provisioned: its objects would be orphaned by its
	// own installation.
	talk := moduleMail(&journal{})
	talk.id = "talk"
	talk.etat = module.Absent
	// A degraded module still takes part: its objects exist and its users need
	// their accounts.
	sondage := moduleMail(&journal{})
	sondage.id = "sondage"
	sondage.etat = module.Degraded

	installerModules(t, mail, office, talk, sondage)
	comptes := modulesComptes(context.Background(), "test.example")
	obtenus := make([]string, 0, len(comptes))
	for _, c := range comptes {
		obtenus = append(obtenus, c.ID)
	}
	if len(obtenus) != 2 || obtenus[0] != "mail" || obtenus[1] != "sondage" {
		t.Fatalf("participating modules are %v, want [mail sondage] (installed or degraded, Accounts implemented)",
			obtenus)
	}
}

func TestTitreModuleRetombeSurLIdentifiant(t *testing.T) {
	m := &fauxModule{id: "mail"}
	if got := titreModule(m); got != "mail" {
		t.Fatalf("module title is %q, want the ID when the declaration has none", got)
	}
}

// ---------------------------------------------------------------------------
// real Keycloak functions

func TestCreerCompteKeycloakAdopteUnCompteExistantSansToucherAuMotDePasse(t *testing.T) {
	var commandes, entrees []string
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, entree, commande string) (string, error) {
		commandes = append(commandes, commande)
		entrees = append(entrees, entree)
		if strings.Contains(commande, "get users") {
			return `[{"id":"id-existant","username":"alice","enabled":true}]`, nil
		}
		t.Fatalf("adopting must not run %q", commande)
		return "", nil
	}

	compte, err := creerCompteKeycloak(context.Background(), module.User{Username: "alice"}, "motdepasse")
	if err != nil {
		t.Fatalf("adopting an existing account must succeed: %v", err)
	}
	if compte.ID != "id-existant" {
		t.Fatalf("adopted account ID is %q, want %q", compte.ID, "id-existant")
	}
	// THE PASSWORD IS NOT RESET on adoption: the operator may have changed it,
	// and a retry must not undo that.
	for i, entree := range entrees {
		if entree != "" {
			t.Fatalf("adoption must not write to stdin (call %d: %q, command %q)", i, entree, commandes[i])
		}
	}
	for _, commande := range commandes {
		if strings.Contains(commande, "create users") {
			t.Fatalf("adoption must not create anything, got %q", commande)
		}
	}
}

func TestCreerCompteKeycloakCreePuisPoseLeMotDePasse(t *testing.T) {
	var commandes, entrees []string
	gets := 0
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, entree, commande string) (string, error) {
		commandes = append(commandes, commande)
		entrees = append(entrees, entree)
		switch {
		case strings.Contains(commande, "get users"):
			gets++
			if gets == 1 {
				return "[]", nil
			}
			return `[{"id":"id-neuf","username":"alice","enabled":true}]`, nil
		case strings.Contains(commande, "create users"), strings.Contains(commande, "set-password"):
			return "", nil
		}
		t.Fatalf("unexpected kcadm command %q", commande)
		return "", nil
	}

	compte, err := creerCompteKeycloak(context.Background(),
		module.User{Username: "alice", Email: "alice@test.example"}, "s3cret")
	if err != nil {
		t.Fatalf("creating an account must succeed: %v", err)
	}
	if compte.ID != "id-neuf" {
		t.Fatalf("created account ID is %q, want %q", compte.ID, "id-neuf")
	}
	var creation int = -1
	for i, commande := range commandes {
		if strings.Contains(commande, "create users") {
			creation = i
		}
	}
	if creation < 0 {
		t.Fatalf("no creation call, got %v", commandes)
	}
	if !strings.Contains(commandes[creation], "email='alice@test.example'") {
		t.Fatalf("creation does not carry the address: %q", commandes[creation])
	}
	if !strings.Contains(commandes[creation], "emailVerified=true") {
		t.Fatalf("a created address must be verified: %q", commandes[creation])
	}
	pose := -1
	for i, commande := range commandes {
		if strings.Contains(commande, "set-password") {
			pose = i
		}
	}
	if pose <= creation {
		t.Fatalf("the password must be set after the creation, got %v", commandes)
	}
	if got := entrees[pose]; got != "s3cret" {
		t.Fatalf("the password travels on stdin, got %q", got)
	}
	if !strings.Contains(commandes[pose], "--new-password") {
		t.Fatalf("the set-password command must read the password from the variable: %q", commandes[pose])
	}
}

func TestEcrireCompteKeycloakFusionneLesAttributs(t *testing.T) {
	var document string
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, entree, commande string) (string, error) {
		if strings.Contains(commande, "get users/") && strings.Contains(commande, "id-alice") {
			return `{"id":"id-alice","username":"alice","email":"ancienne@test.example","attributes":{"existant":["garde-moi"]}}`, nil
		}
		if strings.Contains(commande, "update users/") && strings.Contains(commande, "id-alice") {
			document = entree
			return "", nil
		}
		t.Fatalf("unexpected kcadm command %q", commande)
		return "", nil
	}

	err := ecrireCompteKeycloak(context.Background(),
		module.User{ID: "id-alice", Username: "alice"},
		module.AccountResult{
			Email:      "alice@test.example",
			Attributes: map[string]string{"ceffio_kind": "internal"},
		})
	if err != nil {
		t.Fatalf("write-back must succeed: %v", err)
	}
	// THE MERGE IS THE POINT: the attributes this platform did not write must
	// survive, or a module's own marker would disappear on the next write-back.
	for _, attendu := range []string{
		`"existant":["garde-moi"]`,
		`"ceffio_kind":["internal"]`,
		`"email":"alice@test.example"`,
		`"emailVerified":true`,
	} {
		if !strings.Contains(document, attendu) {
			t.Fatalf("written document does not contain %s:\n%s", attendu, document)
		}
	}
}

func TestEcrireCompteKeycloakSansRienAFaireNInterrogeRien(t *testing.T) {
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, _, commande string) (string, error) {
		t.Fatalf("an empty result must not touch the directory, got %q", commande)
		return "", nil
	}
	if err := ecrireCompteKeycloak(context.Background(), module.User{ID: "id-alice"}, module.AccountResult{}); err != nil {
		t.Fatalf("an empty result is a no-op, got: %v", err)
	}
}

// TestListerComptesKeycloakPagineEtLitLesAttributs : the two Keycloak 26.8 traps,
// both measured on the live demo (2026-11-14) and both INVISIBLE in the answer.
//
// `--first` is refused by kcadm ("Unknown options: '--first', '0'", exit 2), so
// `ceffio users list` failed on a realm whose credentials were perfectly fine.
// A bare `--fields attributes` returns an EMPTY map even when the account has
// attributes — the documented filter rule returns an empty object for a map whose
// children are not requested with brackets — so the module markers
// (`ceffio_kind`) would vanish from accounts that carry them and a marked account
// would be read as external. The filter must also be QUOTED, because the command
// runs through `sh -c`: the first version of the fix passed `attributes(*)` bare
// and kcadm never started (`syntax error near unexpected token '('`).
func TestListerComptesKeycloakPagineEtLitLesAttributs(t *testing.T) {
	var commandes []string
	ancien := executerKcadm
	t.Cleanup(func() { executerKcadm = ancien })
	executerKcadm = func(_ context.Context, _ string, commande string) (string, error) {
		commandes = append(commandes, commande)
		if strings.Contains(commande, "--offset 0") {
			// A FULL PAGE forces the second call: Keycloak caps an answer at 100.
			page := make([]string, 0, 100)
			for i := 0; i < 100; i++ {
				page = append(page, fmt.Sprintf(
					`{"id":"id-%d","username":"user-%d","enabled":true}`, i, i))
			}
			return "[" + strings.Join(page, ",") + "]", nil
		}
		return `[{"id":"id-marque","username":"alice","enabled":true,` +
			`"attributes":{"ceffio_kind":["internal"]}}]`, nil
	}

	comptes, err := listerComptesKeycloak(context.Background())
	if err != nil {
		t.Fatalf("listerComptesKeycloak: %v", err)
	}
	if len(comptes) != 101 {
		t.Fatalf("listed %d accounts, want 101 (the full page and the short one)", len(comptes))
	}
	if len(commandes) != 2 {
		t.Fatalf("kcadm was invoked %d time(s), want 2 (one full page, one short)", len(commandes))
	}
	for i, commande := range commandes {
		if strings.Contains(commande, "--first") {
			t.Fatalf("call %d still passes --first, which kcadm 26.8 refuses: %s", i, commande)
		}
		if !strings.Contains(commande, `--fields "id,username,email,enabled,attributes(*)"`) {
			t.Fatalf("call %d does not pass the quoted, bracketed field filter "+
				"(unquoted, the parentheses are a shell syntax error; unbracketed, "+
				"Keycloak answers an empty map): %s", i, commande)
		}
	}
	if !strings.Contains(commandes[1], "--offset 100") {
		t.Fatalf("the second page does not start at 100: %s", commandes[1])
	}
	if got := comptes[100].Attributes["ceffio_kind"]; got != "internal" {
		t.Fatalf("the module marker was not read: %q", got)
	}
}
