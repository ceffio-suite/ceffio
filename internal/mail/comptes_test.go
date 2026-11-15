// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the mailboxes of internal users: the Stalwart account, its
// platform-domain alias, its quota, its app password and the operations the
// Users page offers on it (§4.7, §9.B, §9.F, §9.H).
//
// WHY THESE TESTS EXIST: every one of these operations is IDEMPOTENT BY
// CONTRACT — `EnsureAccount` is replayed on each install and on each page
// action, and a delete is retried after a partial failure — so the failures to
// catch are silent convergence bugs rather than crashes: a second call that
// rewrites the quota and invalidates an operator's change, an alias write that
// overwrites a colleague's address because the index was computed from the
// count instead of the highest index, a rotation that destroys the app password
// Nextcloud Mail is still configured with, or a suspension that re-enables a
// restriction an operator had set. None of them raises an error, and all of
// them are invisible until a user stops receiving mail.
//
// THE FAKE IS THE ONE OF `noreply_test.go`, EXTENDED WHERE THIS FEATURE NEEDS
// MORE: it now destroys accounts (including the 1.0.3 `notDestroyed:notFound`
// lie of §9.H) and honours the `aliases/<index>` pointer keys. The app-password
// half already refuses the management account and hides the secret on read,
// which is what makes "the vault is the only copy" observable here.
package mail

import (
	"context"
	"strings"
	"testing"
)

// --- EnsureAccount: the nominal path and the repair path -------------------

// TestAssurerCompteCourrielCreeLeCompteEtLAlias: on a fresh server, the account
// is created in the DIRECTORY domain with the ownership marker and the quota,
// and the mail-domain address is attached as an alias.
//
// THE TWO DOMAINS ARE THE POINT: the account name is `<username>@ceffio.local`
// because that is what the OIDC directory gives the WebUI login (§9.B), and
// `<username>@<domain>` is only an alias — creating the account in the mail
// domain instead would make the user's SSO login create a second account.
func TestAssurerCompteCourrielCreeLeCompteEtLAlias(t *testing.T) {
	b := installer(t)
	compte, err := AssurerCompteCourriel(context.Background(), "alice", "example.com", 2)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}

	if compte.Adresse != "alice@ceffio.local" {
		t.Errorf("account address is %q, expected alice@ceffio.local", compte.Adresse)
	}
	if compte.Domaine != DomaineComptes {
		t.Errorf("account domain is %q, expected %s", compte.Domaine, DomaineComptes)
	}
	if compte.Quota != 2<<30 {
		t.Errorf("quota is %d bytes, expected %d", compte.Quota, 2<<30)
	}
	if len(compte.Aliases) != 1 || compte.Aliases[0] != "alice@example.com" {
		t.Errorf("aliases are %v, expected [alice@example.com]", compte.Aliases)
	}
	if compte.Description != marqueCompte {
		t.Errorf("description is %q, expected the ownership marker %q", compte.Description, marqueCompte)
	}

	brut := b.serveur.compteNommeBrut("alice")
	if brut == nil {
		t.Fatalf("no account named alice was created: %v", b.serveur.comptes)
	}
	if brut["domainId"] != "c" {
		t.Errorf("account created in domain %v, expected the directory domain c", brut["domainId"])
	}
	alias := brut["aliases"].(map[string]any)["0"].(map[string]any)
	if alias["name"] != "alice" || alias["domainId"] != "b" {
		t.Errorf("alias is %v, expected alice in the mail domain b", alias)
	}
}

// TestAssurerCompteCourrielEstIdempotent: a second call writes NOTHING.
//
// THIS IS WHAT EVERY `upgrade` AND EVERY PAGE ACTION REPLAYS: an unconditional
// quota or alias write would bump the account's modification counter on each
// replay and, worse, overwrite a quota an operator raised by hand.
func TestAssurerCompteCourrielEstIdempotent(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	if _, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1); err != nil {
		t.Fatalf("first AssurerCompteCourriel: %v", err)
	}
	sets := b.serveur.appelsDe("x:Account/set")
	if sets == 0 {
		t.Fatalf("the first run wrote nothing: %v", b.serveur.appels)
	}
	ecritures := len(b.serveur.ecritures)

	if _, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1); err != nil {
		t.Fatalf("second AssurerCompteCourriel: %v", err)
	}
	if apres := b.serveur.appelsDe("x:Account/set"); apres != sets {
		t.Errorf("the second run sent %d x:Account/set instead of 0", apres-sets)
	}
	if len(b.serveur.ecritures) != ecritures {
		t.Errorf("the second run updated the account %d time(s) instead of 0", len(b.serveur.ecritures)-ecritures)
	}
}

// TestAssurerCompteCourrielCompleteLeCompteCreeParLeSSO: an account the first
// SSO login auto-provisioned has neither alias nor quota; the repair path adds
// them WITHOUT creating a second account.
func TestAssurerCompteCourrielCompleteLeCompteCreeParLeSSO(t *testing.T) {
	b := installer(t)
	b.serveur.ajouterCompte("bob", "c", map[string]any{"@type": "Inherit"})

	compte, err := AssurerCompteCourriel(context.Background(), "bob", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	if nommes := b.serveur.comptesNommes("bob"); len(nommes) != 1 {
		t.Fatalf("the repair created a duplicate: %d accounts named bob", len(nommes))
	}
	if len(compte.Aliases) != 1 || compte.Aliases[0] != "bob@example.com" {
		t.Errorf("aliases are %v, expected [bob@example.com]", compte.Aliases)
	}
	if compte.Quota != 1<<30 {
		t.Errorf("quota is %d bytes, expected 1 GiB", compte.Quota)
	}
	brut := b.serveur.compteNommeBrut("bob")
	if brut["description"] != nil && brut["description"] != marqueCompte {
		t.Errorf("the repair stamped a foreign description %v on the account", brut["description"])
	}
}

// TestAssurerCompteCourrielDeplaceUnCompteMalDomaine: an account of the same
// name living in the mail domain is MOVED, not duplicated.
func TestAssurerCompteCourrielDeplaceUnCompteMalDomaine(t *testing.T) {
	b := installer(t)
	b.serveur.ajouterCompte("alice", "b", map[string]any{"@type": "Inherit"})

	compte, err := AssurerCompteCourriel(context.Background(), "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	if nommes := b.serveur.comptesNommes("alice"); len(nommes) != 1 {
		t.Fatalf("a second alice account was created: %d accounts", len(nommes))
	}
	if brut := b.serveur.compteNommeBrut("alice"); brut["domainId"] != "c" {
		t.Errorf("account domain is %v after the repair, expected the directory domain c", brut["domainId"])
	}
	if compte.Adresse != "alice@ceffio.local" {
		t.Errorf("account address is %q after the repair, expected alice@ceffio.local", compte.Adresse)
	}
}

// TestAssurerCompteCourrielNeRemplacePasUnAliasExistant: the new alias goes to
// the first FREE index, never to index 0 when an operator's alias sits there.
func TestAssurerCompteCourrielNeRemplacePasUnAliasExistant(t *testing.T) {
	b := installer(t)
	b.serveur.ajouterCompte("alice", "c", map[string]any{"@type": "Inherit"})
	b.serveur.compteNommeBrut("alice")["aliases"] = map[string]any{
		"0": map[string]any{"name": "sales", "domainId": "b", "enable": true},
	}

	compte, err := AssurerCompteCourriel(context.Background(), "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	attendus := map[string]bool{"alice@example.com": true, "sales@example.com": true}
	for _, adresse := range compte.Aliases {
		delete(attendus, adresse)
	}
	if len(attendus) != 0 {
		t.Errorf("aliases are %v, missing %v", compte.Aliases, attendus)
	}
}

// TestAssurerCompteCourrielRefuseUnDomaineAbsent: a mail domain the SSO step
// never created is an incomplete installation, reported as such — the alias has
// no target and the caller must not create an account it cannot address.
func TestAssurerCompteCourrielRefuseUnDomaineAbsent(t *testing.T) {
	installer(t)
	_, err := AssurerCompteCourriel(context.Background(), "alice", "absent.example", 1)
	if err == nil || !strings.Contains(err.Error(), "absent.example") {
		t.Fatalf("expected an error naming the absent domain, got %v", err)
	}
}

// --- The credential --------------------------------------------------------

// TestAssurerMotDePasseCompteStockeLeSecretDansLeCoffre: the app password is
// created with the Nextcloud Mail description, and its secret — returned ONCE —
// is written to the vault under the account it belongs to.
func TestAssurerMotDePasseCompteStockeLeSecretDansLeCoffre(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	compte, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}

	secret, err := AssurerMotDePasseCompte(ctx, "alice", "alice@ceffio.local", compte.ID)
	if err != nil {
		t.Fatalf("AssurerMotDePasseCompte: %v", err)
	}
	if secret == "" || secret != b.serveur.dernierSecret {
		t.Errorf("returned secret %q, expected the one the server created (%q)", secret, b.serveur.dernierSecret)
	}
	motsDePasse := b.serveur.motDePasseDe(compte.ID)
	if len(motsDePasse) != 1 || motsDePasse[0].Description != descriptionMotDePasseCompte {
		t.Fatalf("app passwords are %v, expected exactly one %q", motsDePasse, descriptionMotDePasseCompte)
	}
	entree := b.coffre.entree(composantCoffre, entreeCoffreCompte("alice"))
	if entree["password"] != secret {
		t.Errorf("vault password is %q, expected the created secret", entree["password"])
	}
	if entree["account"] != compte.ID {
		t.Errorf("vault account is %q, expected the Stalwart id %q (a re-created account gets a new one)", entree["account"], compte.ID)
	}
	if entree["user"] != "alice@ceffio.local" {
		t.Errorf("vault user is %q, expected alice@ceffio.local", entree["user"])
	}
}

// TestAssurerMotDePasseCompteReutiliseLEntreeExistante: when the vault entry
// belongs to the same account, the password is REUSED and the server is not
// touched.
//
// A ROTATION HERE WOULD BREAK NEXTCLOUD MAIL SILENTLY: the Mail account stores
// the password it was created with, and nothing re-reads it.
func TestAssurerMotDePasseCompteReutiliseLEntreeExistante(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	compte, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	b.coffre.entrees[composantCoffre+"/"+entreeCoffreCompte("alice")] = map[string]string{
		"user":     "alice@ceffio.local",
		"password": "mot-de-passe-en-place",
		"account":  compte.ID,
	}
	b.serveur.appels = nil

	secret, err := AssurerMotDePasseCompte(ctx, "alice", "alice@ceffio.local", compte.ID)
	if err != nil {
		t.Fatalf("AssurerMotDePasseCompte: %v", err)
	}
	if secret != "mot-de-passe-en-place" {
		t.Errorf("returned secret %q, expected the stored one", secret)
	}
	if len(b.serveur.appels) != 0 {
		t.Errorf("the JMAP server was called %d time(s) for a credential that works: %v", len(b.serveur.appels), b.serveur.appels)
	}
	if b.coffre.ecritures != 0 {
		t.Errorf("the vault was rewritten %d time(s) for a credential that works", b.coffre.ecritures)
	}
}

// TestAssurerMotDePasseCompteTourneQuandLeCompteChange: a vault entry written
// for ANOTHER Stalwart id is stale — a re-created account never accepts the old
// password — so the old password is destroyed and a new one stored.
func TestAssurerMotDePasseCompteTourneQuandLeCompteChange(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	compte, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	b.coffre.entrees[composantCoffre+"/"+entreeCoffreCompte("alice")] = map[string]string{
		"user": "alice@ceffio.local", "password": "perime", "account": "compte-detruit",
	}
	b.serveur.ajouterMotDePasse(compte.ID, "ap0", descriptionMotDePasseCompte, "perime")
	b.serveur.prochainMotDePasse = 0
	b.serveur.operations = nil

	secret, err := AssurerMotDePasseCompte(ctx, "alice", "alice@ceffio.local", compte.ID)
	if err != nil {
		t.Fatalf("AssurerMotDePasseCompte: %v", err)
	}
	if secret == "perime" {
		t.Fatal("the stale credential was returned: Nextcloud Mail would authenticate with a destroyed password")
	}
	operations := strings.Join(b.serveur.operations, ",")
	if !strings.Contains(operations, "detruire:ap0") || !strings.Contains(operations, "creer:ap1") {
		t.Errorf("operations are %v, expected the stale password destroyed before the new one is created", b.serveur.operations)
	}
	entree := b.coffre.entree(composantCoffre, entreeCoffreCompte("alice"))
	if entree["password"] != secret || entree["account"] != compte.ID {
		t.Errorf("vault entry is %v, expected the new secret under account %s", entree, compte.ID)
	}
}

// TestAssurerMotDePasseCompteSansCoffreRefuse: without OpenBao there is nowhere
// to keep a secret that is returned once, so the call fails instead of creating
// an unrecoverable password.
func TestAssurerMotDePasseCompteSansCoffreRefuse(t *testing.T) {
	b := installer(t)
	t.Setenv("BAO_ADDR", "")
	compte, err := AssurerCompteCourriel(context.Background(), "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	_, err = AssurerMotDePasseCompte(context.Background(), "alice", "alice@ceffio.local", compte.ID)
	if err == nil || !strings.Contains(err.Error(), "OpenBao") {
		t.Fatalf("expected an error naming OpenBao, got %v", err)
	}
	if len(b.serveur.motDePasseDe(compte.ID)) != 0 {
		t.Errorf("a password was created despite the missing vault: %v", b.serveur.motDePasseDe(compte.ID))
	}
}

// --- Suspension and reactivation ------------------------------------------

// TestSuspendrePuisReprendreLeCompte: suspension refuses logins, reactivation
// removes ONLY that restriction, and an operator's other restriction survives
// both calls.
//
// THE OTHER RESTRICTION IS THE ASSERTION THAT MATTERS: `Merge` replaces the
// disabled-permission set, so a careless implementation re-enables `emailSend`
// on an account an operator barred, and nobody sees it.
func TestSuspendrePuisReprendreLeCompte(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	id := b.serveur.ajouterCompte("alice", "c", map[string]any{
		"@type": "Merge", "disabledPermissions": map[string]any{"emailSend": true},
	})

	if err := SuspendreCompte(ctx, "alice"); err != nil {
		t.Fatalf("SuspendreCompte: %v", err)
	}
	if !b.serveur.compteNommeBrut("alice")["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)["authenticate"].(bool) {
		t.Error("the suspension did not disable authentication")
	}
	if b.serveur.compteNommeBrut("alice")["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)["emailSend"] != true {
		t.Error("the suspension silently re-enabled an operator's emailSend restriction")
	}
	comptes, err := LireComptesCourriel(ctx)
	if err != nil {
		t.Fatalf("LireComptesCourriel: %v", err)
	}
	if !compteNommeDeTest(comptes, "alice").Suspendu {
		t.Error("the account does not read back as suspended")
	}

	if err := ReprendreCompte(ctx, "alice"); err != nil {
		t.Fatalf("ReprendreCompte: %v", err)
	}
	permissions := b.serveur.comptes[id]["permissions"].(map[string]any)
	desactivees := permissions["disabledPermissions"].(map[string]any)
	if _, encore := desactivees["authenticate"]; encore {
		t.Error("authentication is still disabled after the reactivation")
	}
	if desactivees["emailSend"] != true {
		t.Error("the reactivation re-enabled an operator's emailSend restriction")
	}
}

// TestReprendreUnCompteSansAutreRefusRemetInherit: when authentication was the
// only disabled permission, the object goes back to the shape the server gives
// an unrestricted account.
func TestReprendreUnCompteSansAutreRefusRemetInherit(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	b.serveur.ajouterCompte("alice", "c", map[string]any{
		"@type": "Merge", "disabledPermissions": map[string]any{"authenticate": true},
	})
	if err := ReprendreCompte(ctx, "alice"); err != nil {
		t.Fatalf("ReprendreCompte: %v", err)
	}
	permissions := b.serveur.compteNommeBrut("alice")["permissions"].(map[string]any)
	if permissions["@type"] != "Inherit" {
		t.Errorf("permissions are %v, expected the Inherit object", permissions)
	}
}

// --- Deletion --------------------------------------------------------------

// TestSupprimerCompteCourrielDetruitLeCompteEtLeCredential: the account and its
// vault entry are both gone, and a SECOND deletion — the normal retry after a
// partial failure — succeeds without doing anything.
func TestSupprimerCompteCourrielDetruitLeCompteEtLeCredential(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	compte, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1)
	if err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	if _, err := AssurerMotDePasseCompte(ctx, "alice", "alice@ceffio.local", compte.ID); err != nil {
		t.Fatalf("AssurerMotDePasseCompte: %v", err)
	}

	if err := SupprimerCompteCourriel(ctx, "alice"); err != nil {
		t.Fatalf("SupprimerCompteCourriel: %v", err)
	}
	if len(b.serveur.comptesNommes("alice")) != 0 {
		t.Errorf("the account survives the deletion: %v", b.serveur.comptes)
	}
	if entree := b.coffre.entree(composantCoffre, entreeCoffreCompte("alice")); len(entree) != 0 {
		t.Errorf("the vault entry survives the deletion: %v", entree)
	}
	if b.coffre.suppressions != 1 {
		t.Errorf("the vault was asked to delete %d time(s), expected 1", b.coffre.suppressions)
	}

	if err := SupprimerCompteCourriel(ctx, "alice"); err != nil {
		t.Fatalf("the retried deletion failed: %v", err)
	}
}

// TestSupprimerCompteCourrielCroitLaRelecture: 1.0.3 answers
// `notDestroyed:notFound` for an account that IS gone (§9.H); the read-back is
// the authority, so the deletion is a success and the vault entry is removed.
func TestSupprimerCompteCourrielCroitLaRelecture(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	if _, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1); err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	b.coffre.entrees[composantCoffre+"/"+entreeCoffreCompte("alice")] = map[string]string{
		"user": "alice@ceffio.local", "password": "secret", "account": "u1",
	}
	b.serveur.destruction = "mente"

	if err := SupprimerCompteCourriel(ctx, "alice"); err != nil {
		t.Fatalf("SupprimerCompteCourriel: %v", err)
	}
	if len(b.serveur.comptesNommes("alice")) != 0 {
		t.Errorf("the account survives the deletion: %v", b.serveur.comptes)
	}
	if entree := b.coffre.entree(composantCoffre, entreeCoffreCompte("alice")); len(entree) != 0 {
		t.Errorf("the vault entry was kept although the account is gone: %v", entree)
	}
}

// TestSupprimerCompteCourrielEchoueSiLeCompteSurvit: an account the server
// REFUSED to destroy keeps its credential, because deleting the vault entry
// would leave a working app password with no owner.
func TestSupprimerCompteCourrielEchoueSiLeCompteSurvit(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	if _, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1); err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	b.coffre.entrees[composantCoffre+"/"+entreeCoffreCompte("alice")] = map[string]string{
		"user": "alice@ceffio.local", "password": "secret", "account": "u1",
	}
	b.serveur.destruction = "refusee"

	err := SupprimerCompteCourriel(ctx, "alice")
	if err == nil || !strings.Contains(err.Error(), "still present") {
		t.Fatalf("expected an error saying the account is still present, got %v", err)
	}
	if entree := b.coffre.entree(composantCoffre, entreeCoffreCompte("alice")); len(entree) == 0 {
		t.Error("the credential was deleted although the account survives: its password is now unowned")
	}
}

// --- Read model and quota --------------------------------------------------

// TestLireComptesCourrielLitQuotaUsageEtSuspendu: the page's three facts come
// from three different shapes of the JMAP answer — `quotas.maxDiskQuota`
// nested, `usedDiskQuota` top-level, `permissions` typed — and the alias table
// is keyed by index.
func TestLireComptesCourrielLitQuotaUsageEtSuspendu(t *testing.T) {
	b := installer(t)
	id := b.serveur.ajouterCompte("alice", "c", map[string]any{
		"@type": "Merge", "disabledPermissions": map[string]any{"authenticate": true},
	})
	compte := b.serveur.comptes[id]
	compte["quotas"] = map[string]any{"maxDiskQuota": float64(3 << 30)}
	compte["usedDiskQuota"] = float64(312 << 20)
	compte["aliases"] = map[string]any{
		"0": map[string]any{"name": "contact", "domainId": "b", "enable": true},
	}

	comptes, err := LireComptesCourriel(context.Background())
	if err != nil {
		t.Fatalf("LireComptesCourriel: %v", err)
	}
	lu := compteNommeDeTest(comptes, "alice")
	if lu.Quota != 3<<30 {
		t.Errorf("quota is %d bytes, expected 3 GiB", lu.Quota)
	}
	if lu.Utilise != 312<<20 {
		t.Errorf("usage is %d bytes, expected 312 MiB", lu.Utilise)
	}
	if !lu.Suspendu {
		t.Error("the account is not reported as suspended")
	}
	if len(lu.Aliases) != 1 || lu.Aliases[0] != "contact@example.com" {
		t.Errorf("aliases are %v, expected [contact@example.com]", lu.Aliases)
	}
	if lu.Domaine != DomaineComptes {
		t.Errorf("domain is %q, expected %s", lu.Domaine, DomaineComptes)
	}
}

// TestAdressePriseVoitLesAlias: an address that is only an alias still receives
// mail, so `ValidateAccount` must see the collision and name its holder.
func TestAdressePriseVoitLesAlias(t *testing.T) {
	b := installer(t)
	id := b.serveur.ajouterCompte("alice", "c", map[string]any{"@type": "Inherit"})
	b.serveur.comptes[id]["aliases"] = map[string]any{
		"0": map[string]any{"name": "contact", "domainId": "b", "enable": true},
	}
	ctx := context.Background()

	if titulaire, prise, err := AdressePrise(ctx, "contact@example.com"); err != nil {
		t.Fatalf("AdressePrise: %v", err)
	} else if !prise || titulaire != "alice" {
		t.Errorf("alias collision: prise=%v titulaire=%q, expected alice", prise, titulaire)
	}
	if _, prise, err := AdressePrise(ctx, "libre@example.com"); err != nil {
		t.Fatalf("AdressePrise: %v", err)
	} else if prise {
		t.Error("a free address was reported as taken")
	}
}

// TestReglerQuotaCompteEcritLesOctets: the quota is written in BYTES, not GiB —
// the server's unit is bytes, and a GiB value would be a quota of 3 octets.
func TestReglerQuotaCompteEcritLesOctets(t *testing.T) {
	b := installer(t)
	ctx := context.Background()
	if _, err := AssurerCompteCourriel(ctx, "alice", "example.com", 1); err != nil {
		t.Fatalf("AssurerCompteCourriel: %v", err)
	}
	if err := ReglerQuotaCompte(ctx, "alice", 4); err != nil {
		t.Fatalf("ReglerQuotaCompte: %v", err)
	}
	quotas := b.serveur.compteNommeBrut("alice")["quotas"].(map[string]any)
	if quotas["maxDiskQuota"] != float64(4<<30) {
		t.Errorf("stored quota is %v, expected %d bytes", quotas["maxDiskQuota"], int64(4)<<30)
	}
}

// --- test helpers ----------------------------------------------------------

// compteNommeBrut returns the mutable map of the account named `nom`, or nil.
// The tests mutate it to describe the state under test.
func (f *fauxNoreply) compteNommeBrut(nom string) map[string]any {
	for _, compte := range f.comptes {
		if compte["name"] == nom {
			return compte
		}
	}
	return nil
}

// comptesNommes returns every account carrying that name, in any domain.
func (f *fauxNoreply) comptesNommes(nom string) []map[string]any {
	var trouves []map[string]any
	for _, compte := range f.comptes {
		if compte["name"] == nom {
			trouves = append(trouves, compte)
		}
	}
	return trouves
}

// appelsDe counts the calls of one JMAP method.
func (f *fauxNoreply) appelsDe(methode string) int {
	n := 0
	for _, appel := range f.appels {
		if appel == methode {
			n++
		}
	}
	return n
}

// compteNommeDeTest picks a named account out of a read model.
func compteNommeDeTest(comptes []CompteCourriel, nom string) CompteCourriel {
	for _, compte := range comptes {
		if compte.Nom == nom {
			return compte
		}
	}
	return CompteCourriel{}
}
