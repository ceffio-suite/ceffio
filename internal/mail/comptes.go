// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mailboxes of the internal users: one Stalwart account per user, its
// platform-domain alias, its quota, its app password, and the operations the
// Users page offers on them (§4.7, §9.B).
//
// # Why the accounts live in `ceffio.local` and the address is an alias
//
// The mail domain is attached to the OIDC directory, and the directory maps
// `preferred_username` to `<username>@ceffio.local` (§9.B). Moving that mapping
// to `<domain>` (option b) would rename `adminceffio` and every SSO user at
// once, and would break the WebUI login of every existing account. Option (c)
// is therefore the implemented one: the account keeps its
// `<username>@ceffio.local` name — so the SSO login finds it, and would CREATE
// it on first login — while `<username>@<domain>` is attached to it as an
// address alias, which is what the outside world writes to.
//
// The consequence is stated rather than hidden: an account auto-provisioned by
// a first SSO login has no alias and no quota until `AssurerCompteCourriel`
// runs on it. The Users page shows that state (`AccountInfos`) instead of
// pretending the mailbox is complete.
//
// # Why every credential is an app password
//
// The domain sits behind an external directory, so the directory OWNS the
// account credentials: writing `credentials` through `x:Account/set` is refused
// with `forbidden` (§9.A). An app password is the one credential a Ceffio-owned
// client can hold, its secret is returned exactly once, and the vault entry
// `ceffio/mail/comptes/<username>` is its only copy — hence the vault is
// mandatory for `boite=true`, exactly as for the platform sender.
package mail

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// DomaineComptes is the domain the OIDC directory gives every account
	// (§9.B). It is NOT the mail domain: the mail domain is only an alias on
	// the account. Hardcoded because it is the same value the SSO step
	// configures (`domaineAdmin`), and deriving it from the settings would make
	// two independent statements about one fact.
	DomaineComptes = "ceffio.local"

	// marqueCompte is written in the account's `description` when Ceffio creates
	// it. It marks ownership without claiming authority: the account is ours
	// because its address belongs to one of our users, and the marker only
	// makes that readable in the WebUI's account list.
	marqueCompte = "ceffio internal user"

	// descriptionMotDePasseCompte marks the app password given to Nextcloud
	// Mail. The description is the ownership filter: only passwords carrying it
	// are destroyed, and the cap of five per account (§9.A) is freed before a
	// new one is created.
	descriptionMotDePasseCompte = "nextcloud-mail"
)

// entreeCoffreCompte is the vault entry of a user's mailbox credential:
// `ceffio/mail/comptes/<username>` (§4.7). The uppercase of the username is
// preserved — vault paths are case-sensitive and the account name is the
// user's.
func entreeCoffreCompte(nom string) string {
	return "comptes/" + nom
}

// The seams, so the module layer's tests run without a cluster: the vault, the
// app-password rotation and the account read are variables, each defaulting to
// the real implementation.
var (
	supprimerEntreeCoffre = secrets.SupprimerEntreeCoffre
)

// CompteCourriel is one Stalwart account, reduced to what the Users page and
// the operations need.
//
// IT EXISTS SO THE REST OF THE PACKAGE DOES NOT JUGGLE MAPS: a `map[string]any`
// read in three places is three chances to misspell a field, and the JMAP
// answer shape (aliases keyed by index, quotas nested, permissions typed)
// would leak into every caller.
type CompteCourriel struct {
	ID          string
	Nom         string
	Domaine     string
	Adresse     string
	Aliases     []string // full addresses, sorted
	Quota       int64    // maxDiskQuota in bytes; 0 means "no quota set"
	Utilise     int64    // usedDiskQuota in bytes
	Suspendu    bool
	Description string

	// The raw objects are kept for the two operations that need the DETAIL
	// rather than the summary: reactivation must preserve the other disabled
	// permissions, and a new alias needs the first free index. They never
	// leave the package.
	permissionsBrutes any
	aliasBruts        any
}

// LireComptesCourriel reads EVERY account in one JMAP request, with the aliases
// resolved to addresses.
//
// ONE REQUEST, NOT ONE PER USER: the Users page lists every user at once, and a
// per-user read would turn a page load into N round trips through the pod's
// HTTP proxy. The aliases are resolved against the domain table read in the
// same call chain because JMAP returns `domainId` and the address a user sees
// is `name@domain-name`.
func LireComptesCourriel(ctx context.Context) ([]CompteCourriel, error) {
	domaines, err := lireNomsDeDomaines(ctx)
	if err != nil {
		return nil, err
	}
	comptes, err := clientJMAP().Get(ctx, "x:Account/get", nil,
		[]string{"id", "name", "domainId", "emailAddress", "aliases", "quotas",
			"permissions", "description", "usedDiskQuota"})
	if err != nil {
		return nil, fmt.Errorf("reading the mail accounts: %w", err)
	}

	resultat := make([]CompteCourriel, 0, len(comptes))
	for _, compte := range comptes {
		lu := CompteCourriel{
			ID:          valeurChaine(compte["id"]),
			Nom:         valeurChaine(compte["name"]),
			Domaine:     domaines[valeurChaine(compte["domainId"])],
			Adresse:     valeurChaine(compte["emailAddress"]),
			Description: valeurChaine(compte["description"]),
			Suspendu:    authentificationSuspendue(compte["permissions"]),

			permissionsBrutes: compte["permissions"],
			aliasBruts:        compte["aliases"],
		}
		if lu.ID == "" || lu.Nom == "" {
			continue
		}
		lu.Quota, lu.Utilise = quotasCompte(compte)
		lu.Aliases = adressesAlias(compte["aliases"], domaines)
		resultat = append(resultat, lu)
	}
	// A STABLE ORDER: the console renders its rows from this list, and an
	// order that changes between two reads would make one user's actions jump
	// to another row in a live-refreshing page.
	sort.Slice(resultat, func(i, j int) bool { return resultat[i].Nom < resultat[j].Nom })
	return resultat, nil
}

// AdressePrise reports the account already holding `adresse`, as an account
// address or as an alias.
//
// AN ALIAS COUNTS: an address that is only an alias still receives mail, so
// creating an account with that address would silently take over somebody
// else's correspondence — the exact collision `ValidateAccount` must refuse.
func AdressePrise(ctx context.Context, adresse string) (string, bool, error) {
	comptes, err := LireComptesCourriel(ctx)
	if err != nil {
		return "", false, err
	}
	for _, compte := range comptes {
		if strings.EqualFold(compte.Adresse, adresse) {
			return compte.Nom, true, nil
		}
		for _, alias := range compte.Aliases {
			if strings.EqualFold(alias, adresse) {
				return compte.Nom, true, nil
			}
		}
	}
	return "", false, nil
}

// AssurerCompteCourriel creates the user's Stalwart account if needed, then
// attaches `<nom>@<domaine>` and the quota to it. It is idempotent.
//
// THE REPAIR PATH IS THE NOMINAL PATH (§9.B): a user who signed in to the WebUI
// before Ceffio ever saw them already has an account without alias and without
// quota. `EnsureAccount` must complete it, not report a conflict — and after a
// replayed install it must find nothing to do.
func AssurerCompteCourriel(ctx context.Context, nom, domaine string, quotaGio int) (CompteCourriel, error) {
	idLocal, idDomaine, err := domainesCompte(ctx, domaine)
	if err != nil {
		return CompteCourriel{}, err
	}

	comptes, err := LireComptesCourriel(ctx)
	if err != nil {
		return CompteCourriel{}, err
	}
	compte, existe := compteNomme(comptes, nom)

	octets := int64(quotaGio) * 1 << 30
	if !existe {
		id, err := creerObjet(ctx, "x:Account/set", map[string]any{
			"@type":       "User",
			"name":        nom,
			"domainId":    idLocal,
			"description": marqueCompte,
			"quotas":      map[string]any{"maxDiskQuota": octets},
		})
		if err != nil {
			return CompteCourriel{}, fmt.Errorf("creating the mailbox account of %s: %w", nom, err)
		}
		// THE CREATE ANSWER GIVES THE ID ONLY: the derived address and the
		// effective quota are read back, because they are what the caller
		// stores and shows.
		compte, err = relireCompte(ctx, id)
		if err != nil {
			return CompteCourriel{}, err
		}
		existe = true
	}

	// THE DOMAIN IS REPAIRED FIRST: it decides the address the server derives,
	// and every later comparison (`<nom>@<domaine>` alias, quota) assumes the
	// account lives in the directory domain.
	if compte.Domaine != DomaineComptes {
		if err := majJMAPObjet(ctx, "x:Account/set", compte.ID, map[string]any{"domainId": idLocal}); err != nil {
			return CompteCourriel{}, fmt.Errorf("moving the mailbox account of %s to %s: %w", nom, DomaineComptes, err)
		}
	}

	// THE ALIAS IS THE ADDRESS THE OUTSIDE WORLD USES (§9.B).
	if err := assurerAliasCompte(ctx, compte, nom, domaine, idDomaine); err != nil {
		return CompteCourriel{}, err
	}

	// THE QUOTA IS WRITTEN ONLY WHEN IT DIFFERS: re-writing it on every call
	// would make an idempotent replay look like a change, and would overwrite a
	// quota an operator raised by hand on every page load.
	if quotaGio > 0 && compte.Quota != octets {
		if err := reglerQuota(ctx, compte.ID, quotaGio); err != nil {
			return CompteCourriel{}, fmt.Errorf("setting the mailbox quota of %s: %w", nom, err)
		}
	}
	return relireCompte(ctx, compte.ID)
}

// assurerAliasCompte adds `<nom>@<domaine>` to the account when it is missing.
//
// THE ALIAS IS WRITTEN AS A POINTER (`aliases/<n>`): §9.B verified that the
// update form takes a pointer to a new index, and the index must be the first
// free one — reusing an occupied index would overwrite another alias.
func assurerAliasCompte(ctx context.Context, compte CompteCourriel, nom, domaine, idDomaine string) error {
	attendue := nom + "@" + domaine
	for _, alias := range compte.Aliases {
		if strings.EqualFold(alias, attendue) {
			return nil
		}
	}
	if err := majJMAPObjet(ctx, "x:Account/set", compte.ID, map[string]any{
		"aliases/" + strconv.Itoa(prochainIndexAlias(compte.aliasBruts)): map[string]any{
			"@type":    "EmailAlias",
			"name":     nom,
			"domainId": idDomaine,
		},
	}); err != nil {
		return fmt.Errorf("attaching the address %s to the mailbox account of %s: %w", attendue, nom, err)
	}
	return nil
}

// ReglerQuotaCompte sets a single account's quota and reads it back.
func ReglerQuotaCompte(ctx context.Context, nom string, quotaGio int) error {
	compte, err := compteParNom(ctx, nom)
	if err != nil {
		return err
	}
	if err := reglerQuota(ctx, compte.ID, quotaGio); err != nil {
		return fmt.Errorf("setting the mailbox quota of %s: %w", nom, err)
	}
	return nil
}

// SuspendreCompte refuses authentication on the account, and keeps reception.
//
// MERGE + `authenticate` DISABLED (§9.F): IMAP and SMTP logins are refused,
// mail already delivered stays, and inbound mail is still accepted — which is
// what a departure or a temporary suspension should do. `Inherit` would replace
// the whole permission set; `emailReceive` would bounce the mail instead.
func SuspendreCompte(ctx context.Context, nom string) error {
	compte, err := compteParNom(ctx, nom)
	if err != nil {
		return err
	}
	if err := majJMAPObjet(ctx, "x:Account/set", compte.ID, map[string]any{
		"permissions": permissionsAvecAuthentificationSuspendue(compte),
	}); err != nil {
		return fmt.Errorf("suspending the mailbox account of %s: %w", nom, err)
	}
	relu, err := relireCompte(ctx, compte.ID)
	if err != nil {
		return err
	}
	if !relu.Suspendu {
		return fmt.Errorf("the mailbox account of %s reads back as active after it was suspended", nom)
	}
	return nil
}

// ReprendreCompte gives authentication back, and touches NOTHING ELSE.
//
// THE READ-BACK DECIDES THE SHAPE: the account may carry other disabled
// permissions (an operator's own), and replacing the object with `Inherit`
// would silently re-enable them. Only `authenticate` is removed; when it was
// the last one, the object goes back to `Inherit`, which is what the server
// gives an account nobody restricted.
func ReprendreCompte(ctx context.Context, nom string) error {
	compte, err := compteParNom(ctx, nom)
	if err != nil {
		return err
	}
	permissions := permissionsSansAuthentification(compte)
	if err := majJMAPObjet(ctx, "x:Account/set", compte.ID, map[string]any{"permissions": permissions}); err != nil {
		return fmt.Errorf("reactivating the mailbox account of %s: %w", nom, err)
	}
	relu, err := relireCompte(ctx, compte.ID)
	if err != nil {
		return err
	}
	if relu.Suspendu {
		return fmt.Errorf("the mailbox account of %s reads back as suspended after it was reactivated", nom)
	}
	return nil
}

// SupprimerCompteCourriel destroys the account and every Ceffio-owned
// credential attached to it.
//
// THE READ-BACK IS THE AUTHORITY (§9.H): 1.0.3 sometimes answers
// `notDestroyed:notFound` for an account that IS gone, so the destroy response
// cannot decide the outcome — the account list can. And the vault entry is
// removed AFTER the account, never before: an unreachable Stalwart with a
// deleted vault entry would leave a working app password with no way to know
// where it came from.
//
// AN ABSENT ACCOUNT IS A SUCCESS: the goal is "no mailbox for this user", and a
// retried deletion — the normal state after a partial failure — must converge.
func SupprimerCompteCourriel(ctx context.Context, nom string) error {
	compte, existe, err := compteExistant(ctx, nom)
	if err != nil {
		return err
	}
	if !existe {
		return supprimerCredentialCompte(ctx, nom)
	}

	// THE RAW CALL, ON PURPOSE: the standard client turns `notDestroyed` into an
	// error, and 1.0.3 reports it for an account that IS gone (§9.H). Failing
	// here would leave the vault entry in place forever on a deletion that
	// actually succeeded. A transport failure is still an error: nothing can be
	// concluded from a request that never arrived.
	if _, _, err := clientJMAP().AppelBrut(ctx, "x:Account/set", map[string]any{
		"destroy": []string{compte.ID},
	}); err != nil {
		return fmt.Errorf("deleting the mailbox account of %s: %w", nom, err)
	}
	restants, err := LireComptesCourriel(ctx)
	if err != nil {
		return err
	}
	if _, encore := compteNomme(restants, nom); encore {
		return fmt.Errorf("the mailbox account of %s is still present after its deletion", nom)
	}
	return supprimerCredentialCompte(ctx, nom)
}

// supprimerCredentialCompte removes the vault entry of the account's app
// password.
//
// NO VAULT IS NOT AN ERROR: an installation without OpenBao keeps no entry, so
// there is nothing to revoke. An UNREACHABLE vault is an error: the credential
// is still there and the deletion is not finished.
func supprimerCredentialCompte(ctx context.Context, nom string) error {
	if !secrets.DepuisEnvironnement().Dispo() {
		return nil
	}
	return supprimerEntreeCoffre(ctx, secrets.DepuisEnvironnement(), composantCoffre, entreeCoffreCompte(nom))
}

// AssurerMotDePasseCompte returns the app password Nextcloud Mail must use,
// creating it (and storing it in the vault) when needed.
//
// THE VAULT ENTRY IS REUSED, NOT ROTATED, when it already exists and belongs to
// the same account: the Nextcloud Mail account stores the password it was
// created with, so a rotation on every `EnsureAccount` would silently break the
// user's mail client. The `account` key holds the Stalwart id — §9.H showed a
// re-created account gets a NEW id, and a password from the destroyed one can
// never authenticate — so a mismatch is the one case that forces a rotation.
func AssurerMotDePasseCompte(ctx context.Context, nom, adresse, idCompte string) (string, error) {
	// THE VAULT IS MANDATORY: the secret is returned once and nothing else
	// keeps a copy. Without a vault, either an existing credential cannot be
	// read or a new one would be lost at the end of the call.
	coffre := secrets.DepuisEnvironnement()
	if coffre == nil {
		return "", fmt.Errorf("no vault configured: the mailbox credential lives in ceffio/%s/%s, so internal mailboxes require OpenBao (BAO_ADDR)",
			composantCoffre, entreeCoffreCompte(nom))
	}

	identifiants, err := lireEntreeCoffre(ctx, coffre, composantCoffre, entreeCoffreCompte(nom))
	if err != nil && !secrets.EntreeAbsente(err) {
		// AN UNREACHABLE VAULT IS NOT "ABSENT": proceeding would create a new
		// password and invalidate the working one this call cannot read.
		return "", fmt.Errorf("reading the mailbox credential of %s: %w", nom, err)
	}
	if identifiants != nil {
		utilisateur := strings.TrimSpace(identifiants["user"])
		motDePasse := strings.TrimSpace(identifiants["password"])
		storedCompte := strings.TrimSpace(identifiants["account"])
		// AN EMPTY `account` COMES FROM AN OLDER ENTRY: the password is kept,
		// because destroying a credential that works to add a bookkeeping field
		// is a net loss.
		if utilisateur != "" && motDePasse != "" && (storedCompte == "" || storedCompte == idCompte) {
			return motDePasse, nil
		}
	}

	secret, err := poserMotDePasse(ctx, idCompte, descriptionMotDePasseCompte)
	if err != nil {
		return "", fmt.Errorf("creating the mailbox app password of %s: %w", nom, err)
	}
	// THE VAULT IS WRITTEN ONLY ONCE THE CREDENTIAL EXISTS: writing before
	// would store a password the server never returned.
	if err := ecrireDansCoffre(ctx, coffre, composantCoffre, entreeCoffreCompte(nom), map[string]string{
		"user":     adresse,
		"password": secret,
		"account":  idCompte,
	}); err != nil {
		return "", fmt.Errorf("storing the mailbox credential of %s: %w", nom, err)
	}
	return secret, nil
}

// compteParNom returns the account of a user, and fails when it is absent.
func compteParNom(ctx context.Context, nom string) (CompteCourriel, error) {
	compte, existe, err := compteExistant(ctx, nom)
	if err != nil {
		return CompteCourriel{}, err
	}
	if !existe {
		return CompteCourriel{}, fmt.Errorf("the mailbox account of %s does not exist", nom)
	}
	return compte, nil
}

// compteExistant is compteParNom without the error when the account is absent:
// the deletion path needs "already gone" to be a normal answer.
func compteExistant(ctx context.Context, nom string) (CompteCourriel, bool, error) {
	comptes, err := LireComptesCourriel(ctx)
	if err != nil {
		return CompteCourriel{}, false, err
	}
	compte, existe := compteNomme(comptes, nom)
	return compte, existe, nil
}

// compteNomme picks the account named `nom`, preferring the directory domain.
//
// THE PREFERENCE DECIDES WHICH ONE IS REPAIRED, NOT WHICH ONE IS TAKEN: a
// server can hold accounts of the same name in several domains, and the mail
// account of a user is the one in `ceffio.local`. A sole candidate elsewhere is
// still returned, and `AssurerCompteCourriel` moves it rather than creating a
// duplicate.
func compteNomme(comptes []CompteCourriel, nom string) (CompteCourriel, bool) {
	var candidats []CompteCourriel
	for _, compte := range comptes {
		if strings.EqualFold(compte.Nom, nom) {
			candidats = append(candidats, compte)
		}
	}
	for _, compte := range candidats {
		if compte.Domaine == DomaineComptes {
			return compte, true
		}
	}
	if len(candidats) > 0 {
		return candidats[0], true
	}
	return CompteCourriel{}, false
}

// relireCompte reads one account back, and fails when it is absent.
//
// A WRITE THAT DOES NOT READ BACK IS AN ERROR: the server refused it silently
// or the object vanished between the calls, and continuing would let the
// caller report a mailbox that does not exist.
func relireCompte(ctx context.Context, idCompte string) (CompteCourriel, error) {
	comptes, err := LireComptesCourriel(ctx)
	if err != nil {
		return CompteCourriel{}, err
	}
	for _, compte := range comptes {
		if compte.ID == idCompte {
			return compte, nil
		}
	}
	return CompteCourriel{}, fmt.Errorf("the mailbox account %s does not read back after it was written", idCompte)
}

// domainesCompte returns the ids of the directory domain and of the mail
// domain, in that order.
//
// BOTH ARE REQUIRED: without the directory domain the account cannot be created
// where the SSO login looks for it; without the mail domain the alias has no
// target. Their absence is an INCOMPLETE INSTALLATION, not an external
// prerequisite — the SSO step creates both.
func domainesCompte(ctx context.Context, domaine string) (string, string, error) {
	idLocal, err := chercherID(ctx, "x:Domain/get", "name", DomaineComptes)
	if err != nil {
		return "", "", fmt.Errorf("reading the directory domain %s: %w", DomaineComptes, err)
	}
	if idLocal == "" {
		return "", "", fmt.Errorf("the directory domain %s does not exist: the SSO setup did not complete", DomaineComptes)
	}
	idDomaine, err := chercherID(ctx, "x:Domain/get", "name", domaine)
	if err != nil {
		return "", "", fmt.Errorf("reading the mail domain %s: %w", domaine, err)
	}
	if idDomaine == "" {
		return "", "", fmt.Errorf("the mail domain %s does not exist: the SSO setup did not complete", domaine)
	}
	return idLocal, idDomaine, nil
}

// reglerQuota writes the quota of one account, in bytes.
func reglerQuota(ctx context.Context, idCompte string, quotaGio int) error {
	return majJMAPObjet(ctx, "x:Account/set", idCompte, map[string]any{
		"quotas": map[string]any{"maxDiskQuota": int64(quotaGio) * 1 << 30},
	})
}

// quotasCompte extracts the quota and the usage, in bytes.
//
// BOTH ARE BYTE COUNTS IN THE SERVER'S ANSWER (§9.G), and `usedDiskQuota` is a
// top-level read-only field while `maxDiskQuota` is nested in `quotas`. A
// missing quota stays 0, which the page renders as "no quota" — an honest
// answer for a mailbox the server does not limit yet.
func quotasCompte(compte map[string]any) (int64, int64) {
	var quota int64
	if quotas, ok := compte["quotas"].(map[string]any); ok {
		if valeur, ok := nombre(quotas["maxDiskQuota"]); ok && valeur > 0 {
			quota = int64(valeur)
		}
	}
	var utilise int64
	if valeur, ok := nombre(compte["usedDiskQuota"]); ok && valeur > 0 {
		utilise = int64(valeur)
	}
	return quota, utilise
}

// adressesAlias resolves the alias table of an account to full addresses.
//
// THE KEYS ARE INDICES, NOT AN ARRAY (§9.B): the server returns an object keyed
// "0", "1", … whose values carry `name` and `domainId`. An alias whose domain
// is unknown is skipped rather than rendered as `name@` — a half address on the
// page is worse than none.
func adressesAlias(brut any, domaines map[string]string) []string {
	var adresses []string
	for _, valeur := range aliasParIndex(brut) {
		alias, ok := valeur.(map[string]any)
		if !ok {
			continue
		}
		nom := valeurChaine(alias["name"])
		domaine := domaines[valeurChaine(alias["domainId"])]
		if nom == "" || domaine == "" {
			continue
		}
		adresses = append(adresses, nom+"@"+domaine)
	}
	sort.Strings(adresses)
	return adresses
}

// prochainIndexAlias returns the first alias index no alias occupies.
//
// THE HIGHEST INDEX + 1, NOT THE COUNT: an account whose aliases were removed
// by hand has holes (`0` gone, `1` present), and writing at `count` would
// overwrite the alias that is still there.
func prochainIndexAlias(brut any) int {
	max := -1
	for index := range aliasParIndex(brut) {
		if n, err := strconv.Atoi(index); err == nil && n > max {
			max = n
		}
	}
	return max + 1
}

// authentificationSuspendue reports whether the account refuses logins.
//
// THE SHAPE IS JUDGED, NOT DEEP-EQUALED, for the same reason as the sender's
// permissions: the server may normalise the object without changing the
// effective permission. What matters is `disabledPermissions.authenticate`.
func authentificationSuspendue(brut any) bool {
	permissions, ok := brut.(map[string]any)
	if !ok || valeurChaine(permissions["@type"]) != "Merge" {
		return false
	}
	desactivees, ok := permissions["disabledPermissions"].(map[string]any)
	if !ok {
		return false
	}
	refus, ok := desactivees["authenticate"].(bool)
	return ok && refus
}

// permissionsAvecAuthentificationSuspendue returns the permission object that
// refuses logins and KEEPS EVERY OTHER RESTRICTION.
//
// THE SAME TRAP AS THE REACTIVATION PATH, MIRRORED: some installations disable
// other permissions (an operator who barred `emailSend` on a compromised
// account), and writing a fresh `Merge` object with only `authenticate` would
// silently re-enable them for the duration of the suspension.
func permissionsAvecAuthentificationSuspendue(compte CompteCourriel) map[string]any {
	desactivees := map[string]any{}
	if permissions, ok := compte.permissionsBrutes.(map[string]any); ok {
		if existantes, ok := permissions["disabledPermissions"].(map[string]any); ok {
			for cle, valeur := range existantes {
				desactivees[cle] = valeur
			}
		}
	}
	desactivees["authenticate"] = true
	return map[string]any{"@type": "Merge", "disabledPermissions": desactivees}
}

// permissionsSansAuthentification returns the permission object that re-enables
// logins while preserving every other restriction.
func permissionsSansAuthentification(compte CompteCourriel) map[string]any {
	// THE OTHER RESTRICTIONS ARE RE-READ, NOT REMEMBERED: `CompteCourriel` only
	// keeps the authentication bit (it is all the page shows), so they come
	// from the raw object kept alongside it.
	restantes := map[string]any{}
	if permissions, ok := compte.permissionsBrutes.(map[string]any); ok {
		if desactivees, ok := permissions["disabledPermissions"].(map[string]any); ok {
			for cle, valeur := range desactivees {
				if cle != "authenticate" {
					restantes[cle] = valeur
				}
			}
		}
	}
	if len(restantes) == 0 {
		return map[string]any{"@type": "Inherit"}
	}
	return map[string]any{"@type": "Merge", "disabledPermissions": restantes}
}

// Gio returns a byte count as GiB, for the page and the CLI.
func Gio(octets int64) int {
	if octets <= 0 {
		return 0
	}
	return int(octets / (1 << 30))
}
