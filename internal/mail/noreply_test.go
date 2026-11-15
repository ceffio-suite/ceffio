// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the platform sender: the account, its single app password, the
// vault entry, and the submission login that decides whether the stored
// credential is still worth keeping.
//
// WHY THESE TESTS EXIST: the app password secret is returned ONCE and cannot be
// read back (§9.A), so "is this credential still the right one?" has no answer
// in the API — it is answered by an SMTP login, and by nothing else. That login
// is also what decides whether a rotation happens, which means a wrong decision
// here either deletes a working password or leaves a dead one in place. Both
// failures are silent at installation time and only surface when a user does
// not receive a notification, so the decisions are exercised rather than
// reviewed.
//
// THE FAKES ARE DELIBERATELY UNFRIENDLY WHERE THE SERVER IS: `x:AppPassword/*`
// answers `accountNotFound` unless the request-level `accountId` is the USER
// account, and a destroy lies with `notDestroyed` (§9.I). A fake that accepted
// the management account would make the one mistake this code must not make
// (`jmap.Client.Get`'s injected account) pass green.
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// fauxMotDePasse is one app password as the fake server stores it. The secret
// is kept here and NEVER returned by a `get`: the real server does the same,
// which is why the vault is the only copy.
type fauxMotDePasse struct {
	ID          string
	Description string
	Secret      string
}

// fauxNoreply is the in-memory JMAP endpoint of the tests: domains, accounts
// and app passwords.
type fauxNoreply struct {
	domaines    []map[string]any
	comptes     map[string]map[string]any
	motsDePasse map[string][]fauxMotDePasse // account id → app passwords
	appels      []string                    // method names, in order
	operations  []string                    // "detruire:<id>" and "creer:<id>", in order
	ecritures   []map[string]any            // `update` payload of every x:Account/set

	prochainCompte       int
	prochainMotDePasse   int
	dernierSecret        string
	mentirSurDestruction bool

	// destruction governs a `destroy` of an ACCOUNT (not of an app password):
	// "" or "ok" removes it and answers `destroyed`; "mente" removes it and
	// answers `notDestroyed:notFound` (the 1.0.3 quirk of §9.H); "refusee"
	// keeps it and answers `notDestroyed:forbidden`.
	destruction string
}

func nouveauFauxNoreply() *fauxNoreply {
	return &fauxNoreply{
		domaines: []map[string]any{
			{"id": "b", "name": "example.com"},
			{"id": "c", "name": "ceffio.local"},
		},
		comptes: map[string]map[string]any{
			"d333333": {
				"id":           "d333333",
				"name":         "adminceffio",
				"domainId":     "c",
				"emailAddress": "adminceffio@ceffio.local",
				"permissions":  map[string]any{"@type": "Inherit"},
			},
		},
		motsDePasse: map[string][]fauxMotDePasse{},
	}
}

// ajouterCompte seeds an account with an explicit domain and permission object,
// so a test can describe the state it wants to repair instead of building it
// through the code under test.
func (f *fauxNoreply) ajouterCompte(nom, idDomaine string, permissions any) string {
	f.prochainCompte++
	id := fmt.Sprintf("u%d", f.prochainCompte)
	f.comptes[id] = map[string]any{
		"id":           id,
		"name":         nom,
		"domainId":     idDomaine,
		"emailAddress": nom + "@" + f.nomDeDomaine(idDomaine),
		"permissions":  permissions,
	}
	return id
}

// ajouterMotDePasse seeds an app password on an account.
func (f *fauxNoreply) ajouterMotDePasse(idCompte, id, description, secret string) {
	f.motsDePasse[idCompte] = append(f.motsDePasse[idCompte], fauxMotDePasse{
		ID: id, Description: description, Secret: secret,
	})
}

// nomDeDomaine renders the name of a domain identifier.
func (f *fauxNoreply) nomDeDomaine(id string) string {
	for _, domaine := range f.domaines {
		if domaine["id"] == id {
			return domaine["name"].(string)
		}
	}
	return ""
}

// completer derives the read-only fields the server computes, so a test never
// asserts on a value the fake was told by hand: `emailAddress` follows the
// account name and its domain, exactly like Stalwart.
func (f *fauxNoreply) completer(compte map[string]any) {
	nom, _ := compte["name"].(string)
	idDomaine, _ := compte["domainId"].(string)
	compte["emailAddress"] = nom + "@" + f.nomDeDomaine(idDomaine)
	if compte["permissions"] == nil {
		compte["permissions"] = map[string]any{"@type": "Inherit"}
	}
}

// transport performs one JMAP exchange, like the real transport seam.
func (f *fauxNoreply) transport(_ context.Context, corps []byte) ([]byte, error) {
	var enveloppe struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	if err := json.Unmarshal(corps, &enveloppe); err != nil {
		return nil, err
	}
	if len(enveloppe.MethodCalls) == 0 {
		return nil, errors.New("empty JMAP request")
	}
	var methode string
	_ = json.Unmarshal(enveloppe.MethodCalls[0][0], &methode)
	var args map[string]any
	_ = json.Unmarshal(enveloppe.MethodCalls[0][1], &args)
	f.appels = append(f.appels, methode)

	nom, reponse := methode, map[string]any{}
	switch methode {
	case "x:Domain/get":
		reponse["list"] = f.listerDomaines()
		reponse["notFound"] = []any{}
	case "x:Account/get":
		reponse["list"] = f.listerComptes(args)
		reponse["notFound"] = []any{}
	case "x:Account/set":
		nom, reponse = f.modifierComptes(args)
	case "x:AppPassword/get":
		nom, reponse = f.listerMotsDePasse(args)
	case "x:AppPassword/set":
		nom, reponse = f.modifierMotsDePasse(args)
	default:
		nom = "error"
		reponse = map[string]any{"type": "unknownMethod", "description": "unknown method " + methode}
	}

	brut, err := json.Marshal(map[string]any{
		"methodResponses": []any{[]any{nom, reponse, "c1"}},
	})
	return brut, err
}

func (f *fauxNoreply) listerDomaines() []any {
	liste := make([]any, 0, len(f.domaines))
	for _, domaine := range f.domaines {
		liste = append(liste, copier(domaine))
	}
	return liste
}

// listerComptes answers a `x:Account/get`, filtering on the requested ids.
//
// A NIL ids LIST MEANS EVERYTHING: that is JMAP's distinction between `null`
// and an omitted list, and the production code relies on it for its by-name
// lookup.
func (f *fauxNoreply) listerComptes(args map[string]any) []any {
	var demandes []string
	if bruts, ok := args["ids"].([]any); ok {
		for _, brut := range bruts {
			if id, ok := brut.(string); ok {
				demandes = append(demandes, id)
			}
		}
	}
	liste := []any{}
	for id, compte := range f.comptes {
		if len(demandes) > 0 && !contient(demandes, id) {
			continue
		}
		liste = append(liste, copier(compte))
	}
	sort.Slice(liste, func(i, j int) bool {
		return liste[i].(map[string]any)["id"].(string) < liste[j].(map[string]any)["id"].(string)
	})
	return liste
}

// ecrireChamp writes one field of an account, honouring the POINTER KEYS the
// server accepts for nested objects: `"aliases/3"` writes index 3 of the alias
// table and leaves the others alone (§9.F). Storing it as a flat key would make
// the read-back show no alias at all, and the code under test would look
// idempotent for the wrong reason.
func (f *fauxNoreply) ecrireChamp(compte map[string]any, cle string, valeur any) {
	if index, ok := strings.CutPrefix(cle, "aliases/"); ok {
		aliases, _ := compte["aliases"].(map[string]any)
		if aliases == nil {
			aliases = map[string]any{}
			compte["aliases"] = aliases
		}
		// THE @type IS DROPPED, like the real server does on read-back.
		champs, _ := valeur.(map[string]any)
		propre := map[string]any{"name": champs["name"], "domainId": champs["domainId"], "enable": true}
		aliases[index] = propre
		return
	}
	compte[cle] = valeur
}

// modifierComptes applies a create and/or update, deriving the read-only fields
// after each write so a repair of `domainId` is observable through the address.
func (f *fauxNoreply) modifierComptes(args map[string]any) (string, map[string]any) {
	reponse := map[string]any{}
	if crees, ok := args["create"].(map[string]any); ok && len(crees) > 0 {
		cree := map[string]any{}
		for cle, brut := range crees {
			champs, _ := brut.(map[string]any)
			f.prochainCompte++
			id := fmt.Sprintf("u%d", f.prochainCompte)
			compte := copierMap(champs)
			compte["id"] = id
			f.completer(compte)
			f.comptes[id] = compte
			cree[cle] = map[string]any{"id": id}
		}
		reponse["created"] = cree
	}
	if maj, ok := args["update"].(map[string]any); ok && len(maj) > 0 {
		f.ecritures = append(f.ecritures, maj)
		modifies := map[string]any{}
		for id, brut := range maj {
			compte, present := f.comptes[id]
			if !present {
				continue
			}
			champs, _ := brut.(map[string]any)
			for cle, valeur := range champs {
				f.ecrireChamp(compte, cle, valeur)
			}
			f.completer(compte)
			modifies[id] = nil
		}
		reponse["updated"] = modifies
	}
	if bruts, ok := args["destroy"].([]any); ok && len(bruts) > 0 {
		detruits := map[string]any{}
		notDetruits := map[string]any{}
		for _, brut := range bruts {
			id, ok := brut.(string)
			if !ok {
				continue
			}
			if _, present := f.comptes[id]; !present {
				// AN ALREADY ABSENT OBJECT IS `notFound`, like the server: the
				// deletion that a retry asks for has nothing left to do.
				notDetruits[id] = map[string]any{"type": "notFound"}
				continue
			}
			if f.destruction == "refusee" {
				notDetruits[id] = map[string]any{"type": "forbidden"}
				continue
			}
			delete(f.comptes, id)
			delete(f.motsDePasse, id)
			f.operations = append(f.operations, "detruire-compte:"+id)
			if f.destruction == "mente" {
				notDetruits[id] = map[string]any{"type": "notFound"}
				continue
			}
			detruits[id] = nil
		}
		if len(detruits) > 0 {
			reponse["destroyed"] = detruits
		}
		if len(notDetruits) > 0 {
			reponse["notDestroyed"] = notDetruits
		}
	}
	return "x:Account/set", reponse
}

// listerMotsDePasse answers a `x:AppPassword/get` for the USER account only.
//
// ANY OTHER accountId IS REFUSED, because that is what the server does: an app
// password list asked for the management account answers `accountNotFound`. A
// fake that was more permissive would hide the exact bug the production code
// documents (§9.A).
func (f *fauxNoreply) listerMotsDePasse(args map[string]any) (string, map[string]any) {
	if nom, refus := f.compteDesMotsDePasse(args); refus != "" {
		return nom, map[string]any{"type": "accountNotFound", "description": refus}
	}
	idCompte, _ := args["accountId"].(string)
	var demandes []string
	if bruts, ok := args["ids"].([]any); ok {
		for _, brut := range bruts {
			if id, ok := brut.(string); ok {
				demandes = append(demandes, id)
			}
		}
	}
	liste := []any{}
	for _, motDePasse := range f.motsDePasse[idCompte] {
		if len(demandes) > 0 && !contient(demandes, motDePasse.ID) {
			continue
		}
		// THE SECRET IS NEVER RETURNED BY A READ: the server shows it once, at
		// creation. Returning it here would let the code under test believe a
		// stored password is readable.
		liste = append(liste, map[string]any{
			"id":          motDePasse.ID,
			"description": motDePasse.Description,
		})
	}
	return "x:AppPassword/get", map[string]any{"list": liste, "notFound": []any{}}
}

// modifierMotsDePasse applies a create and/or destroy, and can LIE about the
// destroy: with `mentirSurDestruction`, the object is removed while the body
// reports `notDestroyed:notFound` — the 1.0.3 quirk of §9.I that forces a
// decision on the read-back.
func (f *fauxNoreply) modifierMotsDePasse(args map[string]any) (string, map[string]any) {
	if nom, refus := f.compteDesMotsDePasse(args); refus != "" {
		return nom, map[string]any{"type": "accountNotFound", "description": refus}
	}
	idCompte, _ := args["accountId"].(string)
	reponse := map[string]any{}
	if bruts, ok := args["destroy"].([]any); ok && len(bruts) > 0 {
		var detruits []string
		for _, brut := range bruts {
			if id, ok := brut.(string); ok {
				detruits = append(detruits, id)
				f.operations = append(f.operations, "detruire:"+id)
			}
		}
		restants := f.motsDePasse[idCompte][:0]
		for _, motDePasse := range f.motsDePasse[idCompte] {
			if !contient(detruits, motDePasse.ID) {
				restants = append(restants, motDePasse)
			}
		}
		f.motsDePasse[idCompte] = restants
		if f.mentirSurDestruction {
			notDetruits := map[string]any{}
			for _, id := range detruits {
				notDetruits[id] = map[string]any{"type": "notFound"}
			}
			reponse["notDestroyed"] = notDetruits
		} else {
			detruitsReponse := map[string]any{}
			for _, id := range detruits {
				detruitsReponse[id] = nil
			}
			reponse["destroyed"] = detruitsReponse
		}
	}
	if crees, ok := args["create"].(map[string]any); ok && len(crees) > 0 {
		cree := map[string]any{}
		for cle, brut := range crees {
			champs, _ := brut.(map[string]any)
			description, _ := champs["description"].(string)
			f.prochainMotDePasse++
			id := fmt.Sprintf("ap%d", f.prochainMotDePasse)
			secret := fmt.Sprintf("secret-%d", f.prochainMotDePasse)
			f.motsDePasse[idCompte] = append(f.motsDePasse[idCompte], fauxMotDePasse{
				ID: id, Description: description, Secret: secret,
			})
			f.dernierSecret = secret
			f.operations = append(f.operations, "creer:"+id)
			// THE SECRET IS IN THE CREATE ANSWER ONLY, which is the whole
			// reason the vault exists.
			cree[cle] = map[string]any{"id": id, "secret": secret}
		}
		reponse["created"] = cree
	}
	return "x:AppPassword/set", reponse
}

// compteDesMotsDePasse checks the request-level accountId and returns the
// refusal text when it is not a user account. An EMPTY identifier is refused
// too: falling back on the management account is the mistake to catch.
func (f *fauxNoreply) compteDesMotsDePasse(args map[string]any) (string, string) {
	idCompte, _ := args["accountId"].(string)
	if idCompte == "" {
		return "error", "no accountId at the request level"
	}
	if idCompte == "d333333" || f.comptes[idCompte] == nil {
		return "error", "account " + idCompte + " not found: app passwords belong to a user account"
	}
	return "", ""
}

// motDePasseDe returns the app passwords of an account.
func (f *fauxNoreply) motDePasseDe(idCompte string) []fauxMotDePasse {
	return f.motsDePasse[idCompte]
}

// fauxCoffre is the vault: an in-memory map behind the two seams, so a test
// never reaches OpenBao.
type fauxCoffre struct {
	entrees      map[string]map[string]string // "composant/nom" → entry
	lectures     int
	ecritures    int
	suppressions int
}

func nouveauFauxCoffre() *fauxCoffre {
	return &fauxCoffre{entrees: map[string]map[string]string{}}
}

func (f *fauxCoffre) lire(_ context.Context, _ *secrets.Coffre, composant, nom string) (map[string]string, error) {
	f.lectures++
	entree, present := f.entrees[composant+"/"+nom]
	if !present {
		// THE SENTINEL MATTERS: production distinguishes "absent entry" (create
		// one) from "unreachable vault" (fail without rotating).
		return nil, fmt.Errorf("no entry %s/%s: %w", composant, nom, secrets.ErrEntreeAbsente)
	}
	return copierEntree(entree), nil
}

func (f *fauxCoffre) ecrire(_ context.Context, _ *secrets.Coffre, composant, nom string, donnees map[string]string) error {
	f.ecritures++
	f.entrees[composant+"/"+nom] = copierEntree(donnees)
	return nil
}

// supprimer stands in for the DELETE call, and FOLLOWS THE REAL CONTRACT: an
// absent entry is a success (the goal is "no credential left"), which is what
// lets a retried deletion converge instead of failing on its second run.
func (f *fauxCoffre) supprimer(_ context.Context, _ *secrets.Coffre, composant, nom string) error {
	f.suppressions++
	delete(f.entrees, composant+"/"+nom)
	return nil
}

// entree returns a copy of a stored entry.
func (f *fauxCoffre) entree(composant, nom string) map[string]string {
	return copierEntree(f.entrees[composant+"/"+nom])
}

// fauxVerification records the submission logins and answers through a
// function, so a test states which password is refused rather than modelling
// the whole SMTP dialogue.
type fauxVerification struct {
	appels  []identifiants
	refuser func(utilisateur, motDePasse string) error
}

type identifiants struct {
	Hote        string
	Utilisateur string
	MotDePasse  string
}

func (f *fauxVerification) verifier(_ context.Context, hote, utilisateur, motDePasse string) error {
	f.appels = append(f.appels, identifiants{Hote: hote, Utilisateur: utilisateur, MotDePasse: motDePasse})
	if f.refuser != nil {
		return f.refuser(utilisateur, motDePasse)
	}
	return nil
}

// banc is the set of fakes one test works with.
type banc struct {
	serveur *fauxNoreply
	coffre  *fauxCoffre
	smtp    *fauxVerification
}

// installer substitutes every seam, restores them at the end, and primes the
// environment: a vault address, and NO mail-domain override (a developer's
// shell must not change the host the verification is asserted on).
func installer(t *testing.T) *banc {
	t.Helper()
	t.Setenv("BAO_ADDR", "https://bao.example.com")
	t.Setenv("BAO_FORMAT", "")
	t.Setenv("CEFFIO_MAIL_DOMAIN", "")
	b := &banc{
		serveur: nouveauFauxNoreply(),
		coffre:  nouveauFauxCoffre(),
		smtp:    &fauxVerification{},
	}
	remplacer(t, &transportJMAP, b.serveur.transport)
	remplacer(t, &lireEntreeCoffre, b.coffre.lire)
	remplacer(t, &ecrireDansCoffre, b.coffre.ecrire)
	remplacer(t, &supprimerEntreeCoffre, b.coffre.supprimer)
	remplacer(t, &verifierSoumission, b.smtp.verifier)
	return b
}

// TestAssurerNoreplyCreeLeCompteEtLeMotDePasse: on a fresh installation, the
// sender account is created in the mail domain with reception disabled, exactly
// one app password is created, the credential is stored, and the submission
// login is attempted with it.
func TestAssurerNoreplyCreeLeCompteEtLeMotDePasse(t *testing.T) {
	b := installer(t)
	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("AssurerNoreply: %v", err)
	}

	compte := b.serveur.compteNomme("noreply")
	if compte == nil {
		t.Fatalf("no account named noreply was created: %v", b.serveur.comptes)
	}
	if compte["domainId"] != "b" {
		t.Errorf("domainId %v, expected the identifier of example.com (b)", compte["domainId"])
	}
	if compte["emailAddress"] != "noreply@example.com" {
		t.Errorf("emailAddress %v, expected noreply@example.com", compte["emailAddress"])
	}
	if !permissionsNoreplyConformes(compte["permissions"]) {
		t.Errorf("permissions %v, expected Merge with emailReceive disabled", compte["permissions"])
	}

	motsDePasse := b.serveur.motDePasseDe(compte["id"].(string))
	if len(motsDePasse) != 1 {
		t.Fatalf("expected 1 app password, got %d: %v", len(motsDePasse), motsDePasse)
	}
	if motsDePasse[0].Description != descriptionMotDePasse {
		t.Errorf("description %q, expected %q", motsDePasse[0].Description, descriptionMotDePasse)
	}

	entree := b.coffre.entree(composantCoffre, entreeCoffre)
	if entree["user"] != "noreply@example.com" {
		t.Errorf("vault user %q, expected noreply@example.com", entree["user"])
	}
	if entree["password"] != b.serveur.dernierSecret || entree["password"] == "" {
		t.Errorf("vault password %q is not the secret the server returned (%q)", entree["password"], b.serveur.dernierSecret)
	}
	if len(b.smtp.appels) != 1 {
		t.Fatalf("expected 1 submission login, got %d: %v", len(b.smtp.appels), b.smtp.appels)
	}
	essai := b.smtp.appels[0]
	if essai.Hote != "mail.example.com" {
		t.Errorf("verified on %q, expected mail.example.com", essai.Hote)
	}
	if essai.Utilisateur != "noreply@example.com" || essai.MotDePasse != entree["password"] {
		t.Errorf("logged in as %q with the wrong secret: %v", essai.Utilisateur, essai)
	}
	if len(b.serveur.operations) != 1 || !strings.HasPrefix(b.serveur.operations[0], "creer:") {
		t.Errorf("expected one creation and no destruction, got %v", b.serveur.operations)
	}
}

// TestAssurerNoreplyNeToucheARienSiLeMotDePasseFonctionne: a credential the
// server accepts means NOTHING is read from or written to JMAP.
//
// THIS IS THE PATH EVERY UPGRADE TAKES: a write per replay would bump the
// account's modification counter for a password that has not changed, and a
// rotating secret would invalidate the configuration Nextcloud and Keycloak
// already hold.
func TestAssurerNoreplyNeToucheARienSiLeMotDePasseFonctionne(t *testing.T) {
	b := installer(t)
	b.coffre.entrees["mail/noreply"] = map[string]string{
		"user":     "noreply@example.com",
		"password": "mot-de-passe-en-place",
	}
	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("AssurerNoreply: %v", err)
	}
	if len(b.serveur.appels) != 0 {
		t.Errorf("the JMAP server was called %d time(s) for a credential that works: %v", len(b.serveur.appels), b.serveur.appels)
	}
	if b.coffre.ecritures != 0 {
		t.Errorf("the vault was written %d time(s) for a credential that works", b.coffre.ecritures)
	}
	if len(b.smtp.appels) != 1 || b.smtp.appels[0].MotDePasse != "mot-de-passe-en-place" {
		t.Errorf("the stored credential should have been the one verified, got %v", b.smtp.appels)
	}
}

// TestAssurerNoreplyTourneLeMotDePasseRefuse: a refused login is the only
// reason to rotate.
//
// THE STALE PASSWORD MUST GO BEFORE THE NEW ONE IS CREATED: the account is
// capped at five app passwords (§9.A), so creating first would fail as soon as
// an operator's own passwords fill the slots. And an operator's password must
// survive: only the one carrying our description is ours.
func TestAssurerNoreplyTourneLeMotDePasseRefuse(t *testing.T) {
	b := installer(t)
	compte := b.serveur.ajouterCompte("noreply", "b", map[string]any{
		"@type":               "Merge",
		"disabledPermissions": map[string]any{"emailReceive": true},
	})
	b.serveur.ajouterMotDePasse(compte, "ap-vieux", descriptionMotDePasse, "secret-perime")
	b.serveur.ajouterMotDePasse(compte, "ap-telephone", "mon-telephone", "secret-du-telephone")
	b.coffre.entrees["mail/noreply"] = map[string]string{
		"user":     "noreply@example.com",
		"password": "secret-perime",
	}
	b.smtp.refuser = func(_, motDePasse string) error {
		if motDePasse == "secret-perime" {
			return fmt.Errorf("%w: 454 4.7.0 authentication failed", errIdentifiantsRefuses)
		}
		return nil
	}

	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("AssurerNoreply: %v", err)
	}

	restants := b.serveur.motDePasseDe(compte)
	if len(restants) != 2 {
		t.Fatalf("expected the operator's password plus the new one, got %v", restants)
	}
	plates := 0
	for _, motDePasse := range restants {
		if motDePasse.Description == descriptionMotDePasse {
			plates++
			if motDePasse.Secret == "secret-perime" {
				t.Errorf("the stale platform sender password is still present")
			}
		}
	}
	if plates != 1 {
		t.Errorf("expected exactly 1 platform sender password, got %d: %v", plates, restants)
	}
	entree := b.coffre.entree(composantCoffre, entreeCoffre)
	if entree["password"] == "secret-perime" || entree["password"] == "" {
		t.Errorf("the vault still holds the refused password (%q)", entree["password"])
	}
	if entree["password"] != b.serveur.dernierSecret {
		t.Errorf("the vault holds %q, not the secret the server returned (%q)", entree["password"], b.serveur.dernierSecret)
	}
	if len(b.smtp.appels) != 2 {
		t.Fatalf("expected 2 submission logins (the refused one, then the new one), got %v", b.smtp.appels)
	}
	if b.smtp.appels[0].MotDePasse != "secret-perime" || b.smtp.appels[1].MotDePasse != entree["password"] {
		t.Errorf("the logins did not go old-then-new: %v", b.smtp.appels)
	}
	if len(b.serveur.operations) < 2 {
		t.Fatalf("expected a destroy and a create, got %v", b.serveur.operations)
	}
	if !strings.HasPrefix(b.serveur.operations[0], "detruire:") || !strings.HasPrefix(b.serveur.operations[1], "creer:") {
		t.Errorf("the stale password must be destroyed BEFORE the new one is created, got %v", b.serveur.operations)
	}
}

// TestAssurerNoreplyGardeLeMotDePasseSiLeServeurEstInjoignable: a network
// failure is not a verdict on the credential.
//
// ROTATING HERE WOULD LOSE A WORKING PASSWORD: the new secret would be
// unusable for the same network reason, and the old one is gone. The install
// must not fail either — reachability is reported by the `smtp` check, with an
// actionable message.
func TestAssurerNoreplyGardeLeMotDePasseSiLeServeurEstInjoignable(t *testing.T) {
	b := installer(t)
	b.coffre.entrees["mail/noreply"] = map[string]string{
		"user":     "noreply@example.com",
		"password": "mot-de-passe-en-place",
	}
	b.smtp.refuser = func(_, _ string) error {
		return errors.New("cannot reach mail.example.com:465: connection refused")
	}
	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("an unreachable submission port must not fail the installation: %v", err)
	}
	if len(b.serveur.appels) != 0 {
		t.Errorf("the credential was rotated although the server was only unreachable: %v", b.serveur.appels)
	}
	if b.coffre.ecritures != 0 {
		t.Errorf("the vault was rewritten although the server was only unreachable")
	}
}

// TestAssurerNoreplyNeReecritPasUnCompteConforme: an account that already
// carries the right domain and permissions gets no `x:Account/set` at all.
func TestAssurerNoreplyNeReecritPasUnCompteConforme(t *testing.T) {
	b := installer(t)
	b.serveur.ajouterCompte("noreply", "b", map[string]any{
		"@type":               "Merge",
		"disabledPermissions": map[string]any{"emailReceive": true},
	})
	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("AssurerNoreply: %v", err)
	}
	if nombreAppels(b.serveur.appels, "x:Account/set") != 0 {
		t.Errorf("a conforming account was rewritten: %v", b.serveur.appels)
	}
}

// TestAssurerNoreplyRepareLeDomaineEtLesPermissions: an account moved to
// another domain, or carrying inherited permissions, is repaired in ONE write —
// and the address is read back afterwards, because it follows the domain.
func TestAssurerNoreplyRepareLeDomaineEtLesPermissions(t *testing.T) {
	b := installer(t)
	compte := b.serveur.ajouterCompte("noreply", "c", map[string]any{"@type": "Inherit"})
	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("AssurerNoreply: %v", err)
	}
	if len(b.serveur.ecritures) != 1 {
		t.Fatalf("expected exactly one x:Account/set update, got %d: %v", len(b.serveur.ecritures), b.serveur.ecritures)
	}
	champs, _ := b.serveur.ecritures[0][compte].(map[string]any)
	if champs["domainId"] != "b" {
		t.Errorf("domainId not repaired in the same write: %v", champs)
	}
	if !permissionsNoreplyConformes(champs["permissions"]) {
		t.Errorf("permissions not repaired in the same write: %v", champs)
	}
	apres := b.serveur.comptes[compte]
	if apres["emailAddress"] != "noreply@example.com" {
		t.Errorf("the address was not re-read after the domain repair: %v", apres["emailAddress"])
	}
	entree := b.coffre.entree(composantCoffre, entreeCoffre)
	if entree["user"] != "noreply@example.com" {
		t.Errorf("the vault stores %q as the login, expected the repaired address", entree["user"])
	}
}

// TestAssurerNoreplyIgnoreUneDestructionMenteuse: the destroy answer is not the
// authority (§9.I); the read-back is.
//
// 1.0.3 answers `notDestroyed:notFound` for an app password it HAS deleted. A
// caller that trusted the body would refuse to rotate, on every run, for ever.
func TestAssurerNoreplyIgnoreUneDestructionMenteuse(t *testing.T) {
	b := installer(t)
	compte := b.serveur.ajouterCompte("noreply", "b", map[string]any{
		"@type":               "Merge",
		"disabledPermissions": map[string]any{"emailReceive": true},
	})
	b.serveur.ajouterMotDePasse(compte, "ap-vieux", descriptionMotDePasse, "secret-perime")
	b.serveur.mentirSurDestruction = true
	b.coffre.entrees["mail/noreply"] = map[string]string{
		"user":     "noreply@example.com",
		"password": "secret-perime",
	}
	b.smtp.refuser = func(_, motDePasse string) error {
		if motDePasse == "secret-perime" {
			return fmt.Errorf("%w: 454 4.7.0 authentication failed", errIdentifiantsRefuses)
		}
		return nil
	}

	if err := AssurerNoreply(context.Background(), "example.com"); err != nil {
		t.Fatalf("a lying destroy answer must not stop the rotation: %v", err)
	}
	restants := b.serveur.motDePasseDe(compte)
	plates := 0
	for _, motDePasse := range restants {
		if motDePasse.Description == descriptionMotDePasse {
			plates++
		}
	}
	if plates != 1 {
		t.Errorf("expected exactly 1 platform sender password after the rotation, got %v", restants)
	}
	if b.coffre.entree(composantCoffre, entreeCoffre)["password"] != b.serveur.dernierSecret {
		t.Errorf("the vault does not hold the new secret")
	}
}

// TestAssurerNoreplyRefuseSansCoffre: without a vault the credential has no
// home, so this is an error and not a warning.
//
// THE SILENT FAILURE THIS PREVENTS: `secrets.EcrireDansCoffre` does nothing
// when no vault is configured. Creating a password then would leave the ONE
// copy of the secret in memory only — the next run would find nothing, rotate,
// and lose it again, all while reporting success.
func TestAssurerNoreplyRefuseSansCoffre(t *testing.T) {
	b := installer(t)
	t.Setenv("BAO_ADDR", "")
	err := AssurerNoreply(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected an error when no vault is configured")
	}
	if !strings.Contains(err.Error(), "OpenBao") {
		t.Errorf("the error should name the missing vault (OpenBao), got: %v", err)
	}
	if len(b.serveur.appels) != 0 {
		t.Errorf("no JMAP call should be made without a vault: %v", b.serveur.appels)
	}
}

// TestAssurerNoreplyRefuseUnDomaineInconnu: the domain is created by the SSO
// setup, so its absence is an incomplete installation.
func TestAssurerNoreplyRefuseUnDomaineInconnu(t *testing.T) {
	b := installer(t)
	err := AssurerNoreply(context.Background(), "autre.example")
	if err == nil {
		t.Fatal("expected an error for a mail domain that does not exist")
	}
	if !strings.Contains(err.Error(), "SSO") {
		t.Errorf("the error should name the SSO setup as the cause, got: %v", err)
	}
	if len(b.smtp.appels) != 0 {
		t.Errorf("no submission login should be attempted without a domain: %v", b.smtp.appels)
	}
}

// ---------------------------------------------------------------------------
// Fixtures helpers
// ---------------------------------------------------------------------------

// compteNomme returns the first account carrying a name, or nil.
func (f *fauxNoreply) compteNomme(nom string) map[string]any {
	for _, compte := range f.comptes {
		if compte["name"] == nom {
			return compte
		}
	}
	return nil
}

// nombreAppels counts the calls to one method.
func nombreAppels(appels []string, methode string) int {
	nombre := 0
	for _, appel := range appels {
		if appel == methode {
			nombre++
		}
	}
	return nombre
}

// contient reports whether a list holds a value.
func contient(liste []string, valeur string) bool {
	for _, element := range liste {
		if element == valeur {
			return true
		}
	}
	return false
}

// copier deep-copies a JSON-shaped object, so the code under test cannot mutate
// the fake's state and make a later assertion pass for the wrong reason.
func copier(objet map[string]any) map[string]any {
	brut, _ := json.Marshal(objet)
	var copie map[string]any
	_ = json.Unmarshal(brut, &copie)
	return copie
}

// copierMap deep-copies a map, tolerating a nil source.
func copierMap(objet map[string]any) map[string]any {
	if objet == nil {
		return map[string]any{}
	}
	return copier(objet)
}

// copierEntree deep-copies a vault entry, tolerating a nil source.
func copierEntree(entree map[string]string) map[string]string {
	copie := map[string]string{}
	for cle, valeur := range entree {
		copie[cle] = valeur
	}
	return copie
}
