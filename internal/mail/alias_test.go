// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the RFC 2142 aliases: postmaster@ and abuse@ must exist, on the
// admin account, exactly once, and a second installation must write nothing.
//
// WHY THESE TESTS EXIST: the alias is written through a POINTER key
// (`"aliases/<index>"`, POC 9.F) because Stalwart 1.0.3 has no `x:Alias/*`
// method. An index that is not free does not fail — it REPLACES the alias that
// was there, silently, and the loser is a user's address. And the read-back is
// not decorative: the write answers `{"updated":{"<id>":null}}`, which says the
// account was touched, not that these addresses exist.
package mail

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// fauxComptes is the in-memory JMAP endpoint holding domains and accounts, with
// the pointer-key shape the server accepts.
type fauxComptes struct {
	domaines  []map[string]any
	comptes   map[string]map[string]any // id → account
	appels    []string
	ecritures []map[string]any // the `update` payload of every x:Account/set
}

func nouveauFauxComptes() *fauxComptes {
	return &fauxComptes{
		domaines: []map[string]any{
			{"id": "b", "name": "example.com"},
			{"id": "c", "name": "ceffio.local"},
		},
		comptes: map[string]map[string]any{
			"d333333": {"id": "d333333", "name": "adminceffio", "aliases": map[string]any{}},
		},
	}
}

// avecAlias primes an existing alias at an index.
func (f *fauxComptes) avecAlias(index, nom, idDomaine string) {
	aliases := f.comptes["d333333"]["aliases"].(map[string]any)
	aliases[index] = map[string]any{"name": nom, "domainId": idDomaine, "enable": true}
}

func (f *fauxComptes) transport(_ context.Context, corps []byte) ([]byte, error) {
	var enveloppe struct {
		MethodCalls [][]json.RawMessage `json:"methodCalls"`
	}
	if err := json.Unmarshal(corps, &enveloppe); err != nil {
		return nil, err
	}
	var methode string
	_ = json.Unmarshal(enveloppe.MethodCalls[0][0], &methode)
	var args map[string]any
	_ = json.Unmarshal(enveloppe.MethodCalls[0][1], &args)
	f.appels = append(f.appels, methode)

	reponse := map[string]any{}
	switch methode {
	case "x:Domain/get":
		reponse["list"] = f.domaines
		reponse["notFound"] = []any{}
	case "x:Account/get":
		reponse["list"] = f.listeComptes(args)
		reponse["notFound"] = []any{}
	case "x:Account/set":
		maj, _ := args["update"].(map[string]any)
		f.ecritures = append(f.ecritures, maj)
		reponse["updated"] = f.appliquer(maj)
	default:
		reponse["list"] = []any{}
	}
	brut, err := json.Marshal(map[string]any{
		"methodResponses": []any{[]any{methode, reponse, "c1"}},
	})
	return brut, err
}

func (f *fauxComptes) listeComptes(args map[string]any) []any {
	demandes, _ := args["ids"].([]any)
	var liste []any
	for id, compte := range f.comptes {
		if len(demandes) > 0 {
			trouve := false
			for _, d := range demandes {
				if d == id {
					trouve = true
				}
			}
			if !trouve {
				continue
			}
		}
		// A DEEP COPY, so the code under test cannot mutate the fake's state by
		// accident and make a later assertion pass for the wrong reason.
		brut, _ := json.Marshal(compte)
		var copie map[string]any
		_ = json.Unmarshal(brut, &copie)
		liste = append(liste, copie)
	}
	sort.Slice(liste, func(i, j int) bool {
		return liste[i].(map[string]any)["id"].(string) < liste[j].(map[string]any)["id"].(string)
	})
	return liste
}

// appliquer applies a pointer-key update, which is what the real server does:
// `"aliases/3"` writes index 3 and leaves the others alone.
func (f *fauxComptes) appliquer(maj map[string]any) map[string]any {
	updated := map[string]any{}
	for id, champs := range maj {
		compte, ok := f.comptes[id]
		if !ok {
			continue
		}
		alias, _ := compte["aliases"].(map[string]any)
		champsMap, _ := champs.(map[string]any)
		for cle, valeur := range champsMap {
			if index, ok := strings.CutPrefix(cle, "aliases/"); ok {
				// THE @type IS DROPPED, like the real server does on read-back
				// (POC 9.F): a test that kept it would accept an address built
				// from a field the server never returns.
				m, _ := valeur.(map[string]any)
				propre := map[string]any{"name": m["name"], "domainId": m["domainId"], "enable": true}
				alias[index] = propre
			}
		}
		updated[id] = nil
	}
	return updated
}

// installer checks the transport, restores the real one, and returns the fake.
func installerFauxComptes(t *testing.T) *fauxComptes {
	t.Helper()
	faux := nouveauFauxComptes()
	ancien := transportJMAP
	transportJMAP = faux.transport
	t.Cleanup(func() { transportJMAP = ancien })
	return faux
}

// TestAssurerAliasCreeLesDeuxAdresses: on a fresh account, both aliases are
// written at the first two free indices, with the mail domain's identifier.
func TestAssurerAliasCreeLesDeuxAdresses(t *testing.T) {
	faux := installerFauxComptes(t)
	if err := AssurerAlias(context.Background(), "example.com", "adminceffio"); err != nil {
		t.Fatalf("AssurerAlias: %v", err)
	}
	alias := faux.comptes["d333333"]["aliases"].(map[string]any)
	if len(alias) != 2 {
		t.Fatalf("expected 2 aliases, got %d: %v", len(alias), alias)
	}
	for index, attendu := range map[string]string{"0": "postmaster", "1": "abuse"} {
		m, ok := alias[index].(map[string]any)
		if !ok {
			t.Fatalf("alias %s missing: %v", index, alias)
		}
		if m["name"] != attendu {
			t.Errorf("alias %s: name %v, expected %s", index, m["name"], attendu)
		}
		if m["domainId"] != "b" {
			t.Errorf("alias %s: domainId %v, expected the identifier of example.com (b)", index, m["domainId"])
		}
	}
}

// TestAssurerAliasEstIdempotent: a second call writes nothing at all.
//
// THIS IS THE ASSERTION THAT MATTERS ON EVERY `upgrade`: the module is replayed
// at each version, and a write per replay would bump the account's modification
// counter forever.
func TestAssurerAliasEstIdempotent(t *testing.T) {
	faux := installerFauxComptes(t)
	ctx := context.Background()
	if err := AssurerAlias(ctx, "example.com", "adminceffio"); err != nil {
		t.Fatalf("first AssurerAlias: %v", err)
	}
	avant := len(faux.ecritures)
	if err := AssurerAlias(ctx, "example.com", "adminceffio"); err != nil {
		t.Fatalf("second AssurerAlias: %v", err)
	}
	if len(faux.ecritures) != avant {
		t.Fatalf("the second run wrote %d time(s) instead of 0: %v",
			len(faux.ecritures)-avant, faux.ecritures[avant:])
	}
}

// TestAssurerAliasNeRemplacePasUnAliasExistant: an alias an operator created
// stays where it is, and the missing one goes to the next FREE index.
func TestAssurerAliasNeRemplacePasUnAliasExistant(t *testing.T) {
	faux := installerFauxComptes(t)
	faux.avecAlias("0", "postmaster", "b")
	faux.avecAlias("1", "sales", "b")
	if err := AssurerAlias(context.Background(), "example.com", "adminceffio"); err != nil {
		t.Fatalf("AssurerAlias: %v", err)
	}
	alias := faux.comptes["d333333"]["aliases"].(map[string]any)
	vendre, _ := alias["1"].(map[string]any)
	if vendre == nil || vendre["name"] != "sales" {
		t.Fatalf("the existing alias at index 1 was overwritten: %v", alias)
	}
	abuse, _ := alias["2"].(map[string]any)
	if abuse == nil || abuse["name"] != "abuse" {
		t.Fatalf("abuse should have been written at the first free index (2): %v", alias)
	}
	if len(alias) != 3 {
		t.Fatalf("expected 3 aliases (2 existing + 1 added), got %d: %v", len(alias), alias)
	}
}

// TestAssurerAliasRefuseUnDomaineAbsent: the domain is created by the SSO setup,
// so its absence is an incomplete installation, not an external prerequisite —
// continuing would write an alias pointing nowhere.
func TestAssurerAliasRefuseUnDomaineAbsent(t *testing.T) {
	installerFauxComptes(t)
	err := AssurerAlias(context.Background(), "autre.example", "adminceffio")
	if err == nil {
		t.Fatal("expected an error for a mail domain that does not exist")
	}
	if !strings.Contains(err.Error(), "SSO") {
		t.Errorf("the error should name the SSO setup as the cause, got: %v", err)
	}
}
