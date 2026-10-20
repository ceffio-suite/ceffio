// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestLeGroupeDAccesEstDeclare : one field, required, with a pattern.
//
// A FREE-TEXT LIST WITHOUT VALIDATION IS THE TRAP: the authorization compares the
// token's `email` claim against these EXACT strings, so a typo does not degrade the
// rule — it refuses the person it meant to allow, with a Keycloak account that is
// otherwise perfect.
func TestLeGroupeDAccesEstDeclare(t *testing.T) {
	g := (&longhornUIModule{}).Settings()
	if len(g) != 1 || g[0].ID != groupeAcces {
		t.Fatalf("groupes = %v, attendu un seul groupe %q", g, groupeAcces)
	}
	if len(g[0].Fields) != 1 {
		t.Fatalf("%d champ(s), attendu un seul", len(g[0].Fields))
	}
	f := g[0].Fields[0]
	if f.Key != "allowed_emails" {
		t.Errorf("clé = %q", f.Key)
	}
	if !f.Required {
		t.Error("le champ n'est pas Required : une sauvegarde vide laisserait la liste " +
			"vide et le proxy refuserait tout le monde")
	}
	if f.Pattern == "" {
		t.Error("aucun Pattern : une adresse mal formée serait acceptée, et refuserait " +
			"ensuite la bonne personne")
	}
}

// TestUneListeVideEstRefusee : the proxy would refuse everyone, including the person who
// just saved.
func TestUneListeVideEstRefusee(t *testing.T) {
	m := &longhornUIModule{}
	if err := m.Validate(groupeAcces, module.Values{"allowed_emails": ""}); err == nil {
		t.Fatal("une liste vide a été acceptée : l'interface refuserait tout le monde")
	}
	if err := m.Validate(groupeAcces, module.Values{"allowed_emails": "   "}); err == nil {
		t.Fatal("une liste blanche a été acceptée")
	}
}

// TestUneAdresseMalFormeeEstNommee : the error names the offending address.
//
// "the list is invalid" sends the operator to read four addresses; naming one is what
// makes it a fix rather than a puzzle.
func TestUneAdresseMalFormeeEstNommee(t *testing.T) {
	m := &longhornUIModule{}
	err := m.Validate(groupeAcces, module.Values{
		"allowed_emails": "adminceffio@ceffio.local, pas-une-adresse",
	})
	if err == nil {
		t.Fatal("une adresse mal formée a été acceptée")
	}
	if !strings.Contains(err.Error(), "pas-une-adresse") {
		t.Errorf("l'erreur ne nomme pas l'adresse fautive : %v", err)
	}
}

// TestPlusieursAdressesSontAcceptees : the field is a list, not one address.
func TestPlusieursAdressesSontAcceptees(t *testing.T) {
	m := &longhornUIModule{}
	for _, cas := range []string{
		"adminceffio@ceffio.local",
		"a@b.fr,c@d.fr",
		"a@b.fr, c@d.fr",
		"jean.dupont+admin@sous.domaine.example.org",
	} {
		if err := m.Validate(groupeAcces, module.Values{"allowed_emails": cas}); err != nil {
			t.Errorf("%q refusé : %v", cas, err)
		}
	}
}

// TestLeDefautEstLAdministrateur : the module is usable the moment it is installed.
func TestLeDefautEstLAdministrateur(t *testing.T) {
	m := &longhornUIModule{}
	v, err := m.Current(context.Background(), module.Env{}, groupeAcces)
	if err != nil {
		t.Fatalf("Current sans store : %v", err)
	}
	if v["allowed_emails"] != adresseDefaut {
		t.Errorf("défaut = %q, attendu %q : une liste vide par défaut produirait un proxy "+
			"qui refuse la personne qui vient de l'installer", v["allowed_emails"], adresseDefaut)
	}
}

// TestUnGroupeInconnuEstRefuse : a programming error, not an empty success.
func TestUnGroupeInconnuEstRefuse(t *testing.T) {
	m := &longhornUIModule{}
	if err := m.Validate("nope", nil); err == nil {
		t.Error("groupe inconnu accepté par Validate")
	}
	if _, err := m.Current(context.Background(), module.Env{}, "nope"); err == nil {
		t.Error("groupe inconnu accepté par Current")
	}
	if err := m.Apply(context.Background(), module.Env{}, "nope", nil); err == nil {
		t.Error("groupe inconnu accepté par Apply")
	}
}

// TestLeTestDitCeQuIlFait : the console shows a test button; it must not claim to have
// verified something it cannot.
func TestLeTestDitCeQuIlFait(t *testing.T) {
	m := &longhornUIModule{}
	r := m.Test(context.Background(), module.Env{}, groupeAcces,
		module.Values{"allowed_emails": adresseDefaut})
	if !r.OK {
		t.Errorf("le test échoue sur une liste valide : %s", r.Detail)
	}
	if !strings.Contains(r.Detail, "1 address") {
		t.Errorf("le test ne compte pas les adresses : %q", r.Detail)
	}

	// AN INVALID LIST IS REPORTED BY THE SAME BUTTON, with the real reason.
	ko := m.Test(context.Background(), module.Env{}, groupeAcces,
		module.Values{"allowed_emails": "pas-une-adresse"})
	if ko.OK {
		t.Error("le test accepte une liste invalide")
	}
	if !strings.Contains(ko.Detail, "pas-une-adresse") {
		t.Errorf("le test ne nomme pas l'adresse fautive : %q", ko.Detail)
	}
}

// TestLesAdressesSontTrieesEtDedupliquees : the same set typed in another order must not
// restart the pod. A restart cuts the page for a few seconds, and doing that for nothing
// teaches the operator to ignore the blips.
func TestLesAdressesSontTrieesEtDedupliquees(t *testing.T) {
	a := sommeAdresses("b@x.fr,a@x.fr")
	b := sommeAdresses("a@x.fr,b@x.fr")
	if a != b {
		t.Errorf("deux ordres de la même liste donnent %q et %q : le pod redémarrerait "+
			"pour un changement qui n'en est pas un", a, b)
	}

	c := sommeAdresses("a@x.fr,a@x.fr,b@x.fr")
	if c != a {
		t.Error("un doublon change la somme : une saisie répétée redémarrerait le proxy")
	}

	if sommeAdresses("a@x.fr") == sommeAdresses("a@x.fr,b@x.fr") {
		t.Error("ajouter une adresse ne change pas la somme : le proxy ne redémarrerait " +
			"pas et garderait l'ancienne liste")
	}
}

// TestTrierLignesNettoie : spaces and empty entries are removed.
func TestTrierLignesNettoie(t *testing.T) {
	got := trierLignes(" b@x.fr , a@x.fr ,, ")
	attendu := []string{"a@x.fr", "b@x.fr"}
	if len(got) != len(attendu) {
		t.Fatalf("obtenu %v, attendu %v", got, attendu)
	}
	for i := range attendu {
		if got[i] != attendu[i] {
			t.Errorf("obtenu %v, attendu %v", got, attendu)
			break
		}
	}
}
