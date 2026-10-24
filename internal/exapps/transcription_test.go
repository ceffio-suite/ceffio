// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package exapps

import (
	"strings"
	"testing"
)

// TestLanguesDepuisListe covers the parsing an operator triggers from the
// console, the CLI and the installer alike: whatever the separator, whatever
// the case, a code that has no model must be REFUSED rather than stored. A
// stored code without a model is the exact failure this work removes: the app
// advertises the language and dies on it at the first call.
func TestLanguesDepuisListe(t *testing.T) {
	cas := []struct {
		nom     string
		entree  string
		attendu []string
	}{
		{"une langue", "fr", []string{"fr"}},
		{"espaces et virgules", "  fr , ar  ", []string{"fr", "ar"}},
		{"doublons et casse", "fr,FR,fr", []string{"fr"}},
		{"point-virgule", "fr;ar", []string{"fr", "ar"}},
		{"retour à la ligne", "fr\nar", []string{"fr", "ar"}},
		{"ordre conservé", "ar,fr", []string{"ar", "fr"}},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			obtenu, err := LanguesDepuisListe(c.entree)
			if err != nil {
				t.Fatalf("LanguesDepuisListe(%q): %v", c.entree, err)
			}
			if strings.Join(obtenu, ",") != strings.Join(c.attendu, ",") {
				t.Errorf("LanguesDepuisListe(%q) = %v, attendu %v", c.entree, obtenu, c.attendu)
			}
		})
	}
}

// TestLanguesDepuisListeRefuse: an unknown code is an error that NAMES the
// accepted ones — the operator cannot guess "br" or "ar-tn" from a bare
// refusal.
func TestLanguesDepuisListeRefuse(t *testing.T) {
	for _, entree := range []string{"", "   ", "xx", "fr,zz"} {
		if _, err := LanguesDepuisListe(entree); err == nil {
			t.Errorf("LanguesDepuisListe(%q) a accepté une liste sans modèle", entree)
		}
	}

	_, err := LanguesDepuisListe("xx")
	if err == nil || !strings.Contains(err.Error(), "fr") {
		t.Errorf("le refus doit lister les codes connus, obtenu: %v", err)
	}
}

// TestModelesConnus checks the list the help text shows: empty would offer the
// operator nothing to type, unsorted would change the message on every build.
func TestModelesConnus(t *testing.T) {
	codes := ModelesConnus()
	if len(codes) == 0 {
		t.Fatal("ModelesConnus is empty")
	}
	for i := 1; i < len(codes); i++ {
		if codes[i-1] > codes[i] {
			t.Errorf("ModelesConnus is not sorted: %v", codes)
		}
	}
	if _, ok := modelesVosk["fr"]; !ok {
		t.Error("the default language fr has no model")
	}
	for _, c := range LanguesParDefaut {
		if _, ok := modelesVosk[c]; !ok {
			t.Errorf("LanguesParDefaut contains %q, which has no model", c)
		}
	}
}
