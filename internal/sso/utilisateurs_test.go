// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sso

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestLaListeDesComptesSuitLesPages : Keycloak's admin API answers 100 accounts
// unless asked otherwise. A listing that stops at the first page would hide
// every account past the hundredth — exactly the ones a module has never
// provisioned.
func TestLaListeDesComptesSuitLesPages(t *testing.T) {
	ancien := pageUtilisateurs
	t.Cleanup(func() { pageUtilisateurs = ancien })

	var offsets []int
	pageUtilisateurs = func(ctx context.Context, premier, taille int) ([]UtilisateurRealm, error) {
		offsets = append(offsets, premier)
		page := make([]UtilisateurRealm, 0, taille)
		switch premier {
		case 0, 100:
			for i := 0; i < taille; i++ {
				page = append(page, UtilisateurRealm{Login: fmt.Sprintf("u%d", premier+i)})
			}
		case 200:
			page = append(page, UtilisateurRealm{Login: "dernier"})
		default:
			return nil, fmt.Errorf("unexpected offset %d", premier)
		}
		return page, nil
	}

	comptes, err := UtilisateursRealm(context.Background())
	if err != nil {
		t.Fatalf("listing the realm's accounts: %v", err)
	}
	if len(comptes) != 201 {
		t.Errorf("%d accounts read, want 201 (the third page is partial and must end the listing)", len(comptes))
	}
	if len(offsets) != 3 || offsets[0] != 0 || offsets[1] != 100 || offsets[2] != 200 {
		t.Errorf("the pages were requested at %v, want [0 100 200]", offsets)
	}
}

// TestLaListeRefuseUnePaginationQuiNAvancePas : a full page forever is a
// listing that does not terminate. It must be named as a failure, not return
// the first 5000 accounts as if they were all of them.
func TestLaListeRefuseUnePaginationQuiNAvancePas(t *testing.T) {
	ancien := pageUtilisateurs
	t.Cleanup(func() { pageUtilisateurs = ancien })

	var appels int
	pageUtilisateurs = func(ctx context.Context, premier, taille int) ([]UtilisateurRealm, error) {
		appels++
		page := make([]UtilisateurRealm, taille)
		return page, nil
	}

	_, err := UtilisateursRealm(context.Background())
	if err == nil {
		t.Fatal("an endless listing was reported as complete")
	}
	if !strings.Contains(err.Error(), fmt.Sprint(plafondUtilisateurs)) {
		t.Errorf("the error does not name the cap: %v", err)
	}
	if appels != plafondUtilisateurs/taillePageUtilisateurs {
		t.Errorf("%d pages requested, want %d", appels, plafondUtilisateurs/taillePageUtilisateurs)
	}
}

// TestLirePageUtilisateurs: the document is extracted from the progress lines
// kcadm prints around it, an empty realm is an empty list, and anything else is
// an ERROR — "no accounts" and "the command failed" must never look alike.
func TestLirePageUtilisateurs(t *testing.T) {
	sortie := `Logging into http://localhost:8080 as user admin of realm master
[ {
  "id" : "0cb65a27-d90d-45c8-91d9-e41bb65bd270",
  "username" : "merouane",
  "email" : "merouane@example.org",
  "enabled" : true
}, {
  "id" : "991b28ef-45a1-45e4-b26c-0b8062325c97",
  "username" : "sans.mail",
  "email" : null,
  "enabled" : false
} ]`
	comptes, err := lirePageUtilisateurs(sortie)
	if err != nil {
		t.Fatalf("decoding a valid listing: %v", err)
	}
	if len(comptes) != 2 {
		t.Fatalf("%d accounts decoded, want 2", len(comptes))
	}
	if comptes[0].Login != "merouane" || comptes[0].Mail != "merouane@example.org" || !comptes[0].Enabled {
		t.Errorf("first account decoded as %+v", comptes[0])
	}
	if comptes[1].Login != "sans.mail" || comptes[1].Mail != "" || comptes[1].Enabled {
		t.Errorf("an account without address or enabled decoded as %+v", comptes[1])
	}

	vide, err := lirePageUtilisateurs("Logging into http://localhost:8080 as user admin\n[ ]")
	if err != nil {
		t.Fatalf("an empty realm must decode: %v", err)
	}
	if len(vide) != 0 {
		t.Errorf("an empty realm returned %d accounts", len(vide))
	}

	_, err = lirePageUtilisateurs("error: something went wrong")
	if err == nil {
		t.Fatal("an output carrying no array was accepted as an empty realm")
	}
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Errorf("the error does not show what was received: %v", err)
	}
}
