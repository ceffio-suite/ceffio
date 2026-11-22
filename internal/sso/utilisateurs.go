// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Reading the realm's accounts, for the modules that must create a local
// account for each of them.
//
// THE REALM IS THE SOURCE OF TRUTH for who exists. A module that keeps one
// object per person (OpenProject is one) therefore has to read this list, not
// guess it from the Users page: the page is a view over the realm, and a user
// created in Keycloak by another path must still get their account.
package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// UtilisateurRealm is one account of the application realm, reduced to what a
// module needs to create its own.
//
// THE KEYCLOAK FIELD NAMES ARE KEPT: the structure is decoded straight from
// `kcadm get users`, and a rename here would have to be mirrored there.
type UtilisateurRealm struct {
	ID      string `json:"id"`
	Login   string `json:"username"`
	Mail    string `json:"email"`
	Enabled bool   `json:"enabled"`
}

// Page size and safety cap of the listing. The cap is not a policy: it turns a
// pagination that does not terminate (an endpoint ignoring `first`/`max`, for
// example) into an error instead of a silent truncation.
const (
	taillePageUtilisateurs = 100
	plafondUtilisateurs    = 5000
)

// pageUtilisateurs is the seam the pagination is tested through: it returns one
// page of the realm's accounts, starting at `premier`.
var pageUtilisateurs = pageUtilisateursKcadm

// UtilisateursRealm returns every account of the ceffio realm, ALL PAGES
// INCLUDED.
//
// PAGINATION IS NOT OPTIONAL: Keycloak's admin API answers 100 users unless
// asked otherwise, so a single call would quietly hide every account past the
// hundredth — precisely the accounts that predate a module and that nobody has
// provisioned yet.
func UtilisateursRealm(ctx context.Context) ([]UtilisateurRealm, error) {
	var tous []UtilisateurRealm
	for premier := 0; premier < plafondUtilisateurs; premier += taillePageUtilisateurs {
		page, err := pageUtilisateurs(ctx, premier, taillePageUtilisateurs)
		if err != nil {
			return nil, err
		}
		tous = append(tous, page...)
		if len(page) < taillePageUtilisateurs {
			return tous, nil
		}
	}
	return nil, fmt.Errorf("sso: the realm has more than %d accounts and the listing did not "+
		"end: the pagination is not advancing, and reading a truncated list would leave "+
		"accounts unprovisioned", plafondUtilisateurs)
}

// pageUtilisateursKcadm reads one page through kcadm.
func pageUtilisateursKcadm(ctx context.Context, premier, taille int) ([]UtilisateurRealm, error) {
	sortie, err := runKcadm(ctx, "get", "users",
		"--fields", "id,username,email,enabled",
		"--offset", strconv.Itoa(premier),
		"--limit", strconv.Itoa(taille))
	if err != nil {
		return nil, fmt.Errorf("sso: reading the realm's accounts: %w", err)
	}
	page, err := lirePageUtilisateurs(sortie)
	if err != nil {
		return nil, err
	}
	return page, nil
}

// lirePageUtilisateurs decodes the JSON array out of what kcadm printed.
//
// THE SHAPE IS KNOWN AND NARROW: kcadm prints one or two progress lines, then
// the document. The brackets are located rather than parsed leniently — an
// output carrying no array is reported WITH WHAT WAS RECEIVED, because "no
// accounts" and "a failed command" must never look alike: the first would tell
// an installation that nobody needs an account.
func lirePageUtilisateurs(sortie string) ([]UtilisateurRealm, error) {
	debut := strings.Index(sortie, "[")
	fin := strings.LastIndex(sortie, "]")
	if debut < 0 || fin <= debut {
		return nil, fmt.Errorf("sso: the realm's account list is not a JSON array: %.200q",
			strings.TrimSpace(sortie))
	}
	var page []UtilisateurRealm
	if err := json.Unmarshal([]byte(sortie[debut:fin+1]), &page); err != nil {
		return nil, fmt.Errorf("sso: decoding the realm's accounts: %w: %.200q", err,
			strings.TrimSpace(sortie))
	}
	return page, nil
}
