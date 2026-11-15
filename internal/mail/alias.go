// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The addresses every mail domain must accept, on the admin account.
//
// WHY THESE TWO AND NOT A MAILBOX EACH: RFC 2142 asks a mail domain to accept
// `postmaster@` and `abuse@`. They are read by other mail servers, by abuse
// desks and by the DNSBLs — an unreachable postmaster is itself a
// deliverability signal. Creating a mailbox for each would mean an account
// nobody reads, with a quota, in the user list; an ALIAS delivers to the admin
// inbox, where it will actually be seen.
//
// THE ALIAS BELONGS TO THE ACCOUNT, NOT TO THE DOMAIN (measured in POC 9.F on
// Stalwart 1.0.3): there is no `x:Alias/*` method in this version. The aliases
// live in the account object and are written through `x:Account/set` with a
// POINTER key (`"aliases/<index>"`), which the server accepts without
// re-sending the aliases already there. Sending the whole map instead would
// work too, and would risk dropping the fields nobody re-sends (description,
// enable).
package mail

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// aliasObligatoires are the addresses a mail domain must accept (RFC 2142).
var aliasObligatoires = []string{"postmaster", "abuse"}

// AssurerAlias creates the postmaster@ and abuse@ aliases of the mail domain,
// pointing at the admin account, idempotently.
//
// IT MUST RUN AFTER THE SSO SETUP: the domain and the admin account are created
// by ConfigurerSSO, and an alias cannot reference a domain that does not exist.
// That is why this is a step of the module's Install rather than of Deploy.
func AssurerAlias(ctx context.Context, domaineMessagerie, compteAdmin string) error {
	idDomaine, err := chercherID(ctx, "x:Domain/get", "name", domaineMessagerie)
	if err != nil {
		return fmt.Errorf("reading the mail domain %s: %w", domaineMessagerie, err)
	}
	if idDomaine == "" {
		// NOT AN EXTERNAL PREREQUISITE: SSO creates this domain, so its absence
		// means the installation is genuinely incomplete, and an alias written
		// now would point nowhere.
		return fmt.Errorf("the mail domain %s does not exist: the SSO setup did not complete", domaineMessagerie)
	}
	idCompte, err := chercherID(ctx, "x:Account/get", "name", compteAdmin)
	if err != nil {
		return fmt.Errorf("reading the admin account %s: %w", compteAdmin, err)
	}
	if idCompte == "" {
		return fmt.Errorf("the admin account %s does not exist: the SSO setup did not complete", compteAdmin)
	}

	domaines, err := lireNomsDeDomaines(ctx)
	if err != nil {
		return err
	}
	existants, prochain, err := lireAlias(ctx, idCompte, domaines)
	if err != nil {
		return err
	}

	// ONLY THE MISSING ONES ARE WRITTEN, each at a FREE index: rewriting an
	// existing alias would bump the account's modification counter for nothing,
	// and a stale index would overwrite an alias an operator created by hand.
	ajouts := map[string]any{}
	for _, nom := range aliasObligatoires {
		if existants[nom+"@"+domaineMessagerie] {
			continue
		}
		ajouts["aliases/"+strconv.Itoa(prochain)] = map[string]any{
			"@type":    "EmailAlias",
			"name":     nom,
			"domainId": idDomaine,
		}
		prochain++
	}
	if len(ajouts) == 0 {
		return nil
	}
	if err := majJMAP(ctx, "x:Account/set", map[string]any{
		"update": map[string]any{idCompte: ajouts},
	}); err != nil {
		return fmt.Errorf("creating the postmaster/abuse aliases: %w", err)
	}

	// THE READ-BACK IS THE PROOF: the write answers `{"updated":{"<id>":null}}`,
	// which says the object was touched, not that these aliases exist. The
	// account is re-read and the ADDRESSES — not the indices — are compared.
	apres, _, err := lireAlias(ctx, idCompte, domaines)
	if err != nil {
		return err
	}
	for _, nom := range aliasObligatoires {
		adresse := nom + "@" + domaineMessagerie
		if !apres[adresse] {
			return fmt.Errorf("the alias %s reads back absent after being written", adresse)
		}
	}
	fmt.Printf("  ∙ aliases: %s\n", adressesObligatoires(domaineMessagerie))
	return nil
}

// lireNomsDeDomaines returns the identifier-to-name table of the mail domains.
//
// NECESSARY BECAUSE `domainId` IS AN IDENTIFIER ("b" on the demo), and an alias
// object carries no domain NAME. Comparing that identifier with the domain name
// is how an alias ends up never matching and being recreated on every run.
func lireNomsDeDomaines(ctx context.Context) (map[string]string, error) {
	domaines, err := clientJMAP().Get(ctx, "x:Domain/get", nil, []string{"id", "name"})
	if err != nil {
		return nil, fmt.Errorf("reading the mail domains: %w", err)
	}
	table := make(map[string]string, len(domaines))
	for _, d := range domaines {
		id, _ := d["id"].(string)
		nom, _ := d["name"].(string)
		if id != "" && nom != "" {
			table[id] = nom
		}
	}
	return table, nil
}

// lireAlias returns the account's alias addresses and the first free index.
//
// THE INDEX MATTERS because the pointer form names it: reusing an occupied one
// replaces that alias silently. `aliases` is a map keyed by index in Stalwart's
// account objects; a list is accepted too, so a version that returns an array
// would not need this reader rewritten.
func lireAlias(ctx context.Context, idCompte string, domaines map[string]string) (map[string]bool, int, error) {
	comptes, err := clientJMAP().Get(ctx, "x:Account/get", []string{idCompte},
		[]string{"id", "aliases"})
	if err != nil {
		return nil, 0, fmt.Errorf("reading the aliases of the admin account: %w", err)
	}
	adresses := map[string]bool{}
	prochain := 0
	for _, compte := range comptes {
		if compte["id"] != idCompte {
			continue
		}
		for index, valeur := range aliasParIndex(compte["aliases"]) {
			n, err := strconv.Atoi(index)
			if err == nil && n >= prochain {
				prochain = n + 1
			}
			m, ok := valeur.(map[string]any)
			if !ok {
				continue
			}
			nom, _ := m["name"].(string)
			idDomaine, _ := m["domainId"].(string)
			if nom != "" && domaines[idDomaine] != "" {
				adresses[nom+"@"+domaines[idDomaine]] = true
			}
		}
	}
	// A NON-NUMERIC INDEX (a version storing aliases by name) must not make the
	// next write collide: the next free numeric index is after the highest one
	// seen, and unknown keys only affect the map above.
	return adresses, prochain, nil
}

// aliasParIndex normalises the `aliases` field to index → alias object.
func aliasParIndex(brut any) map[string]any {
	switch v := brut.(type) {
	case map[string]any:
		return v
	case []any:
		sortie := make(map[string]any, len(v))
		for i, alias := range v {
			sortie[strconv.Itoa(i)] = alias
		}
		return sortie
	}
	return nil
}

// adressesObligatoires renders the aliases a domain must accept, for a message.
func adressesObligatoires(domaine string) string {
	noms := make([]string, 0, len(aliasObligatoires))
	for _, nom := range aliasObligatoires {
		noms = append(noms, nom+"@"+domaine)
	}
	return strings.Join(noms, ", ")
}
