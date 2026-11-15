// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/settings"
)

// Resolve decides which sender the platform uses, in the plan's order.
//
//  1. THE MAIL MODULE IS INSTALLED and its `noreply` credential is in the vault:
//     the platform sends as `noreply@<domain>` through `mail.<domain>` on 465
//     (implicit TLS), authenticated with that credential. The certificate is the
//     one the mail module installed, so the name matches and the connection is
//     trustworthy — that is why the sender's host is the mail HOST and not the
//     platform domain.
//
//  2. OTHERWISE the external relay saved in the files module's `outgoing_mail`
//     settings, when it is filled. This is the pre-existing behaviour: a platform
//     without a mail server keeps using the operator's relay.
//
//  3. OTHERWISE nil: no sender. The callers then leave the applications alone (or
//     clear them, when the platform just uninstalled its mail server).
//
// A READ ERROR IS NEVER SWALLOWED: a vault that answers 500 or a settings
// ConfigMap that cannot be read is a fact the caller must see, because the
// difference between "no sender" and "could not find out" is the difference
// between leaving mail alone and pointing it at the wrong relay.
func Resolve(ctx context.Context, env module.Env) (*Sender, error) {
	installe, err := MailInstalle(ctx, env)
	if err != nil {
		return nil, err
	}
	if installe {
		s, err := senderPlateforme(ctx, env)
		if err != nil {
			return nil, err
		}
		if s != nil {
			return s, nil
		}
	}
	return senderFichiers(ctx, env)
}

// senderPlateforme builds the sender of an installed mail module, or nil when its
// noreply credential is absent (an Install that stopped before step 8, or a vault
// that has not been backed up — the credential is the authority, not the module).
func senderPlateforme(ctx context.Context, env module.Env) (*Sender, error) {
	entree, err := lireCoffre(ctx, ComposantCoffre, SousCheminNoreply)
	if err != nil {
		if secrets.EntreeAbsente(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the platform sender credential: %w", err)
	}
	utilisateur := strings.TrimSpace(entree["user"])
	motDePasse := strings.TrimSpace(entree["password"])
	// THE PAIR IS REQUIRED, not just the password: a credential whose username is
	// missing cannot authenticate, and sending as "*@<domain>" would be a mailbox
	// that does not exist. Absent means "not configured", which falls through to
	// the external relay rather than failing the caller.
	if utilisateur == "" || motDePasse == "" {
		return nil, nil
	}
	return &Sender{
		Host:     "mail." + env.Domain,
		Port:     465,
		Security: "ssl",
		User:     utilisateur,
		Password: motDePasse,
		From:     utilisateur,
		FromName: identity.ReglagesParDefaut().DisplayName,
	}, nil
}

// senderFichiers builds the sender from the files module's stored relay settings.
func senderFichiers(ctx context.Context, env module.Env) (*Sender, error) {
	if env.Settings == nil {
		return nil, nil
	}
	brut, err := env.Settings.Lire(ctx, settings.Namespace, settings.ConfigMapNom, cleReglagesSmtp)
	if err != nil {
		return nil, fmt.Errorf("reading the platform sender settings: %w", err)
	}
	if strings.TrimSpace(brut) == "" {
		return nil, nil
	}
	// ORDINARY VALUES ARE STORED AS ONE JSON OBJECT of strings (internal/settings
	// marshals map[string]string). A document that does not parse is a corrupted
	// setting, not an empty one: reporting it beats silently sending as nobody.
	var valeurs map[string]string
	if err := json.Unmarshal([]byte(brut), &valeurs); err != nil {
		return nil, fmt.Errorf("reading the platform sender settings: %w", err)
	}
	hote := strings.TrimSpace(valeurs["hote"])
	utilisateur := strings.TrimSpace(valeurs["utilisateur"])
	if hote == "" || utilisateur == "" {
		return nil, nil
	}

	port := 587
	if p := strings.TrimSpace(valeurs["port"]); p != "" {
		var lu int
		if _, err := fmt.Sscanf(p, "%d", &lu); err == nil && lu > 0 {
			port = lu
		}
	}

	// THE PASSWORD IS NOT IN THE SETTINGS: it lives in the vault, under the files
	// module's relay component. A relay without one is still a sender (some
	// relays accept a source IP), so an absent entry is not a failure.
	motDePasse := ""
	if entree, err := lireCoffre(ctx, ComposantSmtp, SousCheminRelais); err != nil {
		if !secrets.EntreeAbsente(err) {
			return nil, fmt.Errorf("reading the relay credential: %w", err)
		}
	} else {
		motDePasse = strings.TrimSpace(entree["mot_de_passe"])
	}

	// THE FROM ADDRESS: the form asks for the LOCAL PART (that is what Nextcloud's
	// `mail_from_address` takes), so the domain is the platform's. When the local
	// part is empty, the login name is the best answer when it is already an
	// address, and no sender otherwise.
	expediteur := strings.TrimSpace(valeurs["expediteur"])
	from := ""
	switch {
	case expediteur != "":
		from = expediteur + "@" + env.Domain
	case strings.Contains(utilisateur, "@"):
		from = utilisateur
	}
	if from == "" {
		return nil, nil
	}

	nom := strings.TrimSpace(valeurs["nom_expediteur"])
	if nom == "" {
		nom = identity.ReglagesParDefaut().DisplayName
	}

	return &Sender{
		Host:     hote,
		Port:     port,
		Security: securiteDepuisReglage(valeurs["securite"]),
		User:     utilisateur,
		Password: motDePasse,
		From:     from,
		FromName: nom,
	}, nil
}

// securiteDepuisReglage translates the files module's three-way choice into the
// Sender's two transports.
//
// "aucune" IS AN EMPTY Security, not a third value: the writers speak the two
// protocols they can speak, and "no encryption" is the absence of both. A relay
// reached that way is a misconfiguration in most networks but a legitimate one on
// a loopback or a trusted LAN, so it is carried through rather than refused.
func securiteDepuisReglage(valeur string) string {
	switch strings.TrimSpace(valeur) {
	case "ssl":
		return "ssl"
	case "tls":
		return "starttls"
	default:
		return ""
	}
}

// securiteVersReglage is the inverse, for the Nextcloud writer, whose field keeps
// the three-way vocabulary.
func securiteVersReglage(securite string) string {
	switch securite {
	case "ssl":
		return "ssl"
	case "starttls":
		return "tls"
	default:
		return "aucune"
	}
}

// localPart returns the part of an address before the '@'.
func localPart(adresse string) string {
	if i := strings.Index(adresse, "@"); i >= 0 {
		return adresse[:i]
	}
	return adresse
}

// domaineDe returns the part of an address after the '@', or "" when it has none.
func domaineDe(adresse string) string {
	if i := strings.Index(adresse, "@"); i >= 0 && i+1 < len(adresse) {
		return adresse[i+1:]
	}
	return ""
}
