// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Reading the mail server's ACTUAL state, through the same client the rest of
// the mail package uses.
//
// WHY IT MOVED OUT OF THE COMMAND: these reads used to live in the CLI, where
// they launched `kubectl` themselves — so the console could not answer the
// question "is single sign-on really active?" at all, and the CLI exercised a
// path no test could reach. Here they are the same code for both callers.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Decouvrir calls /api/discover for an account and returns the parsed answer.
//
// THE CHECK IS ON THE ANSWER, not on the configuration: a configuration that is
// correct but not loaded produces the same symptom as a missing one — a sign-in
// that stays on Stalwart's own form — and reading the configuration back would
// pass in both cases.
func Decouvrir(ctx context.Context, compte string) (map[string]any, error) {
	// THE ACCOUNT IS ESCAPED: the address carries an `@`, and an account name
	// is user input. Escaping keeps the request one path even when a name
	// carries a character that would otherwise end it.
	brut, err := lireDansPod(ctx, "http://localhost:8080/api/discover/"+url.PathEscape(compte))
	if err != nil {
		return nil, err
	}
	var reponse map[string]any
	if err := json.Unmarshal(brut, &reponse); err != nil {
		return nil, fmt.Errorf("unreadable answer (%s): %w", tronquer(string(brut), 200), err)
	}
	return reponse, nil
}

// SSOExistant returns the issuer and the client already configured.
//
// READ FROM THE SERVER rather than from an option: a repair must not be able to
// invent a provider. An operator who runs it on an installation pointed at
// Authentik would otherwise silently get Keycloak.
func SSOExistant(ctx context.Context) (string, string, error) {
	objets, err := clientJMAP().Get(ctx, "x:Directory/get", nil,
		[]string{"@type", "issuerUrl", "requireAudience"})
	if err != nil {
		return "", "", fmt.Errorf("reading the OIDC directory: %w", err)
	}
	for _, d := range objets {
		if valeurChaine(d["@type"]) == "Oidc" && valeurChaine(d["issuerUrl"]) != "" {
			return valeurChaine(d["issuerUrl"]), valeurChaine(d["requireAudience"]), nil
		}
	}
	return "", "", nil
}

// DomaineMessagerieExistant returns the mail domain the server already declares.
//
// THE DOMAIN OF THE ADDRESSES, read from the server rather than guessed from the
// web host: they are different things, and mixing them creates a domain that
// receives nothing (measured — see docs/plan-mail.md §9.B). The admin domain is
// excluded: it carries accounts, not mail.
func DomaineMessagerieExistant(ctx context.Context, domaineAdmin string) (string, error) {
	domaines, err := clientJMAP().Get(ctx, "x:Domain/get", nil, []string{"name"})
	if err != nil {
		return "", fmt.Errorf("reading the declared domains: %w", err)
	}
	for _, d := range domaines {
		nom := valeurChaine(d["name"])
		if nom != "" && nom != domaineAdmin {
			return nom, nil
		}
	}
	return "", fmt.Errorf("the server declares no mail domain other than %q: "+
		"pass --domaine explicitly", domaineAdmin)
}

// HoteStalwart returns the public host the server publishes.
//
// FROM ITS OWN DISCOVERY DOCUMENT: the host is what the server believes it is,
// and an operator who fronts it on another name would otherwise get a
// configuration pointing at the wrong address.
func HoteStalwart(ctx context.Context) (string, error) {
	brut, err := lireDansPod(ctx, "http://localhost:8080/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("reading the server's own discovery: %w", err)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(brut, &doc); err != nil {
		return "", fmt.Errorf("unreadable discovery (%s): %w", tronquer(string(brut), 200), err)
	}
	hote := strings.TrimPrefix(strings.TrimPrefix(doc.Issuer, "https://"), "http://")
	if hote == "" {
		return "", fmt.Errorf("the server publishes no issuer: its public URL is not configured")
	}
	return hote, nil
}

// valeurChaine reads a string field, tolerating a null.
func valeurChaine(v any) string {
	s, _ := v.(string)
	return s
}
