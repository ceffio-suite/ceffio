// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

// WHY THESE TESTS EXIST: the state reads used to live in the CLI, behind
// `kubectl exec`, where no test could reach them. They now decide, on their
// own, which directory is the OIDC one and which domain carries the addresses.
// Both decisions were already measured wrong once (a duplicate directory, and a
// mail domain named after the web host), so they are pinned here rather than
// trusted.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// fauxTransportJMAP answers JMAP method calls from a table, for one test.
//
// THE TABLE IS THE POINT: each test states exactly what the server would
// answer, so the assertion is about the decision, not about the plumbing.
func fauxTransportJMAP(t *testing.T, reponses map[string]any) {
	t.Helper()
	ancien := transportJMAP
	t.Cleanup(func() { transportJMAP = ancien })
	transportJMAP = func(_ context.Context, corps []byte) ([]byte, error) {
		var requete struct {
			MethodCalls []json.RawMessage `json:"methodCalls"`
		}
		if err := json.Unmarshal(corps, &requete); err != nil {
			return nil, err
		}
		if len(requete.MethodCalls) == 0 {
			return nil, fmt.Errorf("empty methodcalls")
		}
		var appel []any
		if err := json.Unmarshal(requete.MethodCalls[0], &appel); err != nil {
			return nil, err
		}
		methode, _ := appel[0].(string)
		reponse, connu := reponses[methode]
		if !connu {
			return nil, fmt.Errorf("unexpected method %q", methode)
		}
		enveloppe := map[string]any{
			"methodResponses": []any{[]any{methode, reponse, "c1"}},
		}
		return json.Marshal(enveloppe)
	}
}

func TestSSOExistantChoisitLAnnuaireOidc(t *testing.T) {
	fauxTransportJMAP(t, map[string]any{
		"x:Directory/get": map[string]any{"list": []any{
			map[string]any{"id": "a", "@type": "Ldap", "issuerUrl": ""},
			map[string]any{
				"id": "b", "@type": "Oidc",
				"issuerUrl":       "https://keycloak.example.com/realms/ceffio",
				"requireAudience": "stalwart-webui",
			},
		}},
	})

	issuer, clientID, err := SSOExistant(context.Background())
	if err != nil {
		t.Fatalf("SSOExistant: %v", err)
	}
	if issuer != "https://keycloak.example.com/realms/ceffio" {
		t.Errorf("issuer = %q, expected the OIDC one — a non-OIDC directory must be skipped", issuer)
	}
	if clientID != "stalwart-webui" {
		t.Errorf("client = %q, expected stalwart-webui", clientID)
	}
}

func TestSSOExistantSansAnnuaire(t *testing.T) {
	fauxTransportJMAP(t, map[string]any{
		"x:Directory/get": map[string]any{"list": []any{}},
	})

	issuer, clientID, err := SSOExistant(context.Background())
	if err != nil {
		t.Fatalf("SSOExistant: %v", err)
	}
	if issuer != "" || clientID != "" {
		t.Errorf("issuer=%q client=%q, expected both empty on a fresh installation", issuer, clientID)
	}
}

func TestDomaineMessagerieIgnoreLeDomaineAdmin(t *testing.T) {
	fauxTransportJMAP(t, map[string]any{
		"x:Domain/get": map[string]any{"list": []any{
			map[string]any{"id": "a", "name": "ceffio.local"},
			map[string]any{"id": "b", "name": "example.com"},
		}},
	})

	domaine, err := DomaineMessagerieExistant(context.Background(), "ceffio.local")
	if err != nil {
		t.Fatalf("DomaineMessagerieExistant: %v", err)
	}
	if domaine != "example.com" {
		t.Errorf("domain = %q, expected example.com — the admin domain carries accounts, not mail", domaine)
	}
}

func TestDomaineMessagerieRefuseDeDeviner(t *testing.T) {
	fauxTransportJMAP(t, map[string]any{
		"x:Domain/get": map[string]any{"list": []any{
			map[string]any{"id": "a", "name": "ceffio.local"},
		}},
	})

	_, err := DomaineMessagerieExistant(context.Background(), "ceffio.local")
	if err == nil {
		t.Fatal("DomaineMessagerieExistant accepted a server with no mail domain: " +
			"guessing one creates a domain that receives nothing")
	}
	if !strings.Contains(err.Error(), "--domaine") {
		t.Errorf("error does not say how to proceed: %v", err)
	}
}

func TestEntreGuillemets(t *testing.T) {
	cas := []struct{ entree, attendu string }{
		{"http://localhost:8080/api/discover/a@b", `'http://localhost:8080/api/discover/a@b'`},
		{"a'b", `'a'\''b'`},
		{"a;b", `'a;b'`},
	}
	for _, c := range cas {
		if got := entreGuillemets(c.entree); got != c.attendu {
			t.Errorf("entreGuillemets(%q) = %q, expected %q", c.entree, got, c.attendu)
		}
	}
}
