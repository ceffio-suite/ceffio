// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package acme

import (
	"strings"
	"testing"
)

// TestDefautEstHTTP01 pins the compatibility promise of this package: an
// installation that configures nothing keeps the challenge and the port 80 it
// already had. Every existing deployment depends on this, and a change of
// default would be a silent behaviour change on machines nobody is watching.
func TestDefautEstHTTP01(t *testing.T) {
	for _, v := range []string{VariableChallenge, VariableDNSProvider, VariableDNSZone, VariableWebhookGroup} {
		t.Setenv(v, "")
	}
	r, err := DepuisEnvironnement()
	if err != nil {
		t.Fatalf("no configuration must be valid, got: %v", err)
	}
	if r.Challenge != ChallengeHTTP {
		t.Errorf("challenge = %q, want %q", r.Challenge, ChallengeHTTP)
	}
	if r.DNS01() {
		t.Error("DNS01() true without configuration")
	}
	if r.WebhookGroup != WebhookGroupParDefaut {
		t.Errorf("webhook group = %q, want the default %q", r.WebhookGroup, WebhookGroupParDefaut)
	}
}

// TestChallengeInconnuEstRefuse is the reason this package exists: a wrong
// challenge name must fail HERE, with its own name in the message. Written into
// the manifest, cert-manager would accept the object and never issue anything —
// the operator would see a default Traefik certificate and look for a TLS
// problem.
func TestChallengeInconnuEstRefuse(t *testing.T) {
	for _, cas := range []struct{ nom, valeur string }{
		{"typo", "dns1"},
		{"abbreviation", "dns"},
		{"historical spelling", "http"},
		{"in-tree solver name used as a challenge", "cloudflare"},
	} {
		t.Run(cas.nom, func(t *testing.T) {
			t.Setenv(VariableChallenge, cas.valeur)
			_, err := DepuisEnvironnement()
			if err == nil {
				t.Fatalf("%s=%q accepted, want a refusal", VariableChallenge, cas.valeur)
			}
			if !strings.Contains(err.Error(), cas.valeur) {
				t.Errorf("the error must name the rejected value %q, got: %v", cas.valeur, err)
			}
		})
	}
}

// TestDNS01SansProviderEstRefuse: without a provider there is nothing to
// publish the record with. Ceffio must stop, NOT choose one — a guessed
// provider would point at a credential the operator never created.
func TestDNS01SansProviderEstRefuse(t *testing.T) {
	t.Setenv(VariableChallenge, string(ChallengeDNS))
	t.Setenv(VariableDNSProvider, "")
	_, err := DepuisEnvironnement()
	if err == nil {
		t.Fatal("dns01 without a provider accepted, want a refusal")
	}
	// The message names the SETTING and the VALUE to give it. It no longer
	// names the environment variable: the settings can come from the store now
	// — what the operator chose in the console or on the command line — and
	// naming a variable would point them at one of several ways to set it.
	if !strings.Contains(err.Error(), "requires a DNS provider") {
		t.Errorf("the error must say a provider is required, got: %v", err)
	}
	for _, attendu := range []string{string(ProviderCloudflare), string(ProviderRFC2136)} {
		if !strings.Contains(err.Error(), attendu) {
			t.Errorf("the error must mention %q so the operator has an example, got: %v", attendu, err)
		}
	}
}

// TestProviderAvecHTTP01EstRefuse: a configuration whose parts contradict each
// other is refused rather than half-applied. Ignoring the provider in silence
// would leave an operator believing DNS-01 is active.
func TestProviderAvecHTTP01EstRefuse(t *testing.T) {
	t.Setenv(VariableChallenge, string(ChallengeHTTP))
	t.Setenv(VariableDNSProvider, string(ProviderCloudflare))
	_, err := DepuisEnvironnement()
	if err == nil {
		t.Fatal("http01 with a DNS provider accepted, want a refusal naming the contradiction")
	}
	// The two VALUES are named, so the operator sees which of their two
	// settings is the one to change.
	if !strings.Contains(err.Error(), string(ChallengeHTTP)) ||
		!strings.Contains(err.Error(), string(ProviderCloudflare)) {
		t.Errorf("the error must name both values, got: %v", err)
	}
}

// TestDNS01Valide covers the accepted shapes, including the provider names this
// project has never heard of: the webhook receives the name as data, so an
// unknown-but-valid provider must pass through untouched. Refusing it here
// would mean republishing Ceffio to support one more DNS host.
func TestDNS01Valide(t *testing.T) {
	for _, cas := range []struct {
		provider  string
		webhook   bool
		enArbreIn string
	}{
		{string(ProviderCloudflare), false, "cloudflare"},
		{string(ProviderRoute53), false, "route53"},
		{string(ProviderRFC2136), false, "rfc2136"},
		{string(ProviderACMEDNS), false, "acmedns"},
		{"scaleway", true, "scaleway"},
		{"ovh", true, "ovh"},
		{"gandi", true, "gandi"},
		{"hetzner", true, "hetzner"},
		{"un-provider-qui-nexiste-pas-encore", true, "inconnu"},
	} {
		t.Run(cas.enArbreIn, func(t *testing.T) {
			t.Setenv(VariableChallenge, string(ChallengeDNS))
			t.Setenv(VariableDNSProvider, cas.provider)
			t.Setenv(VariableDNSZone, "exemple.fr")

			r, err := DepuisEnvironnement()
			if err != nil {
				t.Fatalf("provider %q refused: %v", cas.provider, err)
			}
			if !r.DNS01() {
				t.Error("DNS01() false on a dns01 configuration")
			}
			if r.Zone != "exemple.fr" {
				t.Errorf("zone = %q, want the configured one", r.Zone)
			}
			if got := r.EmpreinteWebhook(); got != cas.webhook {
				t.Errorf("EmpreinteWebhook() = %v pour %q, want %v", got, cas.provider, cas.webhook)
			}
		})
	}
}

// TestCasseEtEspacesTolere: an operator writes "DNS01" or leaves a trailing
// space in a shell variable. Normalising is right; being strict about the case
// would refuse a configuration that is not actually wrong. The REFUSAL stays
// strict — see TestChallengeInconnuEstRefuse.
func TestCasseEtEspacesTolere(t *testing.T) {
	t.Setenv(VariableChallenge, "  DNS01 ")
	t.Setenv(VariableDNSProvider, " CLoudFlare ")
	t.Setenv(VariableWebhookGroup, "  acme.exemple.fr  ")

	r, err := DepuisEnvironnement()
	if err != nil {
		t.Fatalf("a differently-cased value must be accepted: %v", err)
	}
	if r.Challenge != ChallengeDNS {
		t.Errorf("challenge = %q", r.Challenge)
	}
	if r.Provider != ProviderCloudflare {
		t.Errorf("provider = %q", r.Provider)
	}
	if r.WebhookGroup != "acme.exemple.fr" {
		t.Errorf("webhook group = %q, want it trimmed", r.WebhookGroup)
	}
}

// TestHTTP01Expose verifies the value used by read-only callers (a status page,
// a view built without touching the cluster configuration): it must be a valid,
// complete setting, not a zero value with an empty solver identity.
func TestHTTP01Expose(t *testing.T) {
	r := HTTP01()
	if r.Challenge != ChallengeHTTP || r.DNS01() {
		t.Errorf("HTTP01() = %+v, want the http01 challenge", r)
	}
	if r.WebhookGroup == "" {
		t.Error("HTTP01() leaves the webhook group empty: a caller building a manifest from it would write a broken solver")
	}
	if r.Provider != "" {
		t.Errorf("HTTP01() carries provider %q: http01 uses none", r.Provider)
	}
}
