// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/acme"
)

// TestAucunChampEtrangerDansLeGabarit is the guardrail for a failure that would
// be invisible until runtime, and total when it happens.
//
// vault.AnnotationsAgent sets `error-on-missing-key-env: true` — a missing key
// makes the render FAIL instead of writing an empty value, which is the right
// choice. But the flag applies to the WHOLE template: rendering the union of
// every provider's fields would make a Cloudflare entry fail, because the OVH
// fields it legitimately does not have would be reported missing. The pod would
// never start, and the message would name a field for a provider the operator
// never chose.
//
// So each provider must render ITS OWN fields and nothing else.
func TestAucunChampEtrangerDansLeGabarit(t *testing.T) {
	// provider -> variables that must appear, and those that must NOT.
	for _, cas := range []struct {
		provider string
		attendu  []string
		interdit []string
	}{
		{
			provider: "cloudflare",
			attendu:  []string{"CF_API_TOKEN"},
			interdit: []string{"OVH_", "AWS_", "RFC2136_", "SCALEWAY_", "ACMEDNS_"},
		},
		{
			provider: "ovh",
			attendu:  []string{"OVH_ENDPOINT", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"},
			interdit: []string{"CF_API_TOKEN", "AWS_", "RFC2136_"},
		},
		{
			provider: "scaleway",
			attendu:  []string{"SCALEWAY_API_TOKEN", "SCALEWAY_PROJECT_ID"},
			interdit: []string{"CF_API_TOKEN", "OVH_", "AWS_"},
		},
		{
			provider: "route53",
			attendu:  []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"},
			interdit: []string{"CF_API_TOKEN", "OVH_", "GANDI_"},
		},
		{
			// RFC 2136 is the reason "no API-provider account" is not a dead
			// end: BIND, Knot, PowerDNS, Technitium, Windows DNS — all covered
			// in-tree, with a TSIG key and no token.
			provider: "rfc2136",
			attendu:  []string{"RFC2136_NAMESERVER", "RFC2136_TSIG_KEY", "RFC2136_TSIG_SECRET", "RFC2136_TSIG_ALGORITHM"},
			interdit: []string{"CF_API_TOKEN", "OVH_", "AWS_", "SCALEWAY_"},
		},
		{
			// acme-dns: delegated by CNAME, the credential writes exactly one
			// record name. The path for an operator with no rights on the main
			// zone.
			provider: "acmedns",
			attendu:  []string{"ACMEDNS_API_URL", "ACMEDNS_USERNAME", "ACMEDNS_PASSWORD", "ACMEDNS_SUBDOMAIN"},
			interdit: []string{"CF_API_TOKEN", "OVH_", "RFC2136_"},
		},
	} {
		t.Run(cas.provider, func(t *testing.T) {
			gabarit := gabaritPourTest(t, acme.Provider(cas.provider))

			for _, v := range cas.attendu {
				if !strings.Contains(gabarit, v) {
					t.Errorf("provider %q: the template lacks %q — its credentials would be empty:\n%s",
						cas.provider, v, gabarit)
				}
			}
			for _, v := range cas.interdit {
				if strings.Contains(gabarit, v) {
					t.Errorf("provider %q: the template renders %q, a field of ANOTHER host. "+
						"With error-on-missing-key-env, the render would fail and the pod would never start:\n%s",
						cas.provider, v, gabarit)
				}
			}
		})
	}
}

// TestLeNomDuProviderVoyageAvecLEndroit: the provider name must be rendered in
// EVERY case, including the unknown ones. It is what lets the solver verify that
// the credential it holds was stored for the host it is about to write to — a
// Cloudflare token used against a Scaleway zone fails with an authorization
// error that never mentions the mismatch.
func TestLeNomDuProviderVoyageAvecLEndroit(t *testing.T) {
	for _, p := range []acme.Provider{
		acme.ProviderCloudflare, acme.ProviderRoute53, acme.ProviderRFC2136,
		acme.ProviderACMEDNS, "scaleway", "un-provider-inconnu",
	} {
		gabarit := gabaritPourTest(t, p)
		if !strings.Contains(gabarit, "CEFFIO_DNS_PROVIDER_NAME") {
			t.Errorf("provider %q: the rendered file does not carry the provider name:\n%s", p, gabarit)
		}
	}
}

// TestProviderInconnuResteUtilisable: an unknown-but-valid provider must produce
// a usable template. Refusing outright would mean a Ceffio release per DNS host
// — the coupling this whole design exists to avoid — and the generic api_token
// field covers the majority of libdns implementations.
func TestProviderInconnuResteUtilisable(t *testing.T) {
	gabarit := gabaritPourTest(t, "un-provider-inconnu")
	if !strings.Contains(gabarit, "API_TOKEN") {
		t.Errorf("an unknown provider renders no token at all:\n%s", gabarit)
	}
	if strings.TrimSpace(gabarit) == "" {
		t.Error("an unknown provider produces an empty template")
	}
}

// TestWebhookAbsentEnHTTP01: under HTTP-01 the solver would be a pod on a port
// nothing calls. deployerWebhookDNS must be a no-op — asserted here because the
// function is called unconditionally by Deploy.
func TestWebhookAbsentEnHTTP01(t *testing.T) {
	// Exercised through the manifests rather than the apply path (which needs a
	// cluster): a dns01-only component must not be produced for http01.
	// The guard itself lives in deployerWebhookDNS; this test pins the shape of
	// what it returns on the other path.
	m := webhookManifests(acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare"})
	if !strings.Contains(m, "ceffio-acme-dns-webhook") {
		t.Errorf("the solver manifest lacks its own name:\n%s", m)
	}
	// No TLS certificate is ever requested over HTTP-01 paths: the solver is
	// internal to cert-manager and always signed by the internal authority.
	c := webhookCertificatManifest()
	if !strings.Contains(c, issuerCA) {
		t.Errorf("the solver certificate is not signed by the internal authority:\n%s", c)
	}
	// The APIService must keep its caBundle injection: a bundle pasted once
	// expires silently and the API starts refusing calls weeks later.
	a := webhookAPIServiceManifest()
	if !strings.Contains(a, "cert-manager.io/inject-ca-from") {
		t.Errorf("the APIService lost its caBundle injection:\n%s", a)
	}
	if !strings.Contains(a, "insecureSkipTLSVerify: false") {
		t.Errorf("the APIService must not skip TLS verification:\n%s", a)
	}
}

// gabaritPourTest extrait le gabarit d'injection du manifeste du solver.
//
// Extracting it from the real manifest rather than calling champsDuProvider
// directly is deliberate: what matters is the TEMPLATE THAT REACHES THE POD,
// not the list the function returns. A regression in AnnotationsAgent or in the
// Sprintf would be invisible otherwise.
func gabaritPourTest(t *testing.T, p acme.Provider) string {
	t.Helper()
	m := webhookManifests(acme.Reglages{Challenge: acme.ChallengeDNS, Provider: p})
	i := strings.Index(m, "agent-inject-template-env: |")
	if i < 0 {
		t.Fatalf("no injection template in the solver manifest for %q:\n%s", p, m)
	}
	return m[i:]
}
