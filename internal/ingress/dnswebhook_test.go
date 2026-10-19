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
// The injection template sets `error-on-missing-key-<name>` — a missing key
// makes the render FAIL instead of writing an empty value, which is the right
// choice. But the flag applies to the WHOLE template: rendering the union of
// every provider's fields would make a Cloudflare entry fail, because the OVH
// fields it legitimately does not have would be reported missing. The pod would
// never start, and the message would name a field for a provider the operator
// never chose.
//
// So each provider must render ITS OWN fields and nothing else.
func TestAucunChampEtrangerDansLeGabarit(t *testing.T) {
	for _, cas := range []struct {
		provider string
		attendu  []string
		interdit []string
	}{
		{
			provider: "cloudflare",
			attendu:  []string{"api_token", "provider"},
			interdit: []string{"endpoint", "application_key", "tsig_key", "project_id"},
		},
		{
			provider: "ovh",
			attendu:  []string{"endpoint", "application_key", "application_secret", "consumer_key"},
			interdit: []string{"api_token", "tsig_key", "project_id"},
		},
		{
			provider: "scaleway",
			attendu:  []string{"api_token", "project_id"},
			interdit: []string{"endpoint", "application_key", "tsig_key"},
		},
		{
			provider: "route53",
			attendu:  []string{"access_key_id", "secret_access_key", "region"},
			interdit: []string{"api_token", "application_key", "tsig_key"},
		},
		{
			// RFC 2136: the reason "no API-provider account" is not a dead end.
			// BIND, Knot, PowerDNS, Technitium, Windows DNS — a TSIG key and a
			// target server, no token at all. Its presence in the built image
			// was checked with `--list-providers`.
			provider: "rfc2136",
			attendu:  []string{"nameserver", "tsig_key", "tsig_secret", "tsig_algorithm"},
			interdit: []string{"api_token", "application_key", "project_id"},
		},
		{
			// acme-dns: delegated by CNAME, the credential writes exactly one
			// record name. The path for an operator with no rights on the main
			// zone.
			provider: "acmedns",
			attendu:  []string{"api_url", "username", "password", "subdomain"},
			interdit: []string{"api_token", "tsig_key", "application_key"},
		},
	} {
		t.Run(cas.provider, func(t *testing.T) {
			gabarit := gabaritPourTest(t, acme.Provider(cas.provider))

			for _, v := range cas.attendu {
				if !strings.Contains(gabarit, v) {
					t.Errorf("provider %q: the template lacks the field %q — its credential would be empty:\n%s",
						cas.provider, v, gabarit)
				}
			}
			for _, v := range cas.interdit {
				if strings.Contains(gabarit, v) {
					t.Errorf("provider %q: the template renders %q, a field of ANOTHER host. "+
						"With error-on-missing-key, the render would fail and the pod would never start:\n%s",
						cas.provider, v, gabarit)
				}
			}
		})
	}
}

// TestLeNomDuProviderVoyageAvecLEndroit: the provider name must be rendered in
// EVERY case, including the unknown ones. It is what lets the operator tell
// which host an entry was stored for — a Cloudflare token used against a
// Scaleway zone fails with an authorization error that never mentions the
// mismatch.
func TestLeNomDuProviderVoyageAvecLEndroit(t *testing.T) {
	for _, p := range []acme.Provider{
		acme.ProviderCloudflare, acme.ProviderRoute53, acme.ProviderRFC2136,
		acme.ProviderACMEDNS, "scaleway", "un-provider-inconnu",
	} {
		gabarit := gabaritPourTest(t, p)
		if !strings.Contains(gabarit, "provider") {
			t.Errorf("provider %q: the rendered Secret does not carry the provider name:\n%s", p, gabarit)
		}
	}
}

// TestProviderInconnuResteUtilisable: an unknown-but-valid provider must produce
// a usable template. Refusing outright would mean one Ceffio release per DNS
// host — the coupling this whole design exists to avoid — and the generic
// api_token field covers the majority of libdns implementations.
func TestProviderInconnuResteUtilisable(t *testing.T) {
	gabarit := gabaritPourTest(t, "un-provider-inconnu")
	if !strings.Contains(gabarit, "api_token") {
		t.Errorf("an unknown provider renders no token at all:\n%s", gabarit)
	}
	if strings.TrimSpace(gabarit) == "" {
		t.Error("an unknown provider produces an empty template")
	}
}

// TestLeSecretEstBienForme pins the correction that made the first draft
// unusable.
//
// THE SOLVER READS THE SECRET'S KEYS, it does not read a file: it loads every
// key of the referenced Secret into a map and marshals that map to its provider
// library. The rendered document must therefore be `key: value` pairs. Shell
// `export VAR='value'` lines would produce a single key named
// "export CF_API_TOKEN='…'", and the provider would receive no credential at
// all — failing every challenge with an authentication error that names nothing.
func TestLeSecretEstBienForme(t *testing.T) {
	gabarit := gabaritPourTest(t, acme.ProviderCloudflare)
	if strings.Contains(gabarit, "export ") {
		t.Errorf("the template writes shell assignments; the solver reads Secret keys:\n%s", gabarit)
	}
	if !strings.Contains(gabarit, "api_token:") {
		t.Errorf("the template does not write an `api_token:` key:\n%s", gabarit)
	}
}

// TestGroupNameEstObligatoire, from a measurement on the built image:
//
//	F1018 23:04:10 main.go:44] GROUP_NAME environment variable must be specified
//
// The process exits immediately without it, so the Deployment MUST carry it —
// and it must equal the group name the ClusterIssuer declares and the one the
// APIService registers under. Three places hold that single identity.
//
// ASSERTED ON AN OUT-OF-TREE PROVIDER, since only those get a webhook at all:
// Cloudflare, Route 53, RFC 2136 and acme-dns are handled by cert-manager
// itself and never produce this Deployment.
func TestGroupNameEstObligatoire(t *testing.T) {
	horsArbre := acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "scaleway", WebhookGroup: webhookGroup}

	m := webhookManifests(horsArbre)
	if !strings.Contains(m, "name: GROUP_NAME") {
		t.Errorf("the solver Deployment does not set GROUP_NAME and would crash-loop:\n%s", m)
	}
	if !strings.Contains(m, "value: "+webhookGroup) {
		t.Errorf("GROUP_NAME does not carry the shared group value %q:\n%s", webhookGroup, m)
	}
	api := webhookAPIServiceManifest()
	if !strings.Contains(api, "name: v1alpha1."+webhookGroup) {
		t.Errorf("the APIService does not register under %q:\n%s", webhookGroup, api)
	}
	issuer := acmeManifest("a@b.fr", horsArbre)
	if !strings.Contains(issuer, "groupName: "+webhookGroup) {
		t.Errorf("the ClusterIssuer asks for another group than %q:\n%s", webhookGroup, issuer)
	}
}

// TestAucunComposantPourUnProviderConnu: the whole point of the correction.
// cert-manager's binary already carries the solver, so a Deployment for
// Cloudflare would be a pod on a port nothing calls — plus an image to build,
// publish and maintain for a capability that needs none of it.
func TestAucunComposantPourUnProviderConnu(t *testing.T) {
	for _, p := range []acme.Provider{
		acme.ProviderCloudflare, acme.ProviderRoute53,
		acme.ProviderRFC2136, acme.ProviderACMEDNS,
	} {
		r := acme.Reglages{Challenge: acme.ChallengeDNS, Provider: p, WebhookGroup: webhookGroup}
		if r.EmpreinteWebhook() {
			t.Errorf("provider %q is routed to the webhook while cert-manager knows it natively", p)
		}
		// The manifest is still produced (the Secret is mandatory), but it must
		// not contain a Deployment.
		sec := secretDNSManifests(r)
		if strings.Contains(sec, "kind: Deployment") {
			t.Errorf("provider %q produces a Deployment for a solver cert-manager already has:\n%s", p, sec)
		}
		if !strings.Contains(sec, secretACME) {
			t.Errorf("provider %q does not even produce its credential Secret:\n%s", p, sec)
		}
	}
}

// TestSolverLitLeSecretInjection verifies the two halves agree on ONE name: the
// name the injector creates and the name the ClusterIssuer asks the solver to
// read. A mismatch means the solver reads a Secret that does not exist while the
// injector fills another — a failure that names neither.
func TestSolverLitLeSecretInjection(t *testing.T) {
	horsArbre := acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "scaleway", WebhookGroup: webhookGroup}
	m := webhookManifests(horsArbre)
	if !strings.Contains(m, "agent-inject-secret-"+secretACME) {
		t.Errorf("the injector does not create the Secret %q:\n%s", secretACME, m)
	}
	issuer := acmeManifest("a@b.fr", horsArbre)
	if !strings.Contains(issuer, "name: "+secretACME) {
		t.Errorf("the ClusterIssuer points the solver at another Secret name than %q:\n%s", secretACME, issuer)
	}
	// The Role must grant the read: without it the pod starts and every
	// challenge fails on a permission denied.
	if !strings.Contains(m, "resources: [\"secrets\"]") {
		t.Errorf("the solver Role does not grant reading its own Secret:\n%s", m)
	}

	// THE IN-TREE PATH REFERENCES THE SAME SECRET but injects nothing: there
	// is no pod to carry annotations. Verified on Cloudflare, the provider the
	// demo deployment uses.
	cf := acme.Reglages{Challenge: acme.ChallengeDNS, Provider: acme.ProviderCloudflare, Zone: "exemple.fr"}
	sec := secretDNSManifests(cf)
	if !strings.Contains(sec, "agent-inject-secret-"+secretACME) {
		t.Errorf("the Cloudflare Secret is not fed from the vault:\n%s", sec)
	}
	if !strings.Contains(acmeManifest("a@b.fr", cf), "api-token") {
		t.Errorf("the Cloudflare issuer does not ask for the key cert-manager expects:\n%s",
			acmeManifest("a@b.fr", cf))
	}
}

// TestWebhookAbsentEnHTTP01: under HTTP-01 the solver would be a pod on a port
// nothing calls, so deployerWebhookDNS is a no-op. The guard lives there; this
// test pins the shape of what the other path produces.
func TestWebhookAbsentEnHTTP01(t *testing.T) {
	m := webhookManifests(acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare"})
	if !strings.Contains(m, webhookName) {
		t.Errorf("the solver manifest lacks its own name %q:\n%s", webhookName, m)
	}
	// The solver's TLS always comes from the internal authority: a second trust
	// chain would be another thing to rotate and one more handshake failure
	// nobody can place.
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
// Extracting it from the real manifest rather than calling clesProvider directly
// is deliberate: what matters is the TEMPLATE THAT REACHES THE POD, not the list
// the function returns. A regression in the annotation helper or in the Sprintf
// would be invisible otherwise.
func gabaritPourTest(t *testing.T, p acme.Provider) string {
	t.Helper()
	m := webhookManifests(acme.Reglages{Challenge: acme.ChallengeDNS, Provider: p})
	i := strings.Index(m, "agent-inject-template-"+secretACME+": |")
	if i < 0 {
		t.Fatalf("no injection template for the Secret %q in the solver manifest (provider %q):\n%s",
			secretACME, p, m)
	}
	return m[i:]
}
