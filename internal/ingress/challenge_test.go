// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/acme"
)

// TestHTTP01ManifestInchange is the non-regression guard of the whole change:
// an installation that configures nothing must produce EXACTLY the manifest it
// produced before the challenge became parametrable. Every deployment in the
// field depends on it, and a difference here rewrites the ClusterIssuers of a
// running cluster on the next `ceffio upgrade`.
//
// The assertions are on the SHAPE, not on the exact bytes: what must not
// change is that the solver is http01 on the traefik class, that no DNS
// credential is referenced, and that both issuers (production and staging)
// are produced by the same call.
func TestHTTP01ManifestInchange(t *testing.T) {
	m := acmeManifest("admin@exemple.fr", acme.HTTP01())

	for _, attendu := range []string{
		"name: ceffio-letsencrypt",
		"name: ceffio-letsencrypt-staging",
		"https://acme-v02.api.letsencrypt.org/directory",
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"email: admin@exemple.fr",
		"- http01:",
		"class: traefik",
	} {
		if !strings.Contains(m, attendu) {
			t.Errorf("the http01 manifest no longer contains %q:\n%s", attendu, m)
		}
	}

	// No credential may leak into the HTTP-01 path: it needs none, and a
	// secretRef there would be a file that looks like it holds a token.
	for _, interdit := range []string{"dns01", "webhook", "secretRef"} {
		if strings.Contains(m, interdit) {
			t.Errorf("the http01 manifest mentions %q — HTTP-01 uses no credential:\n%s", interdit, m)
		}
	}
}

// TestDNS01Manifest: the DNS-01 issuer must reference the webhook solver, and
// carry the provider as a VALUE. That last point is what makes a new DNS host
// a configuration change rather than a code change, so it is asserted
// explicitly.
func TestDNS01Manifest(t *testing.T) {
	reglages := acme.Reglages{
		Challenge:    acme.ChallengeDNS,
		Provider:     acme.Provider("scaleway"),
		Zone:         "exemple.fr",
		WebhookGroup: "acme.exemple.fr",
	}
	m := acmeManifest("admin@exemple.fr", reglages)

	for _, attendu := range []string{
		"- dns01:",
		"webhook:",
		"groupName: acme.exemple.fr",
		"solverName: libdns",
		"provider: scaleway",
		"name: ceffio-acme-dns",
		"namespace: cert-manager",
	} {
		if !strings.Contains(m, attendu) {
			t.Errorf("the dns01 manifest lacks %q:\n%s", attendu, m)
		}
	}

	// The staging twin must be produced with the SAME solver. A staging issuer
	// left on http01 while production runs dns01 would make the very test an
	// operator runs to debug DNS-01 exercise a different code path.
	if c := strings.Count(m, "dns01:"); c != 2 {
		t.Errorf("dns01 solver count = %d, want 2 (production AND staging):\n%s", c, m)
	}
	if strings.Contains(m, "- http01:") {
		t.Errorf("a dns01 manifest still declares an http01 solver:\n%s", m)
	}

	// cnameStrategy must NOT be set: with Follow, cert-manager obeys a CNAME
	// synthesized by a wildcard record and writes the challenge in the wrong
	// zone. Leaving it absent is the deliberate choice.
	if strings.Contains(m, "cnameStrategy") {
		t.Errorf("cnameStrategy is set, which re-introduces the wildcard-CNAME trap:\n%s", m)
	}
}

// TestInTreeProvidersUseTheNativeSolver is the assertion that replaced its
// opposite, and it is worth stating why it flipped.
//
// The first version of this code routed EVERY provider through the webhook
// solver, arguing that a provider would then be a value rather than a branch.
// That reasoning cost an image to build, publish and maintain, plus a component
// to deploy — for a capability cert-manager already has in its own binary. The
// in-tree solvers are: cloudflare, route53, azuredns, clouddns, digitalocean,
// akamai, acmedns, rfc2136. For those, the ClusterIssuer references them
// directly and a Secret is the only prerequisite.
//
// The webhook remains the FALLBACK, for the hosts cert-manager does not know
// (Scaleway, OVH, Gandi, Hetzner…). That is what keeps the provider list open
// without pretending every provider needs a component.
func TestInTreeProvidersUseTheNativeSolver(t *testing.T) {
	for _, cas := range []struct {
		provider string
		cle      string // the key cert-manager expects in the solver block
	}{
		{"cloudflare", "cloudflare:"},
		{"route53", "route53:"},
		{"rfc2136", "rfc2136:"},
		{"acmedns", "acmedns:"},
	} {
		t.Run(cas.provider, func(t *testing.T) {
			m := acmeManifest("admin@exemple.fr", acme.Reglages{
				Challenge:    acme.ChallengeDNS,
				Provider:     acme.Provider(cas.provider),
				Zone:         "exemple.fr",
				WebhookGroup: "acme.exemple.fr",
			})
			if !strings.Contains(m, cas.cle) {
				t.Errorf("provider %q does not use the solver cert-manager ships:\n%s", cas.provider, m)
			}
			// NO WEBHOOK for an in-tree host: it would mean deploying a
			// component, and publishing an image, for nothing.
			if strings.Contains(m, "webhook:") {
				t.Errorf("provider %q is routed through the webhook while cert-manager knows it natively:\n%s",
					cas.provider, m)
			}
			// The credential is always referenced by name: an issuer that
			// resolves to no Secret leaves the challenge pending with the
			// reason buried in the CertificateRequest events.
			if !strings.Contains(m, "ceffio-acme-dns") {
				t.Errorf("provider %q does not reference the credential Secret:\n%s", cas.provider, m)
			}
		})
	}
}

// TestProvidersHorsArbreUtilisentLeWebhook: the fallback must still exist, or
// "compatible everywhere" would mean "compatible with the eight hosts
// cert-manager chose".
func TestProvidersHorsArbreUtilisentLeWebhook(t *testing.T) {
	for _, p := range []acme.Provider{"scaleway", "ovh", "gandi", "hetzner", "un-provider-inconnu"} {
		t.Run(string(p), func(t *testing.T) {
			m := acmeManifest("admin@exemple.fr", acme.Reglages{
				Challenge:    acme.ChallengeDNS,
				Provider:     p,
				WebhookGroup: "acme.exemple.fr",
			})
			if !strings.Contains(m, "webhook:") {
				t.Errorf("provider %q has no native solver and no webhook either — it cannot work:\n%s", p, m)
			}
			if !strings.Contains(m, "provider: "+string(p)) {
				t.Errorf("provider %q is not carried as a value:\n%s", p, m)
			}
		})
	}
}

// TestEmpreinteWebhookSepareLesDeuxChemins pins the single decision that routes
// between them: it must say "no webhook" for the four in-tree solvers and "yes"
// for everything else.
func TestEmpreinteWebhookSepareLesDeuxChemins(t *testing.T) {
	for _, p := range []struct {
		provider string
		webhook  bool
	}{
		{"cloudflare", false},
		{"route53", false},
		{"rfc2136", false},
		{"acmedns", false},
		{"scaleway", true},
		{"ovh", true},
		{"inconnu", true},
	} {
		r := acme.Reglages{Challenge: acme.ChallengeDNS, Provider: acme.Provider(p.provider)}
		if got := r.EmpreinteWebhook(); got != p.webhook {
			t.Errorf("EmpreinteWebhook(%q) = %v, want %v", p.provider, got, p.webhook)
		}
	}
}

// TestRedirectionHTTP01KeepTheExemption: under HTTP-01 the ACME path must stay
// reachable in clear, or renewal breaks. This is not cosmetic — the
// /.well-known/acme-challenge request IS the proof of domain control.
func TestRedirectionHTTP01KeepTheExemption(t *testing.T) {
	m := redirectionManifest("ceffio-files", acme.HTTP01())
	if !strings.Contains(m, "redirectRegex") {
		t.Errorf("http01 redirection lost its conditional rule — the challenge would be redirected:\n%s", m)
	}
	if !strings.Contains(m, `[^.#]`) {
		t.Errorf("http01 redirection lost the path class that exempts a leading dot:\n%s", m)
	}
}

// TestRedirectionDNS01IsUnconditional: under DNS-01 nothing is fetched from
// port 80, so the exemption is dead weight and the rule is a plain redirect.
func TestRedirectionDNS01IsUnconditional(t *testing.T) {
	m := redirectionManifest("ceffio-files", acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "cloudflare"})
	if strings.Contains(m, "redirectRegex") {
		t.Errorf("dns01 redirection still carries the http01 exemption:\n%s", m)
	}
	if !strings.Contains(m, "redirectScheme") {
		t.Errorf("dns01 redirection lacks the unconditional rule:\n%s", m)
	}
	// Both middlewares are still emitted, in both namespaces: the Ingress
	// annotations reference them by name, and a missing one makes Traefik
	// serve the route IN CLEAR without failing anything.
	for _, attendu := range []string{"ceffio-redirect-https", "ceffio-redirect-https-fallback"} {
		if !strings.Contains(m, attendu) {
			t.Errorf("dns01 redirection lacks the middleware %q:\n%s", attendu, m)
		}
	}
	if c := strings.Count(m, "namespace: ceffio-files"); c != 2 {
		t.Errorf("both middlewares must be in the namespace of the Ingress, found %d:\n%s", c, m)
	}
}

// TestResumeChallenge: the log line is what an operator reads to know which
// path is active. "dns01" alone does not say through which host the records go,
// and that is what fails first when a credential is wrong.
func TestResumeChallenge(t *testing.T) {
	if got := resumeChallenge(acme.HTTP01()); got != "HTTP-01" {
		t.Errorf("resumeChallenge(http01) = %q", got)
	}
	got := resumeChallenge(acme.Reglages{Challenge: acme.ChallengeDNS, Provider: "ovh"})
	if !strings.Contains(got, "DNS-01") || !strings.Contains(got, "ovh") {
		t.Errorf("resumeChallenge(dns01) = %q, want the challenge AND the provider", got)
	}
}

// TestSolveurNeProduitJamaisDeBlocVide guards the shape of the generated YAML:
// an empty solvers block would be accepted by the API server and produce an
// issuer that can never complete a challenge.
func TestSolveurNeProduitJamaisDeBlocVide(t *testing.T) {
	for _, r := range []acme.Reglages{
		acme.HTTP01(),
		{Challenge: acme.ChallengeDNS, Provider: "cloudflare", WebhookGroup: "acme.exemple.fr"},
	} {
		s := solveur(r)
		if strings.TrimSpace(s) == "" {
			t.Fatalf("empty solver for challenge %q", r.Challenge)
		}
		if !strings.HasPrefix(s, "    - ") {
			t.Errorf("the solver must be a YAML list item at the `solvers:` level, got:\n%s", s)
		}
	}
}
