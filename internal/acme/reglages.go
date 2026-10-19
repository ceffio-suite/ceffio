// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package acme holds the typing and the validation of the ACME settings shared
// by the whole suite: which challenge proves domain ownership, and through which
// DNS provider.
//
// WHY THIS PACKAGE EXISTS, AND WHY THE TYPES ARE NOT PLAIN STRINGS: the two
// settings have a small, closed set of admissible values, and a wrong one does
// not fail where it is written. An unknown challenge name lands in the
// ClusterIssuer manifest, cert-manager accepts the object, and the certificate
// is simply never issued — the browser then shows Traefik's default
// self-signed certificate, which every operator reads as a TLS problem rather
// than as a typo. Validating HERE turns that silent, weeks-later failure into
// an immediate, named error at the moment the setting is read.
//
// WHY NOT IN internal/ingress: the settings are read by layers that do not
// import the ingress package (the console page, the install sequence, and later
// the registry modules). Keeping them in the layer that happens to consume them
// today is what forces every other caller to read os.Getenv itself — the drift
// this package exists to prevent.
//
// WHERE THE VALUES COME FROM: read once here, from the environment, exactly
// like storage.Classe(). A module never calls os.Getenv: it receives the
// resolved settings through module.Env, so that "what is this installation
// configured with?" has ONE answer, and so that a future settings page and the
// installer can never disagree.
package acme

import (
	"fmt"
	"os"
	"strings"
)

// Challenge is how ACME proves that this cluster controls the domain.
//
// The zero value is ChallengeHTTP because it is the historical behaviour of the
// suite: an installation that configures nothing must keep the challenge it
// already had, and the port 80 it already serves. Every existing installation
// therefore stays valid without a single edit.
type Challenge string

const (
	// ChallengeHTTP proves control by serving a token over plain HTTP on port
	// 80. It needs no credential and no third party, which is why it is the
	// default — but it CANNOT issue a wildcard certificate: the ACME protocol
	// gives the authority no way of checking a name it cannot address. It also
	// needs one certificate per hostname, so the Let's Encrypt weekly quota is
	// consumed one host at a time.
	ChallengeHTTP Challenge = "http01"

	// ChallengeDNS proves control by publishing a TXT record in the domain's
	// zone. No inbound port is involved, the challenge never touches the web
	// server, and — decisively — it is the ONLY challenge that can issue a
	// wildcard. It costs a DNS provider credential, held in OpenBao.
	ChallengeDNS Challenge = "dns01"
)

// Provider is the DNS provider used to publish the challenge record.
//
// WHY IT IS NOT AN ENUMERATION OF KNOWN PROVIDERS: cert-manager resolves
// DNS-01 through an in-tree solver or through a webhook, and the webhook
// receives the provider name as an opaque VALUE inside a free-form `config`
// block. Enumerating the names here would mean editing and republishing Ceffio
// to support one more host, which is exactly the coupling this package refuses.
// The name is therefore carried as data, and an unknown-but-valid provider
// reaches the solver untouched.
type Provider string

// In-tree solver names, accepted as-is by cert-manager with no webhook.
//
// WHY THIS SHORT LIST IS STILL WORTH DECLARING: these are the providers for
// which Ceffio can write a solver with NO third-party component to deploy. An
// operator who picks one gets a configuration that works on the first attempt,
// on any cluster, which is the useful distinction — not a gate on what may be
// used.
const (
	// ProviderCloudflare is Cloudflare (also the target of the Ceffio demo
	// deployment). The public API token is scoped to Zone.DNS:Edit on one
	// zone; the account-wide key is never to be used.
	ProviderCloudflare Provider = "cloudflare"
	// ProviderRoute53 is AWS Route 53.
	ProviderRoute53 Provider = "route53"
	// ProviderRFC2136 is dynamic DNS updates (RFC 2136) with TSIG.
	//
	// It matters more than it looks: it is IN-TREE, and it speaks the standard
	// dynamic-update protocol — so BIND, Knot, PowerDNS, Technitium and Windows
	// DNS are covered with no webhook at all. It is what an operator who runs
	// their own DNS uses, and it is the reason "no API-provider account" is not
	// a dead end.
	ProviderRFC2136 Provider = "rfc2136"
	// ProviderACMEDNS is acme-dns: a small dedicated DNS server that answers
	// ONLY for _acme-challenge, delegated by CNAME.
	//
	// It is the in-tree answer for an operator with no rights over the main
	// zone, or who refuses to hand one out. The credential can write exactly one
	// record name and nothing else.
	ProviderACMEDNS Provider = "acmedns"
)

// Valeurs par défaut, all read from the environment when nothing is configured.
const (
	// VariableChallenge overrides the challenge.
	VariableChallenge = "CEFFIO_ACME_CHALLENGE"
	// VariableDNSProvider overrides the DNS provider (dns01 only).
	VariableDNSProvider = "CEFFIO_DNS_PROVIDER"
	// VariableDNSZone overrides the zone to update (dns01 only).
	VariableDNSZone = "CEFFIO_DNS_ZONE"
	// VariableWebhookGroup is the groupName of the libdns webhook solver.
	//
	// The value doubles as the ACME challenge name the solver registers under,
	// so it is unique per deployment and stable across upgrades: changing it
	// after records have been published would leave the old ones behind.
	VariableWebhookGroup = "CEFFIO_DNS_WEBHOOK_GROUP"
)

// WebhookGroupParDefaut is the groupName used when nothing is configured.
//
// WHY NOT A PROVIDER NAME: this is the identity of the deployed solver, not of
// the DNS host behind it. It has to be a name this project owns, so that it
// cannot collide with another webhook solver in the same cluster — cert-manager
// refuses two solvers claiming the same group.
const WebhookGroupParDefaut = "acme.ceffio.org"

// Reglages is the resolved ACME configuration of one installation.
//
// It is passed BY VALUE through module.Env: a module receives the answer, never
// the environment. Reading the environment in several places is what makes two
// components of the same installation disagree about their own configuration.
type Reglages struct {
	Challenge Challenge
	Provider  Provider

	// Zone is the DNS zone the challenge record is written in. Empty means
	// "the zone of the domain being certified", resolved by the caller.
	Zone string

	// WebhookGroup is the solver identity for out-of-tree providers.
	WebhookGroup string
}

// HTTP01 returns the settings equivalent to a suite that was never
// reconfigured: HTTP-01, no provider, no credential.
//
// WHY EXPOSED: tests and callers that build a module.Env for a read-only
// operation (state, view) should not have to re-read the environment to obtain
// a value they will not use. Reading the environment there would make a status
// page depend on an operator's shell.
func HTTP01() Reglages {
	return Reglages{Challenge: ChallengeHTTP, WebhookGroup: WebhookGroupParDefaut}
}

// DepuisValeurs builds the resolved settings from three values, VALIDATING them.
//
// WHY A SEPARATE ENTRY POINT FROM DepuisEnvironnement: the settings can now come
// from the store — what the operator chose in the console or on the command line
// — and not only from the environment. Both paths must produce the SAME
// validated result, so the checks live here and DepuisEnvironnement simply calls
// this one. Two implementations would let a setting be accepted from the console
// and refused by the installer, or the other way round.
func DepuisValeurs(challenge, provider, zone string) (Reglages, error) {
	r := HTTP01()

	brut := strings.ToLower(strings.TrimSpace(challenge))
	switch Challenge(brut) {
	case "":
		// nothing configured: keep the historical HTTP-01
	case ChallengeHTTP, ChallengeDNS:
		r.Challenge = Challenge(brut)
	default:
		return Reglages{}, fmt.Errorf(
			"challenge %q is not supported: use %q or %q", brut, ChallengeHTTP, ChallengeDNS)
	}

	r.Provider = Provider(strings.ToLower(strings.TrimSpace(provider)))
	r.Zone = strings.TrimSpace(zone)

	// A provider only means something for DNS-01. Saying so is better than
	// ignoring the name in silence: an operator who set a provider while the
	// challenge is still http01 has a configuration that does not do what it
	// says, and would discover it much later.
	if r.Challenge == ChallengeHTTP && r.Provider != "" {
		return Reglages{}, fmt.Errorf(
			"a DNS provider (%q) is set while the challenge is %q: a provider is only used "+
				"by the %q challenge. Use %q, or clear the provider.",
			r.Provider, ChallengeHTTP, ChallengeDNS, ChallengeDNS)
	}

	// DNS-01 without a provider has nothing to publish the record with. This is
	// the hard stop, deliberately WITHOUT a provider guessing game: picking one
	// on the operator's behalf would write a credential they never created.
	if r.Challenge == ChallengeDNS && r.Provider == "" {
		return Reglages{}, fmt.Errorf(
			"the %q challenge requires a DNS provider (one of the in-tree solvers: %s, %s, "+
				"%s, %s — or the provider name of the DNS webhook). Without it no challenge "+
				"record can be published and no certificate will be issued",
			ChallengeDNS, ProviderCloudflare, ProviderRoute53, ProviderRFC2136, ProviderACMEDNS)
	}
	return r, nil
}

// DepuisEnvironnement reads and VALIDATES the settings.
//
// It returns an error rather than falling back to a default when a value is
// wrong: a fallback would install a working HTTPS setup that is not the one the
// operator asked for, and the difference only shows up at the next renewal.
// An installation that cannot honour its own configuration must say so.
//
// Deprecated: the values now come from the module's stored settings, primed from
// these variables on the installation's first pass. This function stays for that
// amorçage and for the install path, and delegates to DepuisValeurs so both
// accept exactly the same configurations.
func DepuisEnvironnement() (Reglages, error) {
	r, err := DepuisValeurs(
		os.Getenv(VariableChallenge),
		os.Getenv(VariableDNSProvider),
		os.Getenv(VariableDNSZone),
	)
	if err != nil {
		return Reglages{}, err
	}
	if g := strings.TrimSpace(os.Getenv(VariableWebhookGroup)); g != "" {
		r.WebhookGroup = g
	}
	return r, nil
}

// DNS01 dit si le challenge configuré est DNS-01.
//
// Exists so that callers never compare the raw string themselves: a comparison
// written by hand in ten places is ten chances of testing "dns" instead of
// "dns01" and taking the wrong branch without any error.
func (r Reglages) DNS01() bool { return r.Challenge == ChallengeDNS }

// EmpreinteWebhook dit si le provider exige le solver webhook (libdns) plutôt
// qu'un solver in-tree.
//
// WHY THIS FUNCTION AND NOT A LIST IN THE CALLER: the set of in-tree solvers is
// a property of cert-manager's version, not of this project. Naming it here,
// once, next to the constants it compares, means a cert-manager upgrade that
// brings a new in-tree solver is a one-line change with an obvious location.
func (r Reglages) EmpreinteWebhook() bool {
	switch r.Provider {
	case ProviderCloudflare, ProviderRoute53, ProviderRFC2136, ProviderACMEDNS:
		return false
	}
	return r.Provider != ""
}
