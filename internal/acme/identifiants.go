// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package acme

import "sort"

// This file describes WHAT CREDENTIAL EACH DNS PROVIDER NEEDS.
//
// WHY A TABLE AND NOT CODE PER PROVIDER: adding a host must be adding a line
// here, not writing a page, a route or a manifest. The table is read by the
// console to draw the credential form and by the module's Apply to know which
// keys to store — so a host added here is configurable everywhere at once, and
// Ceffio does not have to be republished to support it.
//
// WHY IT ALSO MATTERS FOR THE PROVIDERS CEFFIO DOES NOT KNOW: the webhook
// solver receives the provider name as an opaque value and its configuration as
// a free-form map. A host absent from this table can therefore still be used —
// through its own credential fields entered as free text — which is what keeps
// the table a convenience rather than a gate.

// ChampIdentifiant is one credential field of a DNS provider.
//
// The Name is the key the solver expects in its Secret, NOT the provider's own
// spelling of it: the libdns webhook reads `api_token`, while Cloudflare's
// documentation says "API Token". Writing the wrong one produces a solver that
// starts, signs nothing, and fails the challenge with no error naming the field.
type ChampIdentifiant struct {
	// Name is the key in the solver's configuration block and in the Secret.
	Name string `json:"name"`
	// Label is what the operator reads, in the console and in the CLI.
	Label string `json:"label"`
	// Help is one sentence under the field.
	Help string `json:"help,omitempty"`
	// Secret says whether the value is a credential. Only a field marked
	// Secret is masked by the console, kept in OpenBao rather than a
	// ConfigMap, and never sent back to a browser. A non-secret field is
	// something like a zone ID or an endpoint, which an operator may want to
	// read back.
	Secret bool `json:"secret"`
	// Required refuses an empty value when the provider is selected.
	Required bool `json:"required,omitempty"`
}

// IdentifiantsDuProvider returns the credential fields of a provider, and
// whether the provider is known.
//
// UNKNOWN PROVIDERS ARE NOT AN ERROR: the caller falls back to free-form
// fields, so an operator can still configure a host this table does not
// describe. Returning an error here would turn a convenience into a gate — and
// the whole reason the provider name travels as data is that Ceffio must not
// have to be republished for one more host.
func IdentifiantsDuProvider(p Provider) ([]ChampIdentifiant, bool) {
	c, ok := identifiantsProvider[p]
	return c, ok
}

// ChampsIdentifiant construes the credential fields of a provider, falling back
// to free-form ones when the table does not describe it.
//
// THE FREE-FORM FALLBACK IS TWO GENERIC FIELDS, not one blob: the solver reads
// its configuration as a map of key to value, so the operator enters the keys
// its host's documentation gives. A single "configuration" text field would
// force them to encode JSON by hand, which is where a typo becomes a solver
// that runs and does nothing.
//
// The fallback is marked as such in the help text, so the operator knows the
// keys are theirs to get right rather than Ceffio's to guarantee.
func ChampsIdentifiant(p Provider) []ChampIdentifiant {
	if c, ok := identifiantsProvider[p]; ok {
		return c
	}
	return []ChampIdentifiant{
		{
			Name:  "provider",
			Label: "Provider name",
			Help: "The provider name as the solver expects it. Ceffio does not describe this host: " +
				"the field names below are the ones its own documentation gives.",
			Required: true,
		},
		{
			Name:     "credentials",
			Label:    "Credentials",
			Help:     "One key=value per line, exactly as the solver's documentation names them.",
			Secret:   true,
			Required: true,
		},
	}
}

// ProvidersConnus lists the providers described by the table, sorted. It feeds
// the console's help: the operator sees which hosts come with a ready-made
// form.
func ProvidersConnus() []Provider {
	out := make([]Provider, 0, len(identifiantsProvider))
	for p := range identifiantsProvider {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// identifiantsProvider is the table.
//
// THE NAMES ARE THE SOLVER'S, each verified against the component that reads
// them — cert-manager's in-tree solver configuration for the four in-tree
// hosts, the libdns webhook for the rest. Getting one wrong is silent: the
// solver starts, the Secret is written, and the challenge fails with a DNS
// error that names nothing.
var identifiantsProvider = map[Provider][]ChampIdentifiant{
	// In-tree: cert-manager's own cloudflare solver replaces
	// `apiTokenSecretRef`, so the key is `api-token` in the Secret
	// (internal/ingress writes it) and the field below is what the console
	// collects before storing it there.
	ProviderCloudflare: {
		{
			Name:     "api-token",
			Label:    "API token",
			Help:     "A token scoped to Zone.DNS:Edit on the single zone. Never the account-wide key: it would give the solver rights over every domain you own.",
			Secret:   true,
			Required: true,
		},
	},

	// In-tree: access key and secret, in the shape the AWS SDK reads.
	ProviderRoute53: {
		{Name: "access-key-id", Label: "Access key ID", Help: "An IAM key allowed to change records in the zone.", Secret: false, Required: true},
		{Name: "secret-access-key", Label: "Secret access key", Secret: true, Required: true},
		{Name: "region", Label: "Region", Help: "The zone's region; Route 53 is global, so us-east-1 usually works.", Secret: false},
	},

	// In-tree, and the one that needs no account anywhere: it speaks the
	// standard dynamic-update protocol, so BIND, Knot, PowerDNS, Technitium
	// and Windows DNS are all covered. This is why "I run my own DNS" is not a
	// dead end.
	ProviderRFC2136: {
		{Name: "nameserver", Label: "Nameserver", Help: "Host:port of the DNS server accepting updates.", Secret: false, Required: true},
		{Name: "tsig-key-name", Label: "TSIG key name", Secret: false, Required: true},
		{Name: "tsig-key-secret", Label: "TSIG key secret", Help: "The shared secret of the TSIG key, base64 as the server holds it.", Secret: true, Required: true},
		{Name: "tsig-algorithm", Label: "TSIG algorithm", Help: "hmac-sha256 unless the server says otherwise.", Secret: false},
	},

	// In-tree: a small DNS server that answers ONLY for _acme-challenge. The
	// answer for an operator who has no rights over the main zone, or refuses
	// to hand one out — the credential can write one record name and nothing
	// else.
	ProviderACMEDNS: {
		{Name: "username", Label: "acme-dns username", Secret: false, Required: true},
		{Name: "password", Label: "acme-dns password", Secret: true, Required: true},
		{Name: "subdomain", Label: "Subdomain", Help: "The subdomain acme-dns allocated for this zone.", Secret: false, Required: true},
		{Name: "server", Label: "acme-dns server URL", Help: "Where the acme-dns service answers, for example https://auth.example.org.", Secret: false, Required: true},
	},

	// Out-of-tree: handled by the libdns webhook. The field names are the
	// libdns library's, which is what the solver reads — NOT the provider's
	// documentation spelling. Verified against the built image, where a wrong
	// name produces a solver that starts and then fails the challenge.
	"ovh": {
		{Name: "application_key", Label: "Application key", Secret: false, Required: true},
		{Name: "application_secret", Label: "Application secret", Secret: true, Required: true},
		{Name: "consumer_key", Label: "Consumer key", Secret: true, Required: true},
		{Name: "endpoint", Label: "Endpoint", Help: "ovh-eu, ovh-ca, ovh-us… depending on the account.", Secret: false},
	},
	"scaleway": {
		{Name: "secret_key", Label: "Secret key", Secret: true, Required: true},
		{Name: "project_id", Label: "Project ID", Secret: false, Required: true},
		{Name: "organization_id", Label: "Organization ID", Secret: false},
	},
	"gandi": {
		{Name: "api_token", Label: "Personal access token", Help: "A token with the right to change records in the zone.", Secret: true, Required: true},
	},
	"hetzner": {
		{Name: "api_token", Label: "API token", Secret: true, Required: true},
	},
	"ionos": {
		{Name: "api_key", Label: "API key prefix", Secret: false, Required: true},
		{Name: "api_secret", Label: "API secret", Secret: true, Required: true},
	},
	"infomaniak": {
		{Name: "api_token", Label: "API token", Secret: true, Required: true},
	},
	"namecheap": {
		{Name: "api_user", Label: "API user", Secret: false, Required: true},
		{Name: "api_key", Label: "API key", Secret: true, Required: true},
	},
	"digitalocean": {
		{Name: "auth_token", Label: "Personal access token", Secret: true, Required: true},
	},
	"desec": {
		{Name: "auth_token", Label: "Account token", Secret: true, Required: true},
	},
	"porkbun": {
		{Name: "api_key", Label: "API key", Secret: false, Required: true},
		{Name: "secret_api_key", Label: "Secret API key", Secret: true, Required: true},
	},
	"cloudns": {
		{Name: "auth_id", Label: "Auth ID", Secret: false, Required: true},
		{Name: "auth_password", Label: "Auth password", Secret: true, Required: true},
	},
	"godaddy": {
		{Name: "key", Label: "API key", Secret: false, Required: true},
		{Name: "secret", Label: "API secret", Secret: true, Required: true},
	},
	"powerdns": {
		{Name: "server_url", Label: "API URL", Help: "The PowerDNS API endpoint, for example http://pdns:8081.", Secret: false, Required: true},
		{Name: "api_key", Label: "API key", Secret: true, Required: true},
	},
	"azure": {
		{Name: "tenant_id", Label: "Tenant ID", Secret: false, Required: true},
		{Name: "client_id", Label: "Client ID", Secret: false, Required: true},
		{Name: "client_secret", Label: "Client secret", Secret: true, Required: true},
		{Name: "subscription_id", Label: "Subscription ID", Secret: false, Required: true},
		{Name: "resource_group_name", Label: "Resource group", Secret: false, Required: true},
	},
	"googlecloud": {
		{Name: "project", Label: "Project", Secret: false, Required: true},
		{Name: "service_account_json", Label: "Service account JSON", Help: "The whole JSON key of a service account allowed to change records.", Secret: true, Required: true},
	},
}
