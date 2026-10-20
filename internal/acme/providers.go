// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package acme

import (
	"sort"
	"strings"
)

// HOW A PROVIDER IS NAMED TO AN OPERATOR, AND WHAT IT ASKS OF THEM.
//
// WHY IT IS SEPARATE FROM THE CREDENTIAL TABLE: that table answers "which keys does
// the solver read" — a question about the component. This one answers "what does
// the operator read, and what must they go and create" — a question about the
// person. Mixing them would put a marketing name next to a key name and make both
// look like facts of the same kind.
//
// WHY EVERY PROVIDER MUST HAVE AN ENTRY, and why a fallback exists anyway: a
// provider in the credential table but absent here would appear in a dropdown as
// "infomaniak" while the four others read "Infomaniak", and the inconsistency is
// what an operator notices first. The fallback below keeps such a provider
// USABLE — capitalised, with no help — rather than refusing it, because being
// unable to configure a host Ceffio supports would be a worse failure than a
// missing sentence.

// DescriptionProvider is how one provider is presented.
type DescriptionProvider struct {
	// Label is the human name: what a dropdown shows. It is NOT the solver's
	// provider string, which stays the value — a label may be reworded, the
	// value may not.
	Label string
	// Help is ONE sentence: where to create the credential and with which rights.
	// It is shown as the help of the provider's FIRST credential field, which is
	// where an operator looks when they do not know what to paste.
	//
	// WHY ONE SENTENCE AND NOT A PARAGRAPH: this is read from a form, next to a
	// field that is waiting. A link to a documentation page would be better and is
	// deliberately not attempted: it would rot, and a dead link in a form is worse
	// than a sentence that stays true.
	Help string
}

// descriptionsProvider is the table.
//
// THE HELP IS ABOUT RIGHTS, NOT ABOUT NAVIGATION. "Create an API token" is not
// useful; "with Zone → DNS → Edit on the single zone" is, because that is the
// part an operator gets wrong — a token with account-wide rights looks like it
// works and hands the solver more than it needs.
var descriptionsProvider = map[Provider]DescriptionProvider{
	ProviderCloudflare: {
		Label: "Cloudflare",
		Help: "Cloudflare: an API token scoped to Zone → DNS → Edit on the single zone — " +
			"never the account-wide key, which would give the solver rights over every domain you own.",
	},
	ProviderRoute53: {
		Label: "Amazon Route 53",
		Help: "Route 53: an IAM access key whose policy allows route53:ChangeResourceRecordSets " +
			"on the zone, and route53:ListHostedZonesByIds to find it.",
	},
	ProviderRFC2136: {
		Label: "Dynamic DNS (RFC 2136)",
		Help: "RFC 2136: a TSIG key allowed to update _acme-challenge in the zone — " +
			"this covers BIND, Knot, PowerDNS and Windows DNS with no provider account at all.",
	},
	ProviderACMEDNS: {
		Label: "acme-dns",
		Help: "acme-dns: the account credentials the service returns when you register a " +
			"domain — it can write exactly one _acme-challenge record name and nothing else.",
	},

	// --- libdns webhooks ---------------------------------------------------
	//
	// ONE ENTRY PER PROVIDER OF THE CREDENTIAL TABLE, and their help says which
	// object to create rather than how to click: an operator who knows their
	// provider finds it at once, and one who does not is told the right words to
	// search for.
	"ovh": {
		Label: "OVH",
		Help:  "OVH: an API key created at api.ovh.com/createToken, with GET, POST, PUT and DELETE on /domain/zone/* — the four verbs are needed, because the solver writes the record and then removes it.",
	},
	"scaleway": {
		Label: "Scaleway",
		Help:  "Scaleway: an API key whose IAM policy allows DNSZone to write records — the secret key is shown once at creation, so copy it then.",
	},
	"gandi": {
		Label: "Gandi",
		Help:  "Gandi: a personal access token created in the account's security settings, with the right to manage the zone's records.",
	},
	"hetzner": {
		Label: "Hetzner",
		Help:  "Hetzner: an API token created in the project's security settings, with read and write access to the DNS zone.",
	},
	"ionos": {
		Label: "IONOS",
		Help:  "IONOS: an API key made of a prefix and a secret, created in the account's API settings on the DNS contract.",
	},
	"infomaniak": {
		Label: "Infomaniak",
		Help:  "Infomaniak: an API token created in the manager, with the DNS scope on the domain.",
	},
	"namecheap": {
		Label: "Namecheap",
		Help:  "Namecheap: the API user and key enabled in the account's API access page, with your IP added to the whitelist — the call is refused otherwise.",
	},
	"digitalocean": {
		Label: "DigitalOcean",
		Help:  "DigitalOcean: a personal access token with write scope, created in the API section of the account.",
	},
	"desec": {
		Label: "deSEC",
		Help:  "deSEC: an account token created in the account settings — it can write the records of every domain the account owns.",
	},
	"porkbun": {
		Label: "Porkbun",
		Help:  "Porkbun: an API key and its secret, created in the account's API access page, with the domain enabled for API access.",
	},
	"cloudns": {
		Label: "ClouDNS",
		Help:  "ClouDNS: the auth ID and password used for the API, taken from the account's API settings.",
	},
	"godaddy": {
		Label: "GoDaddy",
		Help:  "GoDaddy: a production API key and secret from the developer portal, with the domain attached to it.",
	},
	"powerdns": {
		Label: "PowerDNS",
		Help:  "PowerDNS: the API URL of your own server (for example http://pdns:8081) and its API key from pdns.conf — this is for a server YOU run, not a hosted service.",
	},
	"azure": {
		Label: "Microsoft Azure DNS",
		Help:  "Azure: an application registration with a client secret, granted the DNS Zone Contributor role on the zone.",
	},
	"googlecloud": {
		Label: "Google Cloud DNS",
		Help:  "Google Cloud: the JSON key of a service account with the DNS Administrator role on the project, exported from the IAM console.",
	},
}

// Description returns how a provider is presented, and whether the table knows it.
//
// AN UNKNOWN PROVIDER IS NOT AN ERROR: it gets a capitalised name and no help, so
// a host added to the credential table alone stays configurable. Refusing it would
// make this table a gate, which is the opposite of what the credential table's
// comment promises.
func Description(p Provider) (DescriptionProvider, bool) {
	d, ok := descriptionsProvider[p]
	if ok {
		return d, true
	}
	// THE FALLBACK keeps an undescribed host USABLE: a capitalised name, no help.
	// Refusing it would make this table a gate, which is the opposite of what the
	// credential table's own comment promises.
	return DescriptionProvider{Label: capitaliser(string(p))}, false
}

// capitaliser renders a provider string as a name: "infomaniak" → "Infomaniak".
func capitaliser(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ProvidersTries lists the providers of this table, sorted by their label, so a
// dropdown is alphabetical to the operator's eye rather than to the solver's
// naming.
func ProvidersTries() []Provider {
	out := make([]Provider, 0, len(descriptionsProvider))
	for p := range descriptionsProvider {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return descriptionsProvider[out[i]].Label < descriptionsProvider[out[j]].Label
	})
	return out
}
