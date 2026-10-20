// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"sort"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestLesChampsVisiblesPourDNS01Cloudflare is THE PROOF the plan asks for: for
// challenge=dns01 and dns_provider=cloudflare, the visible fields are EXACTLY the
// challenge, the provider, the zone, and Cloudflare's own — nothing else.
//
// IT IS ASSERTED ON THE DECLARED GROUP, not on a fixture: the question is what the
// ingress module actually shows an operator, so reading a copy would prove nothing
// about the module. The counts are derived from the same tables the form is built
// from, so adding a credential to Cloudflare in internal/acme updates the
// expectation without touching this test — and adding one to OVH must NOT change
// it, which is the second assertion.
func TestLesChampsVisiblesPourDNS01Cloudflare(t *testing.T) {
	m := &ingressModule{}
	var groupe module.Group
	for _, g := range m.Settings() {
		if g.ID == groupeTLS {
			groupe = g
		}
	}
	if len(groupe.Fields) == 0 {
		t.Fatal("the tls group declares no field")
	}

	v := module.Values{"challenge": "dns01", "dns_provider": "cloudflare"}

	var visibles []string
	for _, f := range groupe.Fields {
		if module.Visible(groupe, v, f.Key) {
			visibles = append(visibles, f.Key)
		}
	}
	sort.Strings(visibles)

	// The expected set: the three general fields, plus Cloudflare's credentials.
	attendu := []string{"challenge", "dns_provider", "dns_zone"}
	for _, f := range groupe.Fields {
		if strings.HasPrefix(f.Key, "cred_cloudflare_") {
			attendu = append(attendu, f.Key)
		}
	}
	sort.Strings(attendu)

	if strings.Join(visibles, ",") != strings.Join(attendu, ",") {
		t.Errorf("visible fields = %v\nexpected          = %v\n"+
			"For dns01 + cloudflare the visible set is the challenge, the provider, the zone "+
			"and Cloudflare's own credentials — and NOT one of another provider's.",
			visibles, attendu)
	}

	// Cloudflare must really have credentials, otherwise the test above would
	// pass by comparing two lists that are both only the three general fields.
	var nbCloudflare int
	for _, f := range groupe.Fields {
		if strings.HasPrefix(f.Key, "cred_cloudflare_") {
			nbCloudflare++
			if !f.Required && f.Type == module.Secret {
				t.Errorf("Cloudflare's field %q is a secret and not Required: the table in "+
					"internal/acme says a token is needed to sign the challenge", f.Key)
			}
		}
	}
	if nbCloudflare == 0 {
		t.Fatal("Cloudflare declares no credential field: the comparison above proves nothing")
	}

	// AND NO OTHER PROVIDER'S FIELD APPEARS. This is the defect the chained
	// conditions remove: before, every provider's ~40 fields were drawn as soon as
	// dns01 was chosen.
	for _, cle := range visibles {
		if strings.HasPrefix(cle, "cred_") && !strings.HasPrefix(cle, "cred_cloudflare_") {
			t.Errorf("field %q is visible while cloudflare is the chosen provider.\n"+
				"Before the contract allowed a chained ShowWhen, every provider's fields "+
				"appeared at once; the condition on dns_provider is what narrows it.", cle)
		}
	}

	// A DIFFERENT PROVIDER YIELDS A DIFFERENT SET, which is what makes the
	// condition a choice rather than a label.
	autre := module.Values{"challenge": "dns01", "dns_provider": "ovh"}
	var visiblesOvh int
	for _, f := range groupe.Fields {
		if module.Visible(groupe, autre, f.Key) && strings.HasPrefix(f.Key, "cred_ovh_") {
			visiblesOvh++
		}
		if module.Visible(groupe, autre, f.Key) && strings.HasPrefix(f.Key, "cred_cloudflare_") {
			t.Errorf("Cloudflare's field %q is visible while OVH is the chosen provider", f.Key)
		}
	}
	if visiblesOvh == 0 {
		t.Error("choosing OVH exposes no OVH credential: the chain points at the wrong field")
	}
}

// TestLeProviderEstUnChoixFerme : dns_provider is a Choice whose options come from
// the provider table, with readable labels.
//
// A free-text field was the previous state, and it accepted anything: a typo
// silently produced a solver pointed at a provider nobody supports. A closed list
// means the operator picks, and the module stores a value it knows.
func TestLeProviderEstUnChoixFerme(t *testing.T) {
	m := &ingressModule{}
	var prov module.Field
	for _, g := range m.Settings() {
		for _, f := range g.Fields {
			if f.Key == "dns_provider" {
				prov = f
			}
		}
	}
	if prov.Type != module.Choice {
		t.Fatalf("dns_provider is a %s, expected a Choice: a free-text provider accepts a "+
			"typo and produces a solver pointed at nothing", prov.Type)
	}
	if len(prov.Options) == 0 {
		t.Fatal("dns_provider has no option: the dropdown would be empty")
	}
	if !prov.Required {
		t.Error("dns_provider is not Required: a dns01 installation with no provider cannot sign anything")
	}

	// Every option carries a readable label, and the VALUE stays the solver's
	// name: a label may be reworded, the value may not.
	var vuCloudflare bool
	for _, o := range prov.Options {
		if o.Label == "" {
			t.Errorf("option %q has no label: the list would show the solver's string", o.Value)
		}
		if o.Value == "cloudflare" {
			vuCloudflare = true
			if o.Label != "Cloudflare" {
				t.Errorf("cloudflare's label is %q, expected the readable name", o.Label)
			}
		}
	}
	if !vuCloudflare {
		t.Error("cloudflare is absent from the provider list on a platform that uses it")
	}

	// The condition is on challenge, and the credentials on dns_provider: the
	// two-level chain this lot exists to allow.
	if prov.ShowWhen == nil || prov.ShowWhen.Key != "challenge" {
		t.Errorf("dns_provider's condition is %+v, expected one on challenge", prov.ShowWhen)
	}
}
