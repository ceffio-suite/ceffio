// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"strings"
	"testing"
)

// THE CHAINED CONDITIONS, AND WHY EACH CASE IS HERE.
//
// Before this, a ShowWhen could not point at a field that was itself conditional:
// verifierGroupes refused it, because a field gated by a hidden one can never
// appear. The cost was that the ingress module could not say "show the DNS
// provider once dns01 is chosen, then show that provider's credentials once a
// provider is chosen" — so every provider's ~40 credential fields were drawn at
// once. The rule is now recursive, and these tests pin it.

// groupeChaine is a two-level group: mode → (nothing), dns01 → provider →
// provider's credential. It mirrors what the ingress module declares.
func groupeChaine() Group {
	return Group{
		ID:    "tls",
		Title: "TLS",
		Fields: []Field{
			{Key: "challenge", Label: "Challenge", Type: Choice, Options: []Option{
				{Value: "http01", Label: "HTTP-01"}, {Value: "dns01", Label: "DNS-01"},
			}},
			{Key: "dns_provider", Label: "Dns Provider", Type: Choice, Required: true,
				Options:  []Option{{Value: "cloudflare", Label: "Cloudflare"}, {Value: "ovh", Label: "OVH"}},
				ShowWhen: &Condition{Key: "challenge", Equals: "dns01"}},
			{Key: "cloudflare_token", Label: "Cloudflare Token", Type: Secret, Required: true,
				ShowWhen: &Condition{Key: "dns_provider", Equals: "cloudflare"}},
			{Key: "ovh_application_key", Label: "Ovh Application Key", Type: Secret, Required: true,
				ShowWhen: &Condition{Key: "dns_provider", Equals: "ovh"}},
		},
	}
}

// TestVisibleDeuxNiveaux : a field behind a chain of two conditions is visible
// only when BOTH hold.
//
// THE CASE THAT MATTERS IS THE MIDDLE ONE: with challenge=dns01 and no provider
// chosen, the provider is visible and its credentials are not. A single-level
// comparison would have shown them as soon as challenge matched — which is
// exactly the defect the chain removes.
func TestVisibleDeuxNiveaux(t *testing.T) {
	g := groupeChaine()
	cas := []struct {
		nom     string
		v       Values
		visible map[string]bool
	}{
		{
			nom: "http01: nothing provider-related appears",
			v:   Values{"challenge": "http01"},
			visible: map[string]bool{
				"challenge": true, "dns_provider": false,
				"cloudflare_token": false, "ovh_application_key": false,
			},
		},
		{
			nom: "dns01, no provider chosen yet",
			v:   Values{"challenge": "dns01"},
			visible: map[string]bool{
				"challenge": true, "dns_provider": true,
				// The provider is visible, ITS credentials are not: the second
				// link of the chain is not satisfied.
				"cloudflare_token": false, "ovh_application_key": false,
			},
		},
		{
			nom: "dns01 + cloudflare: only Cloudflare's credential appears",
			v:   Values{"challenge": "dns01", "dns_provider": "cloudflare"},
			visible: map[string]bool{
				"challenge": true, "dns_provider": true,
				"cloudflare_token": true,
				// OVH's field stays hidden: its OWN condition does not hold.
				"ovh_application_key": false,
			},
		},
		{
			nom: "dns01 + ovh: the other direction",
			v:   Values{"challenge": "dns01", "dns_provider": "ovh"},
			visible: map[string]bool{
				"challenge": true, "dns_provider": true,
				"cloudflare_token": false, "ovh_application_key": true,
			},
		},
		{
			nom: "a provider chosen while http01: the chain's FIRST link fails",
			v:   Values{"challenge": "http01", "dns_provider": "cloudflare"},
			visible: map[string]bool{
				"challenge": true,
				// The provider's own condition is false, so it is hidden — and
				// its credentials with it, even though their own condition holds.
				// This is the case a single-level rule gets wrong.
				"dns_provider": false, "cloudflare_token": false,
			},
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			for cle, attendu := range c.visible {
				if got := Visible(g, c.v, cle); got != attendu {
					t.Errorf("Visible(%s) = %v, expected %v.\n"+
						"A field is visible when its own condition holds AND the field that "+
						"condition points at is visible — both halves are needed.",
						cle, got, attendu)
				}
			}
		})
	}
}

// TestVisibleTroisNiveaux : the rule holds for a chain of three, which is what
// makes it a rule rather than a special case for two.
func TestVisibleTroisNiveaux(t *testing.T) {
	g := Group{
		ID:    "trois",
		Title: "Trois",
		Fields: []Field{
			{Key: "a", Label: "A", Type: Choice, Options: []Option{{Value: "on", Label: "On"}}},
			{Key: "b", Label: "B", Type: Choice,
				Options:  []Option{{Value: "on", Label: "On"}},
				ShowWhen: &Condition{Key: "a", Equals: "on"}},
			{Key: "c", Label: "C", Type: Choice,
				Options:  []Option{{Value: "on", Label: "On"}},
				ShowWhen: &Condition{Key: "b", Equals: "on"}},
			{Key: "d", Label: "D", Type: Secret, ShowWhen: &Condition{Key: "c", Equals: "on"}},
		},
	}

	// Each step adds one link: d appears only when all three hold.
	etapes := []struct {
		v        Values
		dVisible bool
	}{
		{Values{}, false},
		{Values{"a": "on"}, false},
		{Values{"a": "on", "b": "on"}, false},
		{Values{"a": "on", "b": "on", "c": "on"}, true},
		// A break in the middle hides everything below, whatever the leaves say.
		{Values{"a": "off", "b": "on", "c": "on"}, false},
		{Values{"a": "on", "b": "off", "c": "on"}, false},
	}
	for _, e := range etapes {
		if got := Visible(g, e.v, "d"); got != e.dVisible {
			t.Errorf("avec %v : Visible(d) = %v, expected %v.\n"+
				"A three-level chain must fail at the first broken link, not only at "+
				"the leaf's own condition.", e.v, got, e.dVisible)
		}
	}
}

// TestUnCycleEstRefuse : A depending on B depending on A is refused at
// registration.
//
// WHY IT IS STILL REFUSED WHILE A CHAIN IS ALLOWED: neither field of a cycle can
// ever be visible, so both would stay hidden forever and nothing would report it —
// the form would simply show neither, and the operator would have no way of
// knowing why. A chain, by contrast, has a reachable root.
func TestUnCycleEstRefuse(t *testing.T) {
	// Direct: A waits on B, B waits on A.
	g := Group{ID: "cycle", Title: "Cycle", Fields: []Field{
		{Key: "a", Label: "A", Type: Bool, ShowWhen: &Condition{Key: "b", Equals: "true"}},
		{Key: "b", Label: "B", Type: Bool, ShowWhen: &Condition{Key: "a", Equals: "true"}},
	}}
	err := verifierGroupes("m", []Group{g})
	if err == nil {
		t.Fatal("a two-field cycle was ACCEPTED: both fields would stay hidden forever, " +
			"and nothing would say why")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("the refusal does not name a cycle: %v", err)
	}
	// The message shows the chain, so the reader sees WHICH fields loop rather
	// than only that one exists.
	if !strings.Contains(err.Error(), "a → b") && !strings.Contains(err.Error(), "b → a") {
		t.Errorf("the refusal does not show the chain: %v", err)
	}

	// Longer: a → b → c → a.
	g3 := Group{ID: "cycle3", Title: "Cycle3", Fields: []Field{
		{Key: "a", Label: "A", Type: Bool, ShowWhen: &Condition{Key: "b", Equals: "true"}},
		{Key: "b", Label: "B", Type: Bool, ShowWhen: &Condition{Key: "c", Equals: "true"}},
		{Key: "c", Label: "C", Type: Bool, ShowWhen: &Condition{Key: "a", Equals: "true"}},
	}}
	if err := verifierGroupes("m", []Group{g3}); err == nil {
		t.Error("a three-field cycle was ACCEPTED")
	}

	// SELF-REFERENCE is the shortest cycle.
	gAuto := Group{ID: "auto", Title: "Auto", Fields: []Field{
		{Key: "a", Label: "A", Type: Bool, ShowWhen: &Condition{Key: "a", Equals: "true"}},
	}}
	if err := verifierGroupes("m", []Group{gAuto}); err == nil {
		t.Error("a field depending on itself was ACCEPTED")
	}

	// A DIAMOND IS NOT A CYCLE: two fields waiting on the same one. Refusing it
	// would make the check useless for a real form.
	gDiamant := Group{ID: "diamant", Title: "Diamant", Fields: []Field{
		{Key: "racine", Label: "Racine", Type: Bool},
		{Key: "gauche", Label: "Gauche", Type: Bool, ShowWhen: &Condition{Key: "racine", Equals: "true"}},
		{Key: "droite", Label: "Droite", Type: Bool, ShowWhen: &Condition{Key: "racine", Equals: "true"}},
		{Key: "bas", Label: "Bas", Type: Bool,
			ShowWhen: &Condition{Key: "gauche", Equals: "true"}},
	}}
	if err := verifierGroupes("m", []Group{gDiamant}); err != nil {
		t.Errorf("a diamond (two fields on one target) was refused: %v.\n"+
			"Only a CYCLE is unrepresentable; a shared target is a normal form.", err)
	}

	// A CHAINED GROUP IS ACCEPTED — the whole point of this change.
	if err := verifierGroupes("m", []Group{groupeChaine()}); err != nil {
		t.Errorf("the chained group was refused: %v.\n"+
			"A ShowWhen pointing at a conditional field is what this change allows.", err)
	}
}

// TestUnRequisMasqueNEstPasExige : a required field that is not visible is not
// demanded, and the same field becomes demanded once it is.
//
// THIS IS THE BEHAVIOUR AN OPERATOR FEELS. A form drawn at challenge=http01 must
// save without a provider token; the same form at dns01=cloudflare must refuse to
// save without one. If a hidden required field were demanded, every save would
// fail for a field the operator cannot see.
func TestUnRequisMasqueNEstPasExige(t *testing.T) {
	g := groupeChaine()

	// Visible path: everything the form drew is supplied.
	ok := Values{
		"challenge": "dns01", "dns_provider": "cloudflare", "cloudflare_token": "jeton",
	}
	if err := Validate(g, ok); err != nil {
		t.Fatalf("a complete visible form was refused: %v", err)
	}

	// A VISIBLE required field with no value IS refused. The field used here is
	// a TEXT one, and that is not incidental: a SECRET that is empty is never
	// demanded, whatever Required says — the value is never sent back to the
	// browser, so a form re-saved to change one setting would otherwise be
	// refused for a password it cannot display. Measuring this was the reason the
	// first version of this test failed: it made a Secret required, and the rule
	// it hit is a deliberate one.
	texte := Group{ID: "t", Title: "T", Fields: []Field{
		{Key: "mode", Label: "Mode", Type: Choice, Options: []Option{
			{Value: "on", Label: "On"}, {Value: "off", Label: "Off"},
		}},
		{Key: "nom", Label: "Nom", Type: Text, Required: true,
			ShowWhen: &Condition{Key: "mode", Equals: "on"}},
	}}
	if err := Validate(texte, Values{"mode": "on", "nom": "x"}); err != nil {
		t.Fatalf("a visible required Text field that IS filled was refused: %v", err)
	}
	err := Validate(texte, Values{"mode": "on"})
	if err == nil {
		t.Fatal("a VISIBLE required Text field with no value was accepted")
	}
	if !strings.Contains(err.Error(), "nom") {
		t.Errorf("the refusal does not name the missing field: %v", err)
	}
	// And the same field, hidden, is not demanded.
	if err := Validate(texte, Values{"mode": "off"}); err != nil {
		t.Errorf("a HIDDEN required Text field was demanded: %v", err)
	}

	// A SECRET, by contrast, is never demanded when empty — Required or not.
	// The rule is asserted here so a later change to it is a visible decision.
	if err := Validate(g, Values{"challenge": "dns01", "dns_provider": "cloudflare"}); err != nil {
		t.Errorf("an empty Secret was demanded: %v.\n"+
			"A stored secret is never sent back, so a form re-saved to change another "+
			"setting would be refused for a password it cannot display.", err)
	}

	// HIDDEN required fields, with no value at all: ACCEPTED.
	for _, v := range []Values{
		{"challenge": "http01"},
		{"challenge": "http01", "dns_provider": "cloudflare"},
	} {
		if err := Validate(g, v); err != nil {
			t.Errorf("avec %v : the save was refused (%v).\n"+
				"A required field that is NOT VISIBLE must not be demanded: the "+
				"operator cannot fill a field they cannot see.", v, err)
		}
	}

	// challenge=dns01 IS refused with no provider, and that is correct: the
	// provider BECOMES VISIBLE, and it is Required. This case was in the list
	// above in the first version of this test, and asserting it would have been
	// asserting that a visible required field is not demanded — the opposite of
	// the rule.
	if err := Validate(g, Values{"challenge": "dns01"}); err == nil {
		t.Error("challenge=dns01 with no provider was accepted: the provider is VISIBLE and " +
			"Required, so it must be demanded")
	}

	// A credential belonging to a provider that was NOT chosen: the field is
	// hidden, so its value is not validated — and must not be required either.
	autre := Values{"challenge": "dns01", "dns_provider": "ovh",
		"ovh_application_key": "k", "cloudflare_token": ""}
	if err := Validate(g, autre); err != nil {
		t.Errorf("a save with another provider's field empty was refused: %v.\n"+
			"The hidden provider's fields must not be demanded.", err)
	}
}

// TestLesChampsVisiblesSontCeuxAttendus pins the exact answer the proof asks for:
// for challenge=dns01 and dns_provider=cloudflare, the visible fields are the
// challenge, the provider, the zone, and Cloudflare's own — nothing else.
func TestLesChampsVisiblesSontCeuxAttendus(t *testing.T) {
	g := Group{
		ID:    "tls",
		Title: "TLS",
		Fields: []Field{
			{Key: "challenge", Label: "Challenge", Type: Choice, Options: []Option{{Value: "dns01", Label: "DNS-01"}}},
			{Key: "dns_provider", Label: "Dns Provider", Type: Choice, Required: true,
				Options:  []Option{{Value: "cloudflare", Label: "Cloudflare"}, {Value: "ovh", Label: "OVH"}},
				ShowWhen: &Condition{Key: "challenge", Equals: "dns01"}},
			{Key: "dns_zone", Label: "Dns Zone", Type: Text,
				ShowWhen: &Condition{Key: "challenge", Equals: "dns01"}},
			{Key: "cloudflare_api_token", Label: "Cloudflare Api Token", Type: Secret, Required: true,
				ShowWhen: &Condition{Key: "dns_provider", Equals: "cloudflare"}},
			{Key: "cloudflare_zone_id", Label: "Cloudflare Zone Id", Type: Text,
				ShowWhen: &Condition{Key: "dns_provider", Equals: "cloudflare"}},
			{Key: "ovh_endpoint", Label: "Ovh Endpoint", Type: Text,
				ShowWhen: &Condition{Key: "dns_provider", Equals: "ovh"}},
		},
	}

	v := Values{"challenge": "dns01", "dns_provider": "cloudflare"}
	got := champsVisibles(g, v)

	attendu := []string{"challenge", "dns_provider", "dns_zone",
		"cloudflare_api_token", "cloudflare_zone_id"}
	if len(got) != len(attendu) {
		t.Fatalf("visible fields = %v (%d), expected %v (%d).\n"+
			"For dns01 + cloudflare the visible set is the challenge, the provider, "+
			"the zone and Cloudflare's own fields — not one of another provider's.",
			got, len(got), attendu, len(attendu))
	}
	for i := range attendu {
		if got[i] != attendu[i] {
			t.Errorf("visible field %d = %q, expected %q (order is declaration order)", i, got[i], attendu[i])
		}
	}
	// And OVH's field is NOT among them.
	for _, k := range got {
		if strings.HasPrefix(k, "ovh_") {
			t.Errorf("OVH's field %q is visible while Cloudflare is the chosen provider", k)
		}
	}
}
