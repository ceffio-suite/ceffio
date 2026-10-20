// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package acme

import (
	"strings"
	"testing"
)

// TestChaqueProviderDeLaTableEstDecrit : every provider that has credential
// fields has a presentation, so a dropdown never shows a raw solver string beside
// four human names.
//
// THE INCONSISTENCY IS WHAT AN OPERATOR SEES FIRST: a list reading
// "Cloudflare · Amazon Route 53 · acme-dns · infomaniak" makes the fourth look
// broken, and the first question asked is whether it is supported. The fallback in
// Description keeps such a provider USABLE, which is why this is a test rather
// than a refusal — but it should not be reachable in a release.
func TestChaqueProviderDeLaTableEstDecrit(t *testing.T) {
	for _, p := range ProvidersConnus() {
		d, ok := Description(p)
		if !ok {
			t.Errorf("provider %q has credential fields and no description: it would appear "+
				"in the list as %q beside names like %q.\n"+
				"Add it to descriptionsProvider — a label, and one sentence saying where to "+
				"create the credential and with which rights.", p, p, "Cloudflare")
			continue
		}
		if strings.TrimSpace(d.Label) == "" {
			t.Errorf("provider %q has a description with no label", p)
		}
		// The label must NOT be the provider string: showing "cloudflare" where
		// the table says "Cloudflare" is the inconsistency this guards.
		if d.Label == string(p) {
			t.Errorf("provider %q shows its own solver string as its label: the label "+
				"is what an operator reads, the string is what the solver receives", p)
		}
		if strings.TrimSpace(d.Help) == "" {
			t.Errorf("provider %q has no help: an operator who does not know what to paste "+
				"finds nothing beside the field", p)
		}
		// ONE SENTENCE, as the contract says: a paragraph in a form is not read.
		//
		// THE COUNT IS ON SENTENCE ENDS, not on periods: a help legitimately
		// contains "api.ovh.com", "route53:ChangeResourceRecordSets" and other
		// dotted tokens, and counting periods flagged correct text. A sentence
		// ends at ". ", "! " or "? ".
		if n := nbPhrases(d.Help); n > 1 {
			t.Errorf("provider %q's help is %d sentences: %.90s\n"+
				"A form shows one sentence beside a field; a paragraph is not read.", p, n, d.Help)
		}
	}
}

// TestLaDescriptionDUnInconnuResteUtilisable : a provider absent from the
// descriptions stays configurable.
//
// The credential table's own comment promises that a host added there alone is
// configurable everywhere at once; refusing to describe it would break that
// promise, and the failure would be an operator unable to use a host Ceffio
// supports.
func TestLaDescriptionDUnInconnuResteUtilisable(t *testing.T) {
	p := Provider("un-hebergeur-inconnu")
	d, ok := Description(p)
	if ok {
		t.Fatal("an unknown provider is reported as described")
	}
	if d.Label != "" && d.Label == string(p) {
		t.Errorf("the fallback label is the raw string %q: it should be capitalised", d.Label)
	}
}

// nbPhrases counts the sentences of a help: a period, exclamation or question
// mark followed by a space or the end of the string.
func nbPhrases(s string) int {
	n := 0
	for i, r := range s {
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		if i == len(s)-1 || (i+1 < len(s) && s[i+1] == ' ') {
			n++
		}
	}
	return n
}

// TestProvidersTriesEstTrieParLibelle : the list a dropdown consumes is sorted on
// what the operator reads, not on the solver's naming.
//
// Sorting on the provider string would put "Amazon Route 53" far from where a
// reader looks for it: the label begins with A, the string with r.
func TestProvidersTriesEstTrieParLibelle(t *testing.T) {
	ls := ProvidersTries()
	if len(ls) < 2 {
		t.Fatalf("only %d provider(s) described: the sort cannot be checked", len(ls))
	}
	for i := 1; i < len(ls); i++ {
		a, _ := Description(ls[i-1])
		b, _ := Description(ls[i])
		if a.Label > b.Label {
			t.Errorf("the list is not sorted by label: %q comes before %q", a.Label, b.Label)
		}
	}
	// And every entry has a description: ProvidersTries reads the descriptions
	// table, so an entry without one would mean the tables disagree.
	for _, p := range ls {
		if _, ok := Description(p); !ok {
			t.Errorf("ProvidersTries returned %q, which has no description", p)
		}
	}
}
