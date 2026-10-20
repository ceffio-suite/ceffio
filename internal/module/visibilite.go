// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

// VISIBILITY OF A FIELD, IN ONE PLACE.
//
// WHY THIS FILE EXISTS: visibility used to be a single comparison —
// `v[f.ShowWhen.Key] == f.ShowWhen.Equals` — repeated in Validate and written a
// second time in the console's JavaScript. Two implementations of one rule drift,
// and the drift is invisible: a form that hides a field the validator expects, or
// shows one it refuses, and neither side reports a disagreement.
//
// THE RULE IS RECURSIVE, and that is what was missing. A field is visible when its
// own condition holds AND the field that condition points at is itself visible.
// Without the second half, a CHAIN could not be expressed at all: the ingress
// module needs the DNS provider's credentials to appear once a provider is chosen
// (dns_provider → cloudflare_token), and dns_provider itself only appears once
// dns01 is chosen (challenge → dns_provider). The registry therefore REFUSED a
// ShowWhen pointing at a conditional field, and the cost was that every provider's
// ~40 credential fields were drawn at once.
//
// THE RECURSION IS WHAT MAKES A FORM EXPRESSIVE, and it is what this file removes:
// the rule above is the whole contract. Any form may now show a field based on a
// choice made in another conditional field, in as many levels as it needs.

// Visible reports whether a field of the group is visible for the given values.
//
// IT IS THE ONLY DEFINITION OF VISIBILITY. Validate calls it to decide whether a
// field must be checked at all, the console applies the same rule in JavaScript
// (pinned by a test that compares the two on the same data), and the CLI uses it
// to report what it would send.
//
// A KEY THAT IS NOT IN THE GROUP IS INVISIBLE, not visible: a caller asking about
// a field that does not exist has a bug, and answering "visible" would let it
// validate or display something nothing declares.
func Visible(g Group, v Values, key string) bool {
	champ, ok := champDe(g, key)
	if !ok {
		return false
	}
	// Visited keys guard against a cycle. verifierGroupes refuses one at
	// registration, so this cannot happen on a validated group — and a function
	// that recurses on caller-supplied data must not be able to loop forever on
	// bad input, because a panic in the console would take down the whole
	// process.
	return visible(g, v, champ, map[string]bool{key: true})
}

// visible is the recursive step, with the visited set threaded through.
func visible(g Group, v Values, f Field, vus map[string]bool) bool {
	if f.ShowWhen == nil {
		return true
	}
	// The field the condition points at must exist AND be visible: a field
	// gated by a hidden choice can never appear, so its dependants cannot
	// either.
	cible, ok := champDe(g, f.ShowWhen.Key)
	if !ok || vus[f.ShowWhen.Key] {
		return false
	}
	if !visible(g, v, cible, ajouter(vus, f.ShowWhen.Key)) {
		return false
	}
	return v[f.ShowWhen.Key] == f.ShowWhen.Equals
}

// champsVisibles returns the keys of the fields visible for these values, in
// declaration order.
//
// WHY IT IS HERE AND NOT IN EACH CALLER: the console must send only what it drew,
// the CLI must report only what it would apply, and a test asserts the two agree.
// Three copies of "which fields are visible" would be three answers.
func champsVisibles(g Group, v Values) []string {
	out := make([]string, 0, len(g.Fields))
	for _, f := range g.Fields {
		if Visible(g, v, f.Key) {
			out = append(out, f.Key)
		}
	}
	return out
}

// champDe returns a field of the group by its key.
func champDe(g Group, key string) (Field, bool) {
	for _, f := range g.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// ajouter returns a copy of the visited set with one more key.
//
// A COPY, not a mutation: the same set is shared across sibling branches of the
// recursion, and marking a key visited in one branch would wrongly hide it in
// another. A diamond — two fields depending on the same one — is legitimate.
func ajouter(vus map[string]bool, key string) map[string]bool {
	out := make(map[string]bool, len(vus)+1)
	for k := range vus {
		out[k] = true
	}
	out[key] = true
	return out
}

// VerifierGroupesPourTest exposes the registry's validation, for a test in another
// package that needs to know its own fixture is a group the registry would accept.
//
// WHY IT IS EXPORTED: the console's test compares the page's visibility function
// with this package's, on a group written as JSON. If that group were one the
// registry refuses — a cycle, a ShowWhen on a Text — the comparison would prove
// nothing, since neither side could ever ship it. The unstable part of the check
// is therefore made available rather than duplicated: a copy in the test would
// drift from the rule it claims to apply.
func VerifierGroupesPourTest(id string, groupes []Group) error {
	return verifierGroupes(id, groupes)
}
