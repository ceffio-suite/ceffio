// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// THE CONSOLE AND THE CONTRACT MUST AGREE ON WHAT IS VISIBLE.
//
// The rule lives in two places, and they cannot share code: module.Visible is Go,
// and the console's form logic is JavaScript that must run in a browser. A
// divergence would be invisible and expensive — a form hiding a field the
// validator demands (an operator cannot save), or showing one it refuses (the save
// fails with a message about a field on screen).
//
// The comparison is made by RUNNING the page's own function, not by reading it or
// by re-implementing it here. An extracted copy would agree with the Go side while
// the shipped page disagreed, which is exactly the failure this test exists to
// catch.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// jeuVisibilite is the data both sides are run on: a group with a chain of two
// levels, a diamond, and a field with no condition.
//
// IT IS THE SAME JSON ON BOTH SIDES — written once, sent to the browser and
// decoded into Go types — so the two cannot be compared on different inputs,
// which would make the test pass while proving nothing.
const jeuVisibilite = `{
  "group": {
    "id": "tls", "title": "TLS",
    "fields": [
      {"key":"challenge","label":"Challenge","type":"choice",
       "options":[{"value":"http01","label":"HTTP-01"},{"value":"dns01","label":"DNS-01"}]},
      {"key":"dns_provider","label":"Provider","type":"choice","required":true,
       "options":[{"value":"cloudflare","label":"Cloudflare"},{"value":"ovh","label":"OVH"}],
       "show_when":{"key":"challenge","equals":"dns01"}},
      {"key":"dns_zone","label":"Zone","type":"text",
       "show_when":{"key":"challenge","equals":"dns01"}},
      {"key":"cloudflare_token","label":"Token","type":"secret","required":true,
       "show_when":{"key":"dns_provider","equals":"cloudflare"}},
      {"key":"ovh_app_key","label":"App key","type":"secret","required":true,
       "show_when":{"key":"dns_provider","equals":"ovh"}},
      {"key":"note","label":"Note","type":"text"}
    ]
  },
  "cases": [
    {"name":"http01 only","values":{"challenge":"http01"}},
    {"name":"dns01, no provider yet","values":{"challenge":"dns01"}},
    {"name":"dns01 + cloudflare","values":{"challenge":"dns01","dns_provider":"cloudflare"}},
    {"name":"dns01 + ovh","values":{"challenge":"dns01","dns_provider":"ovh"}},
    {"name":"provider chosen while http01","values":{"challenge":"http01","dns_provider":"cloudflare"}},
    {"name":"empty","values":{}}
  ]
}`

// TestConsoleEtContratDonnentLaMemeVisibilite compares the two implementations on
// the same data.
//
// THE PAGE'S FUNCTION IS EXECUTED WITH NODE, the same JavaScript the browser
// loads, extracted from the served file. What is compared is the SET of visible
// keys for each case — the answer both sides must produce, in the same order.
func TestConsoleEtContratDonnentLaMemeVisibilite(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed: the comparison needs it to run the page's own function")
	}

	// 1. What the CONTRACT says.
	var jeu struct {
		Group module.Group `json:"group"`
		Cases []struct {
			Name   string            `json:"name"`
			Values map[string]string `json:"values"`
		} `json:"cases"`
	}
	if err := json.Unmarshal([]byte(jeuVisibilite), &jeu); err != nil {
		t.Fatalf("unreadable fixture: %v", err)
	}
	// A group that the registry itself refuses would make the comparison
	// meaningless: the two sides would agree on something that cannot ship.
	if err := module.VerifierGroupesPourTest("test", []module.Group{jeu.Group}); err != nil {
		t.Fatalf("the fixture group is refused by the registry: %v", err)
	}

	attendu := map[string][]string{}
	for _, c := range jeu.Cases {
		v := module.Values{}
		for k, val := range c.Values {
			v[k] = val
		}
		var visibles []string
		for _, f := range jeu.Group.Fields {
			if module.Visible(jeu.Group, v, f.Key) {
				visibles = append(visibles, f.Key)
			}
		}
		attendu[c.Name] = visibles
	}

	// 2. What the PAGE says — by running it.
	obtenu := visibiliteDeLaPage(t)

	for _, c := range jeu.Cases {
		a := strings.Join(attendu[c.Name], ",")
		o := strings.Join(obtenu[c.Name], ",")
		if a != o {
			t.Errorf("case %q: the contract says [%s], the page says [%s].\n"+
				"The two implement ONE rule in two languages; when they disagree, a form "+
				"hides what the validator demands (the save is refused for a field the "+
				"operator cannot see) or shows what it refuses.", c.Name, a, o)
		}
	}

	// 3. And the whole point of the change: a CHAIN yields a narrower set than a
	//    single-level rule would.
	//
	//    This assertion guards the test itself: if both sides regressed to the
	//    old rule together, they would agree and every comparison above would
	//    pass. Saying what the answer must BE, once, is what makes agreement
	//    meaningful.
	attenduChaine := map[string]string{
		"http01 only":                  "challenge,note",
		"dns01, no provider yet":       "challenge,dns_provider,dns_zone,note",
		"dns01 + cloudflare":           "challenge,dns_provider,dns_zone,cloudflare_token,note",
		"dns01 + ovh":                  "challenge,dns_provider,dns_zone,ovh_app_key,note",
		"provider chosen while http01": "challenge,note",
		// A field with NO condition is always visible, so challenge appears even
		// with no values at all. The first version of this table expected
		// "note" alone, and that was wrong: it would have asserted that an
		// unconditional field disappears when nothing is set.
		"empty": "challenge,note",
	}
	for nom, vouloir := range attenduChaine {
		if got := strings.Join(attendu[nom], ","); got != vouloir {
			t.Errorf("case %q: the contract's answer is [%s], expected [%s].\n"+
				"This is the expected answer, not just agreement: with a single-level rule "+
				"the credentials would appear while their provider is hidden.", nom, got, vouloir)
		}
	}
}

// visibiliteDeLaPage runs the page's own visibility function on the fixture.
//
// NODE, NOT A BROWSER: the function computes on data and does not touch the DOM,
// so no headless browser is needed — and running the SHIPPED file means the test
// exercises what a browser loads, not a copy that could drift from it.
func visibiliteDeLaPage(t *testing.T) map[string][]string {
	t.Helper()

	page := string(indexHTML(t))

	// Extract the functions under test from the page, by their names. Taking a
	// RANGE rather than the whole file: the page needs a DOM to run, and only
	// these two functions are pure.
	extrait := ""
	for _, nom := range []string{"champVisible", "estVisible"} {
		debut := strings.Index(page, "function "+nom+"(")
		if debut < 0 {
			t.Fatalf("the page no longer defines %s: the rule moved, and this test "+
				"would compare nothing", nom)
		}
		// Up to the next top-level function, or the end of that block.
		reste := page[debut:]
		fin := strings.Index(reste, "\n  function ")
		if fin < 0 {
			fin = len(reste)
		}
		extrait += reste[:fin] + "\n"
	}

	script := fmt.Sprintf(`
const jeu = %s;
%s
const out = {};
for (const c of jeu.cases) {
  out[c.name] = jeu.group.fields.filter(f => champVisible(jeu.group, c.values, f.key, {})).map(f => f.key);
}
process.stdout.write(JSON.stringify(out));
`, jeuVisibilite, extrait)

	chemin := t.TempDir() + "/vis.js"
	if err := os.WriteFile(chemin, []byte(script), 0o600); err != nil {
		t.Fatalf("writing the script: %v", err)
	}
	sortie, err := exec.Command("node", chemin).Output()
	if err != nil {
		t.Fatalf("running the page's function: %v", err)
	}
	var out map[string][]string
	if err := json.Unmarshal(sortie, &out); err != nil {
		t.Fatalf("unreadable answer from the page's function (%s): %v", sortie, err)
	}
	if len(out) == 0 {
		t.Fatal("the page's function answered nothing: the extraction is broken, " +
			"and every comparison below would pass on empty lists")
	}
	return out
}
