// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/identity/theme"
)

// TestLesClassesDuHeaderSontStylees is the check the plan asks for, and it catches a
// failure that looks like a broken theme rather than a missing rule.
//
// THE HEADER LIVES IN displayNameHtml, NOT IN A TEMPLATE. keycloak.v2 renders that
// string itself, which is what keeps the theme upgrade-safe — but it also means the
// two classes in it are the ONLY thing tying the header to Ceffio's styling. Rename
// one in the HTML without renaming it in the CSS and the header renders as unstyled
// text, centred in the card, in the wrong font, with the slogan at body size.
//
// THE TEST READS BOTH SIDES: the classes out of the constant, the selectors out of
// the stylesheet that actually ships.
func TestLesClassesDuHeaderSontStylees(t *testing.T) {
	classes := classesDuHeader()
	if len(classes) == 0 {
		t.Fatalf("no class in the display name HTML: %s", DisplayNameHTML)
	}

	css := cssEmbede(t)
	for _, c := range classes {
		// A CLASS FROM THE PARENT THEME IS LEGITIMATE. `kc-logo-text` belongs to
		// keycloak.v2, which styles it — that is exactly why the header can be built
		// from a realm string instead of a template. What must not happen is a class
		// that NEITHER this stylesheet nor the parent knows: it renders as unstyled
		// text inside the card.
		if classesParent[c] {
			continue
		}
		motif := regexp.MustCompile(`\.` + regexp.QuoteMeta(c) + `\b`)
		if !motif.MatchString(css) {
			t.Errorf("class %q appears in displayNameHtml but is styled by neither "+
				"ceffio.css nor keycloak.v2.\nThe header is rendered from that string, "+
				"so a class nobody styles renders as raw text inside the sign-in card.\n"+
				"HTML: %s", c, DisplayNameHTML)
		}
	}
}

// TestLeHeaderPorteLeLogoCeffio : the header names the product and carries the
// slogan. A theme that only recolours Keycloak's default page still says "Keycloak"
// above the card on a platform nobody should have to identify.
func TestLeHeaderPorteLeLogoCeffio(t *testing.T) {
	if !strings.Contains(DisplayNameHTML, "Ceffio") {
		t.Errorf("the header does not name Ceffio: %s", DisplayNameHTML)
	}
	if !strings.Contains(DisplayNameHTML, "ceffio-slogan") {
		t.Errorf("the header carries no ceffio-slogan element, so the slogan cannot be "+
			"styled or changed without touching the HTML: %s", DisplayNameHTML)
	}
	if !strings.Contains(DisplayNameHTML, "kc-logo-text") {
		t.Errorf("the header does not use kc-logo-text, the block keycloak.v2 styles "+
			"as the logo area: %s", DisplayNameHTML)
	}
	// THE STRING IS INSERTED INTO A SHELL COMMAND SINGLE-QUOTED, so an apostrophe
	// would break the kcadm call. The slogan is French and French text invites one.
	if strings.Contains(DisplayNameHTML, "'") {
		t.Error("the display name HTML contains an apostrophe, which breaks the " +
			"single-quoted kcadm argument: use a phrasing without one, or quote it")
	}
}

// TestLeRealmNEstPasMaster : the login page applies to the ceffio realm only. The
// master realm's page is how Keycloak itself is administered, and an administrator
// who lands on the wrong door must see it.
func TestLeRealmNEstPasMaster(t *testing.T) {
	if realmCeffio == "master" {
		t.Fatal("realmCeffio is master: theming it would replace the page used to " +
			"administer Keycloak, and an operator with a broken realm would have no " +
			"recognisable way back in")
	}
	if realmCeffio != "ceffio" {
		t.Errorf("realmCeffio = %q, expected ceffio", realmCeffio)
	}
}

// TestLesLocalesDeclareesSontSupportees : the default locale must be one of the
// supported ones, otherwise Keycloak ignores it silently and serves English.
func TestLesLocalesDeclareesSontSupportees(t *testing.T) {
	defaut := ReglagesParDefaut()
	script := localesSupportees
	var trouve bool
	for _, l := range script {
		if l == defaut.Locale {
			trouve = true
		}
	}
	if !trouve {
		t.Errorf("the default locale %q is not among the supported ones %v: Keycloak "+
			"ignores a default outside the list and serves its own default instead",
			defaut.Locale, script)
	}
	// THE PRODUCT IS FRENCH-FIRST.
	if defaut.Locale != "fr" {
		t.Errorf("the default locale is %q, expected fr: Ceffio is distributed to "+
			"French-speaking operators, and English-by-default is what they complained "+
			"about", defaut.Locale)
	}
}

// TestLeThemeParDefautEstCeffio : an installation gets the Ceffio page, not
// Keycloak's.
func TestLeThemeParDefautEstCeffio(t *testing.T) {
	if r := ReglagesParDefaut(); r.Theme != "ceffio" {
		t.Errorf("the default theme is %q, expected ceffio: the whole point of the "+
			"theme is that users see it without configuring anything", r.Theme)
	}
}

// classesParent lists the classes keycloak.v2 provides and styles itself.
//
// THEY ARE NAMED HERE RATHER THAN ASSUMED: adding an entry is a deliberate act that
// says "the parent handles this one", which is a claim someone can check against the
// keycloak.v2 sources. A typo in a class name would fall through to the regex check
// above and fail.
var classesParent = map[string]bool{
	"kc-logo-text": true,
}

// classesDuHeader returns the class names inside the display name HTML.
func classesDuHeader() []string {
	motif := regexp.MustCompile(`class="([^"]*)"`)
	var out []string
	for _, m := range motif.FindAllStringSubmatch(DisplayNameHTML, -1) {
		out = append(out, strings.Fields(m[1])...)
	}
	return out
}

// cssEmbede returns the stylesheet as it ships.
func cssEmbede(t *testing.T) string {
	t.Helper()
	fs, err := theme.Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.HasSuffix(f.Chemin, "ceffio.css") {
			return string(f.Contenu)
		}
	}
	t.Fatal("ceffio.css is not in the embedded theme")
	return ""
}
