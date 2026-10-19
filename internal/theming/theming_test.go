// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package theming

import (
	"regexp"
	"strings"
	"testing"
)

// These tests run WITHOUT a cluster. They check what the package promises on
// its own: that the embedded images exist, that their formats are those
// Nextcloud accepts, and that the list of settings covers the whole theme.
//
// WHY THIS IS WORTH TESTING: an embedded file that disappears is not a compile
// error — `//go:embed` only fails if the PATTERN matches nothing, not if one
// file among several vanishes. A theme applied with a missing logo would leave
// Nextcloud on its default identity, and the installation would report success.

// TestImagesEmbarqueesExistent : every image is present in the binary and is
// not empty.
//
// A zero-length file is the case that worries us: it would make `occ` fail at
// the end of the installation, after everything else has been deployed.
func TestImagesEmbarqueesExistent(t *testing.T) {
	for _, img := range images {
		contenu, err := assets.ReadFile(img.Embede)
		if err != nil {
			t.Errorf("%s: not readable in the binary: %v", img.Embede, err)
			continue
		}
		if len(contenu) == 0 {
			t.Errorf("%s: present but empty", img.Embede)
		}
	}
}

// TestLogoContientViewBox : logo.svg carries a `viewBox="0 0 <l> <h>"`.
//
// WHY IT MATTERS BEYOND THE RENDERING: Nextcloud reads the dimensions from the
// SVG to lay out the logo in the HEADER OF E-MAILS. An SVG without a viewBox
// still displays in a browser — the login page would look right — and breaks
// only in the e-mails, where no one thinks to look.
func TestLogoContientViewBox(t *testing.T) {
	motif := regexp.MustCompile(`viewBox\s*=\s*"0 0 (\d+) (\d+)"`)

	for _, nom := range []string{"logo.svg", "logoheader.svg"} {
		contenu, err := assets.ReadFile("assets/" + nom)
		if err != nil {
			t.Fatalf("%s: unreadable: %v", nom, err)
		}
		m := motif.FindStringSubmatch(string(contenu))
		if m == nil {
			t.Errorf("%s: no viewBox of the form '0 0 <l> <h>' — e-mail headers "+
				"would not know its dimensions", nom)
			continue
		}
		if m[1] == "0" || m[2] == "0" {
			t.Errorf("%s: viewBox has a null dimension (%sx%s)", nom, m[1], m[2])
		}
	}
}

// TestCouleursValides : the colours are hexadecimal as Nextcloud expects.
//
// A named colour ("blue") or an RGB triple would be accepted by occ and then
// rendered inconsistently by the interfaces that parse it as hex. The pattern
// locks the format before a hand edit can tastefully drift.
func TestCouleursValides(t *testing.T) {
	valide := regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	for nom, valeur := range map[string]string{
		"primary_color":    CouleurPrimaire,
		"background_color": CouleurFond,
	} {
		if !valide.MatchString(valeur) {
			t.Errorf("%s = %q: expected #RRGGBB", nom, valeur)
		}
	}
}

// TestToutesLesClesSontCouvertes : the settings really cover the nine keys of
// the theme — five texts/colours plus four images.
//
// THE LIST IS READ FROM THE PACKAGE, never recopied here. A first version of
// this test built its own list of expected keys; removing `slogan` from Deploy
// then left it green, because it was checking its own description of the theme
// instead of the theme. Reading textesEtCouleurs and images ties the test to
// the code it protects.
func TestToutesLesClesSontCouvertes(t *testing.T) {
	posees := map[string]string{}
	for _, kv := range textesEtCouleurs {
		posees[kv[0]] = kv[1]
	}
	for _, img := range images {
		posees[img.Cle] = img.Nom
	}

	// The theme is exactly these nine.
	attendues := []string{
		"name", "slogan", "url", "primary_color", "background_color",
		"logo", "logoheader", "favicon", "background",
	}
	for _, cle := range attendues {
		if _, ok := posees[cle]; !ok {
			t.Errorf("key %q is not set by the theme", cle)
		}
	}
	if len(posees) != len(attendues) {
		t.Errorf("the theme sets %d keys, expected %d: %v", len(posees), len(attendues), posees)
	}

	// `imprintUrl` and `privacyUrl` are deliberately absent: they point at legal
	// notices Ceffio does not host, and an empty link in a login footer is
	// worse than no link.
	for _, cle := range []string{"imprintUrl", "privacyUrl"} {
		if _, ok := posees[cle]; ok {
			t.Errorf("%q is set while Ceffio hosts no such page", cle)
		}
	}
}

// TestCheminsAbsolus : the paths handed to occ are absolute.
//
// occ REFUSES a relative path for an image, and the refusal arrives late — at
// the moment the theme is applied, after the whole deployment. Locking the
// shape here moves that failure to the test suite.
func TestCheminsAbsolus(t *testing.T) {
	if !strings.HasPrefix(repertoireTemporaire, "/") {
		t.Errorf("the temporary directory %q is not an absolute path", repertoireTemporaire)
	}
	for _, img := range images {
		chemin := repertoireTemporaire + "/" + img.Nom
		if !strings.HasPrefix(chemin, "/") {
			t.Errorf("path handed to occ for %s is not absolute: %s", img.Cle, chemin)
		}
	}
}

// TestPasDeSourceEmbarquee : the design sources stay OUT of the binary.
//
// branding/nextcloud/ carries the editable sources (background.svg,
// favicon.svg, logo-ink.svg) and build-assets.py, which regenerates the SVGs
// from the Sora typeface. Embedding them would put the same drawing in the
// binary twice and would ship a build script inside a production executable.
// They live in branding/, where one iterates on the design.
func TestPasDeSourceEmbarquee(t *testing.T) {
	sources := []string{"assets/background.svg", "assets/favicon.svg", "assets/logo-ink.svg"}
	for _, s := range sources {
		if _, err := assets.ReadFile(s); err == nil {
			t.Errorf("%s is embedded in the binary: design sources belong in branding/", s)
		}
	}
}
