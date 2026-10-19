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

// TestToutesLesClesSontCouvertes : the settings really cover the eleven keys of
// the theme — five texts/colours, two legal pages, four images.
//
// THE LIST IS READ FROM THE PACKAGE, never recopied here. A first version of
// this test built its own list of expected keys; removing `slogan` from Deploy
// then left it green, because it was checking its own description of the theme
// instead of the theme. Reading textesEtCouleurs, images and the legal pages
// ties the test to the code it protects.
func TestToutesLesClesSontCouvertes(t *testing.T) {
	posees := map[string]string{}
	for _, kv := range textesEtCouleurs {
		posees[kv[0]] = kv[1]
	}
	for _, img := range images {
		posees[img.Cle] = img.Nom
	}
	// The legal pages, with their defaults — which is what an installation
	// gets when the environment says nothing.
	pages := LegalPages{ImprintURL: ImprintURLDefaut, PrivacyURL: PrivacyURLDefaut}
	for _, kv := range pages.clesLegales() {
		posees[kv[0]] = kv[1]
	}

	// The theme is exactly these eleven.
	attendues := []string{
		"name", "slogan", "url", "primary_color", "background_color",
		"imprintUrl", "privacyUrl",
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

// TestDepuisEnvironnement : the two legal-page variables are read, and a
// malformed value is REFUSED rather than copied.
//
// WHY THE REFUSAL IS TESTED AND NOT ONLY THE HAPPY PATH: Nextcloud writes the
// value into an href untouched. A value without a scheme becomes a relative
// link resolved against the login page, so the visitor lands on
// https://cloud.<domain>/ceffio.org/mentions and gets a 404 that looks like a
// broken installation. Accepting it silently would produce exactly the dead
// link the check exists to prevent.
func TestDepuisEnvironnement(t *testing.T) {
	cas := []struct {
		nom        string
		imprint    string
		privacy    string
		veutErreur bool
		attendu    LegalPages
	}{
		{
			nom:     "rien de configuré : aucune page",
			attendu: LegalPages{},
		},
		{
			nom:     "les deux URLs valides",
			imprint: "https://ceffio.org/mentions-legales",
			privacy: "https://ceffio.org/confidentialite",
			attendu: LegalPages{
				ImprintURL: "https://ceffio.org/mentions-legales",
				PrivacyURL: "https://ceffio.org/confidentialite",
			},
		},
		{
			nom:     "http accepté (une installation interne peut ne pas avoir de TLS)",
			imprint: "http://intranet.local/mentions",
			attendu: LegalPages{ImprintURL: "http://intranet.local/mentions"},
		},
		{
			nom:        "sans schéma : refusé",
			imprint:    "ceffio.org/mentions-legales",
			veutErreur: true,
		},
		{
			nom:        "schéma exotique : refusé",
			privacy:    "mailto:legal@ceffio.org",
			veutErreur: true,
		},
		{
			nom:     "espaces autour : nettoyés",
			imprint: "  https://ceffio.org/mentions-legales  ",
			attendu: LegalPages{ImprintURL: "https://ceffio.org/mentions-legales"},
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			// t.Setenv restores the previous value automatically and forbids
			// t.Parallel — which is what we want: these read the process
			// environment, so they must not run concurrently.
			t.Setenv(VariableImprintURL, c.imprint)
			t.Setenv(VariablePrivacyURL, c.privacy)

			obtenu, err := DepuisEnvironnement()
			if c.veutErreur {
				if err == nil {
					t.Fatalf("expected a refusal, got %+v", obtenu)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if obtenu != c.attendu {
				t.Errorf("got %+v, expected %+v", obtenu, c.attendu)
			}
		})
	}
}

// TestClesLegalesIgnorentLeVide : an empty page is NOT written to Nextcloud.
//
// WHY THIS MATTERS: `occ theming:config imprintUrl ""` CLEARS the value. An
// operator who configured the links once and then removed the variables must
// not lose them — an absent setting means "do not touch", not "erase". The
// default is applied by Deploy, not here, so this function must stay silent on
// empty values.
func TestClesLegalesIgnorentLeVide(t *testing.T) {
	if cles := (LegalPages{}).clesLegales(); len(cles) != 0 {
		t.Errorf("empty pages produced %d keys, expected none: %v", len(cles), cles)
	}
	une := LegalPages{ImprintURL: "https://ceffio.org/mentions-legales"}
	cles := une.clesLegales()
	if len(cles) != 1 || cles[0][0] != "imprintUrl" {
		t.Errorf("one page produced %v, expected only imprintUrl", cles)
	}
}

// TestPagesParDefautSontAbsolues : the shipped defaults are valid URLs.
//
// A default without a scheme is the trap this whole check exists for, and it
// would be invisible: the default is applied AFTER DepuisEnvironnement, so it
// never goes through the validation.
func TestPagesParDefautSontAbsolues(t *testing.T) {
	for nom, url := range map[string]string{
		"imprintUrl": ImprintURLDefaut,
		"privacyUrl": PrivacyURLDefaut,
	} {
		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			t.Errorf("default %s = %q is not an absolute URL", nom, url)
		}
	}
}
