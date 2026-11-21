// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package website

import (
	"regexp"
	"strings"
	"testing"
)

// domaineTest is a domain the IANA reserves for documentation (RFC 2606): the
// tests can name a host without naming anybody's installation, and the page
// they render is the page a real installation renders.
const domaineTest = "example.com"

// adresseTest is a contact address on that same reserved domain: the rendered
// page is identical to the one an installation with an address publishes,
// without naming a real person.
const adresseTest = "equipe@example.com"

// TestFilesRendChaqueFichier proves the rendered page is COMPLETE and
// HOST-INDEPENDENT: every declared file has a key, every key has content, and
// no placeholder survives.
//
// WHY "no placeholder survives" is a hard failure: a literal {{DOMAIN}} on the
// public page is visible to every visitor and in every crawler, and nothing
// but this test would notice it.
func TestFilesRendChaqueFichier(t *testing.T) {
	fichiers, err := Files(domaineTest, "")
	if err != nil {
		t.Fatalf("Files(%q): %v", domaineTest, err)
	}
	if len(fichiers) != len(Paths()) {
		t.Fatalf("%d files rendered, %d declared", len(fichiers), len(Paths()))
	}
	for _, p := range Paths() {
		contenu, ok := fichiers[p.Cle]
		if !ok {
			t.Errorf("key %q is declared but not rendered into %q", p.Cle, p.Chemin)
			continue
		}
		if strings.TrimSpace(contenu) == "" {
			t.Errorf("key %q is empty", p.Cle)
		}
		if strings.Contains(contenu, "{{") {
			t.Errorf("key %q still contains a placeholder", p.Cle)
		}
	}

	// The substitution is not a no-op: the host really appears where it must.
	index := fichiers[CleIndexFR]
	for _, attendu := range []string{
		"https://" + domaineTest + "/",
		"https://admin." + domaineTest,
		"https://" + domaineTest + "/.well-known/security.txt",
	} {
		if !strings.Contains(index, attendu) {
			t.Errorf("FR page does not contain %q", attendu)
		}
	}
}

// TestAucunFichierNonDeclare proves the embed list and the fichier table agree:
// a file dropped into site/ without being declared is NOT published, and the
// test says so instead of letting it rot in the binary.
func TestAucunFichierNonDeclare(t *testing.T) {
	noms, err := fichiersEmbedes()
	if err != nil {
		t.Fatalf("fichiersEmbedes: %v", err)
	}
	declares := map[string]bool{}
	for _, f := range fichiers {
		declares[f.source] = true
	}
	embarques := map[string]bool{}
	for _, n := range noms {
		embarques[n] = true
		if !declares[n] {
			t.Errorf("%s is embedded but not declared in the fichier table: it would never be published", n)
		}
	}
	for source := range declares {
		if !embarques[source] {
			t.Errorf("%s is declared but not embedded: the install would fail at Files time", source)
		}
	}
}

// TestDomaineRefuse proves a host that is not a bare host name is rejected
// instead of producing broken absolute URLs.
func TestDomaineRefuse(t *testing.T) {
	for _, domaine := range []string{"", "   ", "https://example.com", "example.com/", "exa mple.com", "example.com/path"} {
		if _, err := Files(domaine, ""); err == nil {
			t.Errorf("Files(%q) accepted a host that is not a bare host name", domaine)
		}
	}
}

// TestSitemap proves the sitemap lists exactly the two pages the module
// publishes, absolute and without a trailing filename.
func TestSitemap(t *testing.T) {
	fichiers, err := Files(domaineTest, "")
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	sitemap := fichiers[CleSitemap]
	for _, attendu := range []string{
		"<loc>https://" + domaineTest + "/</loc>",
		"<loc>https://" + domaineTest + "/en/</loc>",
	} {
		if !strings.Contains(sitemap, attendu) {
			t.Errorf("sitemap does not contain %q:\n%s", attendu, sitemap)
		}
	}
	if n := strings.Count(sitemap, "<loc>"); n != 2 {
		t.Errorf("sitemap lists %d URLs, expected 2", n)
	}
}

// TestRobotsPointeVersLeSitemap proves robots.txt is a real policy (it allows
// the page) and points at the sitemap the module generates.
func TestRobotsPointeVersLeSitemap(t *testing.T) {
	fichiers, err := Files(domaineTest, "")
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	robots := fichiers[CleRobots]
	if !strings.Contains(robots, "User-agent: *") || !strings.Contains(robots, "Allow: /") {
		t.Errorf("robots.txt does not allow the page:\n%s", robots)
	}
	if !strings.Contains(robots, "Sitemap: https://"+domaineTest+"/sitemap.xml") {
		t.Errorf("robots.txt does not point at the sitemap:\n%s", robots)
	}
}

// TestPageNeChargeRienDExterne proves the page can live behind the Content
// Security Policy the module sets (default-src 'none'): no script, no inline
// style, no form, no frame, and no sub-resource fetched from another origin.
//
// WHY A TEST AND NOT A REVIEW: the policy and the page are edited in two
// different files, and only a test can prove they still agree. The moment
// somebody adds a web font or an inline style attribute, the page renders
// unstyled behind the deployed policy — this test fails first.
func TestPageNeChargeRienDExterne(t *testing.T) {
	fichiers, err := Files(domaineTest, "")
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	interdits := []string{"<script", "style=", "<form", "<iframe", "javascript:", "@import", "onerror=", "onload="}
	for _, cle := range []string{CleIndexFR, CleIndexEN} {
		page := fichiers[cle]
		for _, interdit := range interdits {
			if strings.Contains(page, interdit) {
				t.Errorf("%s contains %q, which the deployed CSP forbids", cle, interdit)
			}
		}
	}

	// Every sub-resource (src=) must be a file the module itself publishes:
	// relative, therefore same-origin.
	for _, cle := range []string{CleIndexFR, CleIndexEN} {
		for _, src := range valeursAttribut(fichiers[cle], "src") {
			if strings.Contains(src, "://") || strings.HasPrefix(src, "//") {
				t.Errorf("%s loads the external sub-resource %q", cle, src)
			}
		}
	}

	// Every LINK must be either same-origin or the source repository. The
	// list is closed on purpose: a new destination is a decision, not a
	// detail, and it is the one thing a public page cannot take back.
	for _, cle := range []string{CleIndexFR, CleIndexEN} {
		for _, href := range valeursAttribut(fichiers[cle], "href") {
			if !strings.Contains(href, "://") && !strings.HasPrefix(href, "//") {
				continue // relative: same origin, published by this module
			}
			if href == "https://github.com/ceffio-suite/ceffio" {
				continue
			}
			if !strings.HasPrefix(href, "https://"+domaineTest+"/") && !strings.HasPrefix(href, "https://admin."+domaineTest) {
				t.Errorf("%s links to the unexpected destination %q", cle, href)
			}
		}
	}
}

// valeursAttribut returns the values of one attribute in an HTML fragment.
func valeursAttribut(html, attribut string) []string {
	re := regexp.MustCompile(`\b` + attribut + `="([^"]*)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestLesDeuxLanguesOntLaMemeStructure proves the English page is a TRANSLATION
// and not a summary: same sections, same headings, one H1, and the right lang
// attribute.
//
// IT RUNS ON BOTH CONTACT VARIANTS because the contact blocks are the one part
// of the page whose presence depends on data: a link added to the French
// footer and forgotten in the English one would pass every other test in this
// file, and be invisible to the operator reading a single language.
func TestLesDeuxLanguesOntLaMemeStructure(t *testing.T) {
	for _, contact := range []string{"", adresseTest} {
		fichiers, err := Files(domaineTest, contact)
		if err != nil {
			t.Fatalf("Files(%q, %q): %v", domaineTest, contact, err)
		}
		type mesure struct {
			lang                string
			h1, sections, liens int
		}
		mesures := map[string]mesure{}
		for cle, lang := range map[string]string{CleIndexFR: "fr", CleIndexEN: "en"} {
			page := fichiers[cle]
			if !strings.Contains(page, `<html lang="`+lang+`">`) {
				t.Errorf("%s does not declare lang=%q", cle, lang)
			}
			mesures[cle] = mesure{
				lang:     lang,
				h1:       strings.Count(page, "<h1"),
				sections: strings.Count(page, "<section"),
				liens:    len(valeursAttribut(page, "href")),
			}
		}
		fr, en := mesures[CleIndexFR], mesures[CleIndexEN]
		if fr.h1 != 1 || en.h1 != 1 {
			t.Errorf("contact %q: a page must have exactly one H1 (fr: %d, en: %d)", contact, fr.h1, en.h1)
		}
		if fr.sections != en.sections {
			t.Errorf("contact %q: FR has %d sections, EN has %d: the English page is not a translation",
				contact, fr.sections, en.sections)
		}
		if fr.liens != en.liens {
			t.Errorf("contact %q: FR has %d links, EN has %d: the English page is not a translation",
				contact, fr.liens, en.liens)
		}
	}
}

// TestPageSansContactNEnPublieAucune proves that an installation without a
// configured address publishes NONE — not an empty mailto:, not a placeholder:
// the footer says, in the page's language, that the reporting channels are the
// ones in security.txt.
//
// The address is empty by default, so this is what a customer installation
// shows unless the operator decides otherwise.
func TestPageSansContactNEnPublieAucune(t *testing.T) {
	fichiers, err := Files(domaineTest, "")
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	sansAdresse := map[string]string{
		CleIndexFR: "Aucune adresse de contact n'est publiée ici",
		CleIndexEN: "No contact address is published here",
	}
	for _, p := range Paths() {
		contenu := fichiers[p.Cle]
		if strings.Contains(contenu, "mailto:") {
			t.Errorf("%s publishes a mailto: link while no address is configured", p.Cle)
		}
		if strings.Contains(contenu, adresseTest) {
			t.Errorf("%s names an address while no address is configured", p.Cle)
		}
	}
	for cle, phrase := range sansAdresse {
		if !strings.Contains(fichiers[cle], phrase) {
			t.Errorf("%s does not say that no contact address is published", cle)
		}
	}
	assertAucunMarqueur(t, fichiers)
}

// TestPageAvecContactPublieLAdresse proves a configured address reaches the
// page TWICE — the footer link and the readable text — in the page's own
// language, and that the "no address" sentence is gone: publishing both would
// tell a visitor two opposite things.
func TestPageAvecContactPublieLAdresse(t *testing.T) {
	fichiers, err := Files(domaineTest, adresseTest)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	liens := map[string]string{CleIndexFR: "Nous écrire", CleIndexEN: "Email us"}
	sansAdresse := map[string]string{
		CleIndexFR: "Aucune adresse de contact n'est publiée ici",
		CleIndexEN: "No contact address is published here",
	}
	for cle, libelle := range liens {
		page := fichiers[cle]
		// The mailto: appears in the navigation link and in the legal
		// paragraph; the address itself is also printed, so that the link is
		// readable when a client refuses to open it.
		if n := strings.Count(page, `href="mailto:`+adresseTest+`"`); n != 2 {
			t.Errorf("%s has %d mailto: links, expected 2 (footer link and legal paragraph)", cle, n)
		}
		if n := strings.Count(page, ">"+adresseTest+"<"); n != 1 {
			t.Errorf("%s prints the address as text %d times, expected 1", cle, n)
		}
		if !strings.Contains(page, libelle) {
			t.Errorf("%s does not label the contact link %q", cle, libelle)
		}
		if strings.Contains(page, sansAdresse[cle]) {
			t.Errorf("%s still says that no contact address is published", cle)
		}
	}
	assertAucunMarqueur(t, fichiers)
}

// TestContactRefuse proves a value that is not an address is rejected at
// render time instead of becoming a broken link.
//
// The settings form already carries the same pattern, but the renderer is the
// last place before the bytes are public: this test is what makes "the form
// said it was valid" insufficient.
func TestContactRefuse(t *testing.T) {
	for _, contact := range []string{
		"pas une adresse",
		"a@b",
		"a@@b.com",
		"<script>@example.com",
		`"x"@example.com`,
		"equipe@example",
		"équipe@example.com",
		"equipe@exa\nmple.com",
	} {
		if _, err := Files(domaineTest, contact); err == nil {
			t.Errorf("Files accepted %q as a contact address", contact)
		}
	}
	// A value with surrounding spaces is the operator's typo, not a different
	// address: trimming it is part of accepting it.
	if _, err := Files(domaineTest, "  "+adresseTest+"  "); err != nil {
		t.Errorf("Files refused a correctly shaped address surrounded by spaces: %v", err)
	}
}

// assertAucunMarqueur proves no conditional-block marker survived into the
// published pages: a stray "<!-- contact:start -->" is an HTML comment no
// browser shows, so nothing but this test would see it in the cluster.
func assertAucunMarqueur(t *testing.T, fichiers map[string]string) {
	t.Helper()
	for _, p := range Paths() {
		for _, nom := range []string{"contact", "no-contact"} {
			for _, borne := range []string{"start", "end"} {
				if m := marqueur(nom, borne); strings.Contains(fichiers[p.Cle], m) {
					t.Errorf("%s still contains the marker %q", p.Cle, m)
				}
			}
		}
	}
}

// TestPageNePubliePasDUneAutreAdresse proves the page names no IP and no
// address other than the configured one: the installation's host is the only
// host it may name, and it names it through the placeholder.
//
// WHY: a public page that invents a contact address sends vulnerability
// reports to an address nobody reads; the security.txt of the host is the
// channel, and it is linked, not duplicated.
func TestPageNePubliePasDUneAutreAdresse(t *testing.T) {
	ipv4 := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, contact := range []string{"", adresseTest} {
		fichiers, err := Files(domaineTest, contact)
		if err != nil {
			t.Fatalf("Files(%q): %v", contact, err)
		}
		adresses := regexp.MustCompile(`mailto:([^"<]+)`).FindAllStringSubmatch(fichiers[CleIndexFR]+fichiers[CleIndexEN], -1)
		for _, a := range adresses {
			if a[1] != contact {
				t.Errorf("the page publishes the address %q, which is not the configured one (%q)", a[1], contact)
			}
		}
		for _, p := range Paths() {
			if ipv4.MatchString(fichiers[p.Cle]) {
				t.Errorf("%s publishes an IP address: %q", p.Cle, ipv4.FindString(fichiers[p.Cle]))
			}
		}
	}
}
