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

// TestFilesRendChaqueFichier proves the rendered page is COMPLETE and
// HOST-INDEPENDENT: every declared file has a key, every key has content, and
// no placeholder survives.
//
// WHY "no placeholder survives" is a hard failure: a literal {{DOMAIN}} on the
// public page is visible to every visitor and in every crawler, and nothing
// but this test would notice it.
func TestFilesRendChaqueFichier(t *testing.T) {
	fichiers, err := Files(domaineTest)
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
		if _, err := Files(domaine); err == nil {
			t.Errorf("Files(%q) accepted a host that is not a bare host name", domaine)
		}
	}
}

// TestSitemap proves the sitemap lists exactly the two pages the module
// publishes, absolute and without a trailing filename.
func TestSitemap(t *testing.T) {
	fichiers, err := Files(domaineTest)
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
	fichiers, err := Files(domaineTest)
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
	fichiers, err := Files(domaineTest)
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
func TestLesDeuxLanguesOntLaMemeStructure(t *testing.T) {
	fichiers, err := Files(domaineTest)
	if err != nil {
		t.Fatalf("Files: %v", err)
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
		t.Errorf("a page must have exactly one H1 (fr: %d, en: %d)", fr.h1, en.h1)
	}
	if fr.sections != en.sections {
		t.Errorf("FR has %d sections, EN has %d: the English page is not a translation", fr.sections, en.sections)
	}
	if fr.liens != en.liens {
		t.Errorf("FR has %d links, EN has %d: the English page is not a translation", fr.liens, en.liens)
	}
}

// TestPageNePublieNiContactNiAdresse proves the page publishes no contact
// address, no IP and no domain of its own: the installation's host is the only
// host it may name, and it names it through the placeholder.
//
// WHY: a public page that invents a contact address sends vulnerability
// reports to an address nobody reads; the security.txt of the host is the
// channel, and it is linked, not duplicated.
func TestPageNePublieNiContactNiAdresse(t *testing.T) {
	fichiers, err := Files(domaineTest)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	ipv4 := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, p := range Paths() {
		contenu := fichiers[p.Cle]
		if strings.Contains(contenu, "mailto:") {
			t.Errorf("%s publishes a mailto: link", p.Cle)
		}
		if ipv4.MatchString(contenu) {
			t.Errorf("%s publishes an IP address: %q", p.Cle, ipv4.FindString(contenu))
		}
	}
}
