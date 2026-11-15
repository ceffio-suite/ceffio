// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package website holds the PUBLIC LANDING PAGE of an installation: the
// static files themselves, and the substitution that makes them
// host-independent.
//
// WHY THE CONTENT LIVES HERE AND NOT IN THE MODULE PACKAGE: the page is
// content (HTML, CSS, a logo, robots.txt), not Kubernetes plumbing. Its own
// package lets the page be edited — and its invariants tested — without
// reading a line of deployment code, and the files are EMBEDDED in the
// binary so that publishing the page never needs the network: an
// installation with no outbound access, or behind an air-gapped mirror, gets
// exactly the same page as any other.
//
// WHY PLACEHOLDERS: one binary serves every installation, and the repository
// forbids committing a real host name — a committed domain becomes a
// hard-coded, WRONG one on somebody else's server, and there is no way to
// tell a reader that it is only an example. The page is therefore written
// once with {{DOMAIN}} / {{ADMIN_URL}} / {{SECURITY_URL}}, and Files resolves
// them from the installation's own host when the module is installed.
//
// {{CONTACT_EMAIL}} IS THE ODD ONE OUT: an address is not a function of the
// host, and the editor's address is not the operator's. It is therefore never
// derived and never committed — it comes from the module's settings, it is
// empty by default, and an empty value REMOVES the address from the page
// (marker-delimited blocks below) instead of publishing an empty mailto:.
package website

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// The embed lists the page files and NOTHING else: a file added to the
// directory without being declared here fails TestAucunFichierNonDeclare,
// which forces the decision of what gets published to stay explicit.
//
//go:embed site/index.html site/en/index.html site/style.css site/logo.svg site/robots.txt
var fichiersSite embed.FS

// Placeholders resolved by Files. They are exported so that the module, the
// tests and any documentation talk about the SAME three strings.
const (
	PlaceholderDomain      = "{{DOMAIN}}"
	PlaceholderAdminURL    = "{{ADMIN_URL}}"
	PlaceholderSecurityURL = "{{SECURITY_URL}}"
	PlaceholderContact     = "{{CONTACT_EMAIL}}"
)

// MotifAdresse is the shape a published contact address must have: one local
// part, one dotted host, no space, no quote, no markup.
//
// It is exported so that the module declares the SAME pattern in its settings
// form: the operator's input is checked by the form, by module.Validate and
// again by Files, and the three cannot disagree. It is deliberately not RFC
// 5322 — the address ends up in a mailto: of a static page, and a permissive
// pattern would accept "a@b", which no mail client can send to.
const MotifAdresse = `^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`

var motifAdresse = regexp.MustCompile(MotifAdresse)

// AdresseValide reports whether s could be published as a mailto: target.
func AdresseValide(s string) bool { return motifAdresse.MatchString(strings.TrimSpace(s)) }

// ConfigMap keys the page is stored under.
//
// WHY THE KEYS ARE FLAT: a ConfigMap key cannot contain "/", but the volume
// projection can — "en/index.html" is a PATH, "index-en.html" is the KEY that
// carries it. The two are declared together in the table below so that a key
// and its path can never drift apart.
const (
	CleIndexFR = "index.html"
	CleIndexEN = "index-en.html"
	CleStyle   = "style.css"
	CleLogo    = "logo.svg"
	CleRobots  = "robots.txt"
	CleSitemap = "sitemap.xml"
)

// fichier is one page file: where it comes from in the embedded tree, the
// ConfigMap key it is stored under, and the path it must appear at inside the
// container.
type fichier struct {
	cle, source, chemin string
}

// fichiers is the COMPLETE list of what gets published. Adding a file to
// site/ without adding it here is a test failure on purpose: the page is
// public, so what it exposes is a decision, never a side effect.
var fichiers = []fichier{
	{cle: CleIndexFR, source: "site/index.html", chemin: "index.html"},
	{cle: CleIndexEN, source: "site/en/index.html", chemin: "en/index.html"},
	{cle: CleStyle, source: "site/style.css", chemin: "style.css"},
	{cle: CleLogo, source: "site/logo.svg", chemin: "logo.svg"},
	{cle: CleRobots, source: "site/robots.txt", chemin: "robots.txt"},
}

// Item is one projected file: the ConfigMap key to read, and the path to
// write it at inside the container.
type Item struct {
	Cle, Chemin string
}

// Paths returns the projection table, ordered by key so that the generated
// manifests and their tests are stable.
//
// The sitemap is included: it is generated rather than written by hand (see
// Files) but it is a published file like the others.
func Paths() []Item {
	out := make([]Item, 0, len(fichiers)+1)
	for _, f := range fichiers {
		out = append(out, Item{Cle: f.cle, Chemin: f.chemin})
	}
	out = append(out, Item{Cle: CleSitemap, Chemin: "sitemap.xml"})
	sort.Slice(out, func(i, j int) bool { return out[i].Cle < out[j].Cle })
	return out
}

// Files renders the page for ONE installation and returns it ready to be
// stored in a ConfigMap: key → content, placeholders resolved.
//
// The domain is the installation's host — the bare name, no scheme, exactly
// what module.Env.Domain carries. Everything derived from it is derived
// HERE, once: the console address and the security.txt URL cannot disagree
// with the host the page is served on, and the content files never have to
// know how an installation names its console.
//
// The contact address is NOT derived: it is the operator's own address, read
// from the module's settings, and empty by default. An empty value publishes
// the page WITHOUT any address or mailto: — the page then says, in the
// operator's language, that the reporting channels are the ones in
// security.txt. A non-empty value is validated here even though the settings
// form already checks it: this is the last place before the bytes are public,
// and a value that slipped past a frontend must not become a broken link.
func Files(domain, contact string) (map[string]string, error) {
	domaine := strings.TrimSpace(domain)
	if domaine == "" {
		return nil, fmt.Errorf("website: empty domain: the page cannot be rendered without the installation's host")
	}
	// A host is not a URL: a scheme smuggled in here would produce
	// "https://https://host" in every canonical link, which is silent in the
	// browser and wrong in every crawler.
	if strings.Contains(domaine, "://") || strings.ContainsAny(domaine, " /") {
		return nil, fmt.Errorf("website: %q is not a bare host name (no scheme, no path): the page is rendered from module.Env.Domain", domaine)
	}
	adresse := strings.TrimSpace(contact)
	if adresse != "" && !AdresseValide(adresse) {
		return nil, fmt.Errorf("website: %q is not a usable contact address (expected name@host.tld)", adresse)
	}

	rempl := strings.NewReplacer(
		PlaceholderDomain, domaine,
		PlaceholderAdminURL, "https://admin."+domaine,
		PlaceholderSecurityURL, "https://"+domaine+"/.well-known/security.txt",
		PlaceholderContact, adresse,
	)

	out := make(map[string]string, len(fichiers)+1)
	for _, f := range fichiers {
		brut, err := fichiersSite.ReadFile(f.source)
		if err != nil {
			return nil, fmt.Errorf("website: reading embedded %s: %w", f.source, err)
		}
		page := string(brut)
		// Only the two HTML pages carry the contact blocks; robots.txt and the
		// binary files have no footer and are left untouched. EITHER marker
		// brings the page here: a page that declared only one variant would
		// otherwise be published raw, markers included, and rendreContact is
		// what refuses that.
		if strings.Contains(page, marqueur("contact", "start")) || strings.Contains(page, marqueur("no-contact", "start")) {
			page, err = rendreContact(page, adresse)
			if err != nil {
				return nil, fmt.Errorf("website: %s: %w", f.source, err)
			}
		}
		out[f.cle] = rempl.Replace(page)
	}
	out[CleSitemap] = sitemap(domaine)

	// A placeholder that survives the substitution means the page publishes
	// a literal "{{DOMAIN}}" to visitors — visible, embarrassing, and only
	// noticed by the first person who opens the site. Fail the install
	// instead.
	for cle, contenu := range out {
		if i := strings.Index(contenu, "{{"); i >= 0 {
			return nil, fmt.Errorf("website: %s still contains an unresolved placeholder: %q", cle, extrait(contenu, i))
		}
	}
	return out, nil
}

// sitemap is generated rather than embedded: it is two URLs derived from the
// host, and a hand-written copy would be one more file to remember to edit
// when a page is added.
func sitemap(domaine string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://` + domaine + `/</loc>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://` + domaine + `/en/</loc>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
`
}

// marqueur builds the HTML comment that delimits a conditional block.
func marqueur(nom, borne string) string { return "<!-- " + nom + ":" + borne + " -->" }

// rendreContact publishes exactly ONE of the two contact variants: the one that
// carries the address, or the one that says there is none.
//
// WHY THEY LIVE IN THE SAME FILE: two nearly identical pages — one with a
// footer link, one without — would drift on the first edit of either. The
// markers make the decision a single boolean, and the tests still see one
// honest page per case.
func rendreContact(contenu, adresse string) (string, error) {
	avec, err := garderBloc(contenu, "contact", adresse != "")
	if err != nil {
		return "", err
	}
	return garderBloc(avec, "no-contact", adresse == "")
}

// garderBloc keeps (true) or removes (false) every block delimited by
// "<!-- nom:start -->" and "<!-- nom:end -->", stripping the markers either
// way. Each marker must sit ALONE on its line, so that removing a block also
// removes its indentation and cannot leave a blank, indented line behind.
//
// A BLOCK MAY APPEAR SEVERAL TIMES (the footer link and the legal paragraph
// are two variants of the same decision), and all its occurrences follow the
// same fate: a page that keeps one and drops the other would be exactly the
// contradiction the two blocks exist to prevent.
func garderBloc(contenu, nom string, garder bool) (string, error) {
	debut, fin := marqueur(nom, "start"), marqueur(nom, "end")
	nd, nf := strings.Count(contenu, debut), strings.Count(contenu, fin)
	if nd == 0 || nd != nf {
		return "", fmt.Errorf("block %q must appear at least once with balanced markers (found %d start and %d end markers)", nom, nd, nf)
	}
	ligne := func(m string) *regexp.Regexp {
		return regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(m) + `[ \t]*\n`)
	}
	if garder {
		return ligne(fin).ReplaceAllString(ligne(debut).ReplaceAllString(contenu, ""), ""), nil
	}
	// (?ms): ^ is a line start and . spans lines. `.*?` stops at the FIRST end
	// marker, which is the one belonging to this start marker: blocks do not
	// interleave, and the count check above makes the loop finite.
	entier := regexp.MustCompile(`(?ms)^[ \t]*` + regexp.QuoteMeta(debut) + `[ \t]*\n.*?^[ \t]*` + regexp.QuoteMeta(fin) + `[ \t]*\n`)
	for i := 0; i < nd; i++ {
		loc := entier.FindStringIndex(contenu)
		if loc == nil {
			return "", fmt.Errorf("block %q: the two markers must each sit alone on their own line", nom)
		}
		contenu = contenu[:loc[0]] + contenu[loc[1]:]
	}
	return contenu, nil
}

// extrait returns a short window around an offset, for error messages that
// point at the offending text instead of at the whole file.
func extrait(contenu string, i int) string {
	debut := i - 40
	if debut < 0 {
		debut = 0
	}
	fin := i + 40
	if fin > len(contenu) {
		fin = len(contenu)
	}
	return strings.TrimSpace(contenu[debut:fin])
}

// fichiersEmbedes lists the embedded tree; the tests use it to prove that
// nothing is published by accident.
func fichiersEmbedes() ([]string, error) {
	var noms []string
	err := fs.WalkDir(fichiersSite, "site", func(chemin string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		noms = append(noms, chemin)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(noms)
	return noms, nil
}
