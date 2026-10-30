// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package docs_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// racine is the repository root, two levels up from internal/docs.
func racine(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	return abs
}

// documents lists every Markdown file a reader is meant to find, starting at the
// README and following the index. A document linked from nowhere is a document
// nobody reads, so the test starts from the two entry points and walks.
func documents(t *testing.T) []string {
	t.Helper()
	root := racine(t)
	var trouves []string
	vus := map[string]bool{}

	var visiter func(rel string)
	visiter = func(rel string) {
		if vus[rel] {
			return
		}
		vus[rel] = true
		if !strings.HasSuffix(rel, ".md") {
			return
		}
		contenu, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return
		}
		trouves = append(trouves, rel)
		for _, cible := range liens(string(contenu)) {
			visiter(filepath.Clean(filepath.Join(filepath.Dir(rel), cible)))
		}
	}

	visiter("README.md")
	visiter("docs/README.md")
	return trouves
}

var motifLien = regexp.MustCompile(`\]\(([^)#\s]+)\)`)

// liens returns the relative targets of a Markdown document, ignoring absolute
// URLs, anchors and anchors-within-a-page.
func liens(s string) []string {
	var sortie []string
	for _, m := range motifLien.FindAllStringSubmatch(s, -1) {
		cible := m[1]
		switch {
		case strings.HasPrefix(cible, "http://"),
			strings.HasPrefix(cible, "https://"),
			strings.HasPrefix(cible, "mailto:"),
			strings.HasPrefix(cible, "#"):
			continue
		}
		if i := strings.IndexAny(cible, "#?"); i >= 0 {
			cible = cible[:i]
		}
		if cible == "" {
			continue
		}
		sortie = append(sortie, cible)
	}
	return sortie
}

// TestAucunLienMort vérifie que chaque lien relatif d'un document atteignable pointe
// vers un fichier qui existe. Un lien mort est la façon la plus banale de rendre une
// documentation inutile : il ne casse aucun build, et il ne se voit qu'au moment où
// quelqu'un a besoin du document.
func TestAucunLienMort(t *testing.T) {
	root := racine(t)
	docs := documents(t)
	if len(docs) < 5 {
		t.Fatalf("only %d documents reached: the walk from README.md is broken", len(docs))
	}

	var morts []string
	for _, d := range docs {
		brut, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			t.Fatalf("reading %s: %v", d, err)
		}
		for _, cible := range liens(string(brut)) {
			p := filepath.Join(root, filepath.Dir(d), cible)
			if _, err := os.Stat(p); err != nil {
				morts = append(morts, d+" -> "+cible)
			}
		}
	}

	if len(morts) > 0 {
		t.Errorf("%d dead link(s) in the documentation:\n  %s",
			len(morts), strings.Join(morts, "\n  "))
	}
}

// TestLesDocumentsDeReferenceSontIndexes vérifie que chaque fichier de docs/ est
// atteignable depuis l'index. Un document orphelin n'est pas lu, et un document
// périmé qu'on ne lit pas est pire qu'aucun document.
func TestLesDocumentsDeReferenceSontIndexes(t *testing.T) {
	root := racine(t)
	atteints := map[string]bool{}
	for _, d := range documents(t) {
		atteints[filepath.ToSlash(d)] = true
	}

	surDisque, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatalf("listing docs/: %v", err)
	}

	var orphelins []string
	for _, f := range surDisque {
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		if !atteints[rel] {
			orphelins = append(orphelins, rel)
		}
	}

	if len(orphelins) > 0 {
		t.Errorf("%d document(s) in docs/ reachable from no index:\n  %s\n"+
			"Add a row to docs/README.md, or move the file to docs/history/ if it is a\n"+
			"working note that no longer describes the code.",
			len(orphelins), strings.Join(orphelins, "\n  "))
	}
}

// TestLesNotesHistoriquesSeDeclarent vérifie que chaque note de docs/history/
// porte son avertissement. Une note de travail y entre parce qu'elle ne décrit plus
// le code ; sans l'en-tête, un lecteur la prend pour la documentation courante.
func TestLesNotesHistoriquesSeDeclarent(t *testing.T) {
	root := racine(t)
	notes, err := filepath.Glob(filepath.Join(root, "docs", "history", "*.md"))
	if err != nil {
		t.Fatalf("listing docs/history/: %v", err)
	}
	if len(notes) == 0 {
		t.Skip("no historical notes")
	}

	for _, n := range notes {
		brut, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("reading %s: %v", n, err)
		}
		contenu := string(brut)
		if !strings.Contains(contenu, "Does not describe the current code") {
			t.Errorf("%s carries no historical header: a working note that still "+
				"speaks of the old stack will be read as current", n)
		}
	}
}

// TestLeReadmeNeVantePasCeQuiNExistePas vérifie les affirmations que la
// documentation a déjà eues fausses, et qui sont vérifiables par lecture du code.
func TestLeReadmeNeVantePasCeQuiNExistePas(t *testing.T) {
	root := racine(t)
	brut, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(brut)

	// (1) Le README a déjà annoncé « aucune dépendance à un service tiers », alors
	// que l'adresse publique est découverte via stun.l.google.com. Une promesse
	// fausse sur un point vérifiable décrédibilise le reste du document.
	if strings.Contains(readme, "no dependency on a third-party service") {
		t.Error("README.md claims no dependency on a third-party service, " +
			"but the public address is discovered through stun.l.google.com")
	}

	// (2) Le README a déjà dit que plus aucun identifiant d'application n'existait
	// comme Secret Kubernetes. Quatre le sont, depuis le coffre.
	if regexp.MustCompile(`no application credential exists as a Kubernetes Secret`).MatchString(readme) {
		t.Error("README.md claims no application credential exists as a Kubernetes " +
			"Secret; four are written from the vault (see docs/secrets.md)")
	}

	// (3) K3s est installé par internal/cluster, pas par internal/platform.
	if regexp.MustCompile(`\|\s*Platform\s*\|\s*` + "`internal/platform`" + `\s*\|\s*K3s`).MatchString(readme) {
		t.Error("README.md credits internal/platform with installing K3s; " +
			"that is internal/cluster — internal/platform applies Helm releases")
	}

	// (4) Les ports de relais de coturn sont 49152-49200. 20000-20100 est la plage
	// de Janus. Annoncer la mauvaise plage fait ouvrir la mauvaise règle de pare-feu.
	// On lit le tableau lui-même : une ligne dont la première cellule est une plage
	// et dont la dernière missionne coturn. Une regex sur des mots voisins ne
	// prouve rien — elle a déjà accepté la mauvaise valeur en silence.
	ligneCoturn := regexp.MustCompile("(?m)^\\|\\s*`([0-9]+-[0-9]+)`\\s*\\|[^|]*\\|[^|]*coturn[^|]*\\|")
	for _, m := range ligneCoturn.FindAllStringSubmatch(readme, -1) {
		if m[1] != "49152-49200" {
			t.Errorf("README.md gives %s as coturn's relay range; it is 49152-49200 "+
				"(20000-20100 is Janus). A firewall rule opening the wrong range "+
				"lets the allocation succeed and the media never pass.", m[1])
		}
	}
	if !strings.Contains(readme, "49152-49200") {
		t.Error("README.md no longer states coturn's relay range at all")
	}
}

// TestLaPolitiqueDeSecuriteEstAtteignable: SECURITY.md must be reached from the
// README's walk, so that its OWN links are checked by TestAucunLienMort.
//
// WHY AN EXPLICIT TEST: the walk follows links, so removing one line from the
// README would silently drop the whole policy from the coverage — no test would
// fail, and a dead link inside the policy would only be found by the person who
// needed it.
func TestLaPolitiqueDeSecuriteEstAtteignable(t *testing.T) {
	root := racine(t)
	if _, err := os.Stat(filepath.Join(root, "SECURITY.md")); err != nil {
		t.Fatalf("SECURITY.md is missing at the root: %v", err)
	}
	for _, d := range documents(t) {
		if d == "SECURITY.md" {
			return
		}
	}
	t.Error("SECURITY.md is not reachable from README.md: link it, so its links are checked too")
}
