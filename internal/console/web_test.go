// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// This file checks that every button of the console can actually do something.
//
// # THE BUG IT PREVENTS
//
// The whole page lives inside an IIFE. A `function` declaration is therefore
// local to it, while an `onclick="..."` attribute runs in the GLOBAL scope — so
// a handler that is not also assigned to `window` cannot be called.
//
// Measured on the live console:
//
//	typeof window.transcriptionAction  → "undefined"
//	the button: enabled, visible, onclick="transcriptionAction('install')"
//
// Clicking did NOTHING: no error, no request, no message. Two buttons were in
// that state — "Install live transcription" and "Deploy it now" — while the
// thirteen other handlers worked, because they had been exposed. Nothing in the
// build, the tests or the logs could see it: the page is valid HTML, the
// function exists, and the browser reports no error.
//
// A SILENT FAILURE IS THE POINT. A handler that threw would be found in a
// minute. One that does nothing reads as a slow server or a permission problem,
// and sends the investigation to the wrong place — which is exactly what
// happened.
//
// THE CHECK IS MECHANICAL: every function named in an onclick must also appear
// as a `window.<name> =`. It does not care which functions exist, only that the
// page cannot ship a button wired to nothing.
package console

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	reOnclick = regexp.MustCompile(`onclick="([a-zA-Z_][a-zA-Z0-9_]*)\(`)
	reWindow  = regexp.MustCompile(`window\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=`)
)

func TestChaqueBoutonAppelleUneFonctionExposee(t *testing.T) {
	source := lireIndex(t)

	appelees := map[string]bool{}
	for _, m := range reOnclick.FindAllStringSubmatch(source, -1) {
		appelees[m[1]] = true
	}
	exposees := map[string]bool{}
	for _, m := range reWindow.FindAllStringSubmatch(source, -1) {
		exposees[m[1]] = true
	}

	if len(appelees) == 0 {
		t.Fatal("aucun onclick trouvé — le fichier a-t-il changé de forme ?")
	}

	var manquantes []string
	for nom := range appelees {
		if !exposees[nom] {
			manquantes = append(manquantes, nom)
		}
	}
	sort.Strings(manquantes)

	if len(manquantes) > 0 {
		t.Errorf("ces fonctions sont appelées par un bouton mais absentes de "+
			"`window` : %s\n\nLa page est dans une IIFE, donc un `onclick` — qui "+
			"s'exécute dans le scope GLOBAL — ne peut pas les voir. Le clic ne "+
			"fait RIEN : pas d'erreur, pas de requête, pas de message.\n"+
			"Ajouter : window.<nom> = <nom>; à la fin du script.",
			strings.Join(manquantes, ", "))
	}
}

// TestLesFonctionsExposeesExistent : l'inverse. Exposer un nom qui n'existe pas
// donnerait `undefined` sur window, et le bouton échouerait avec « is not a
// function » — bruyant, mais tout aussi cassé.
func TestLesFonctionsExposeesExistent(t *testing.T) {
	source := lireIndex(t)

	exposees := map[string]bool{}
	for _, m := range reWindow.FindAllStringSubmatch(source, -1) {
		exposees[m[1]] = true
	}
	// Les affectations de variables (window.refresh = async () => {}) n'ont pas
	// de déclaration `function` : on ne vérifie que celles qui prétendent
	// désigner une fonction nommée.
	declarees := map[string]bool{}
	reFunc := regexp.MustCompile(`(?:async\s+)?function\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
	for _, m := range reFunc.FindAllStringSubmatch(source, -1) {
		declarees[m[1]] = true
	}

	var fantomes []string
	for nom := range exposees {
		// Une lambda affectée directement n'est pas dans `declarees` : on la
		// reconnaît à sa forme, avec OU SANS parenthèses autour du paramètre.
		// `window.resetPwd = async id => {` avait été manqué par la première
		// version de ce test, qui ne cherchait que `async (` — un faux positif
		// apprend à ignorer le test, exactement ce qu'il faut éviter.
		direct := regexp.MustCompile(
			`window\.` + regexp.QuoteMeta(nom) + `\s*=\s*(async\s*)?(\(|function|[a-zA-Z_]+\s*=>|\(\s*\)\s*=>)`).
			MatchString(source)
		if !declarees[nom] && !direct {
			fantomes = append(fantomes, nom)
		}
	}
	sort.Strings(fantomes)
	if len(fantomes) > 0 {
		t.Errorf("ces noms sont exposés sur `window` mais ne correspondent à "+
			"aucune fonction : %s — le bouton échouerait sur « is not a function »",
			strings.Join(fantomes, ", "))
	}
}

func lireIndex(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("web", "index.html"))
	if err != nil {
		t.Fatalf("lecture de web/index.html : %v", err)
	}
	return string(b)
}
