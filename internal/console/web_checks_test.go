// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// Tests de la partie « checks » de la page.
//
// POURQUOI ILS EXISTENT
//
// Le contrat module.Checker définit quatre niveaux, et c'est TOUT le
// vocabulaire : ok, warning, blocking, not_applicable. Si la page en oublie un
// — le plus facile étant not_applicable, qui ne se voit pas sur une capture
// d'écran quand tout va bien — l'opérateur lit une liste incomplète sans le
// savoir : un check « non applicable » disparaît, et avec lui la raison pour
// laquelle le serveur de mail ne reçoit rien. Une absence ne se remarque pas.
//
// CE QUE CHAQUE TEST REFUSE
//
//   - TestLaPageConnaitLesQuatreNiveaux : un niveau sans symbole ni badge, qui
//     s'afficherait comme une ligne vide ou avec un « ? ».
//   - TestLeFixEstUnBlocCopiable : le Fix fondu dans le Detail. Le Detail est ce
//     qui a été MESURÉ, le Fix ce que l'opérateur FAIT ; les mélanger fait
//     coller l'observation dans une zone DNS.
//   - TestLesChecksNeSontDemandesQueSiLeModuleEnDeclare : un appel aux checks
//     pour chaque module, y compris ceux qui n'en déclarent pas — un aller
//     réseau par module à chaque ouverture de page, et une erreur affichée pour
//     des modules qui n'ont rien à vérifier.

import (
	"regexp"
	"strings"
	"testing"
)

// blocConst isole la déclaration d'une constante JS de la page, pour que les
// assertions ne puissent pas être satisfaites par une autre partie du fichier.
func blocConst(t *testing.T, source, nom string) string {
	t.Helper()
	motif := regexp.MustCompile(`const ` + regexp.QuoteMeta(nom) + `\s*=\s*\{[^}]*\};`)
	m := motif.FindString(source)
	if m == "" {
		t.Fatalf("la page ne déclare plus %s : les niveaux de check n'ont plus de "+
			"rendu associé", nom)
	}
	return m
}

// TestLaPageConnaitLesQuatreNiveaux : chaque niveau du contrat a un symbole et
// une classe de badge.
func TestLaPageConnaitLesQuatreNiveaux(t *testing.T) {
	page := lireIndex(t)

	symboles := blocConst(t, page, "CHECK_SYMBOL")
	badges := blocConst(t, page, "CHECK_BADGE")

	for _, niveau := range []string{"ok", "warning", "blocking", "not_applicable"} {
		if !strings.Contains(symboles, niveau+":") {
			t.Errorf("CHECK_SYMBOL ne connaît pas le niveau %q : la ligne "+
				"s'afficherait sans marque, et un check non applicable "+
				"disparaîtrait du seul endroit qui devait le montrer", niveau)
		}
		if !strings.Contains(badges, niveau+":") {
			t.Errorf("CHECK_BADGE ne connaît pas le niveau %q : le badge "+
				"tomberait sur la classe par défaut et la couleur mentirait "+
				"sur la gravité", niveau)
		}
	}
}

// TestLeFixEstUnBlocCopiable : le Fix a son propre bloc et son bouton de copie.
func TestLeFixEstUnBlocCopiable(t *testing.T) {
	page := lireIndex(t)

	if !strings.Contains(page, `class="check-fix`) {
		t.Error("la page ne rend plus le Fix dans un bloc propre : il est " +
			"fondu dans le Detail, et c'est le paragraphe entier qui sera " +
			"collé dans une zone DNS")
	}
	if !strings.Contains(page, `data-fix="${esc(c.fix)}"`) {
		t.Error("le bouton de copie ne porte plus le Fix : il copierait le " +
			"texte du bouton, ou rien")
	}
	// Le bouton est un onclick dans une IIFE : sans assignment sur window, le
	// clic ne fait RIEN (voir web_test.go, qui vérifie la règle pour toute la
	// page ; ce test-ci vérifie que l'action existe encore).
	if !strings.Contains(page, "window.copyCheckFix = copyCheckFix") {
		t.Error("copyCheckFix n'est plus exposé sur window : le bouton " +
			"« Copy fix » ne ferait rien, sans erreur ni requête")
	}
}

// TestLesChecksNeSontDemandesQueSiLeModuleEnDeclare : l'appel est conditionné
// au drapeau que l'API renvoie.
func TestLesChecksNeSontDemandesQueSiLeModuleEnDeclare(t *testing.T) {
	page := lireIndex(t)

	if !strings.Contains(page, "if (!m.checkable) continue;") {
		t.Error("loadModuleChecks n'ignore plus les modules sans check : la " +
			"page demanderait leurs checks à chaque ouverture, pour des " +
			"modules qui n'ont rien à vérifier")
	}
	if !strings.Contains(page, "/api/modules/' + m.id + '/checks") {
		t.Error("la page ne construit plus l'URL des checks depuis l'id du " +
			"module : elle a peut-être un nom de module en dur, ce que " +
			"TestLaPageNAppelleAucunModuleEnDur interdit")
	}
}
