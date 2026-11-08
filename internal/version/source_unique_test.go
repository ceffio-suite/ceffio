// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package version

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// littéralImage reconnaît une image de conteneur écrite en dur, sous les DEUX
// formes que ce dépôt a produites : une affectation Go, et une ligne YAML dans
// un manifeste construit par fmt.Sprintf. La seconde a échappé à la première
// version de ce test — oauth2-proxy est resté en v7.15.5 après un upgrade
// complet, parce que le module écrivait l'image en clair dans son Deployment.
var littéralImage = regexp.MustCompile(`(?m)^\s*(\w+[Ii]mage\s*=\s*"|image:\s*)[a-z0-9.-]+\.[a-z]+/[^"\s]*`)

// imageYAML attrape la forme YAML quand l'image est sur la même ligne que la clé.
var imageYAML = regexp.MustCompile(`(?m)^\s*image:\s*\S+`)

// TestAucuneImageEnDurHorsDuRegistre: le registre se dit « source unique », et
// dix modules gardaient pourtant leur propre constante.
//
// CE QUE ÇA A COÛTÉ, ET POURQUOI CE TEST EXISTE : `ceffio upgrade` comparait le
// registre, appliquait les constantes des modules, et terminait sur
// « keycloak : still on 26.7.3 (target 26.8.2) » — neuf fois. Le registre
// décrivait des versions que le déploiement n'utilisait pas.
//
// LA RÈGLE EST MÉCANIQUE : une image se lit avec version.Image("<composant>").
// Une chaîne littérale dans un autre paquet est une duplication qui dérivera.
func TestAucuneImageEnDurHorsDuRegistre(t *testing.T) {
	racine := filepath.Join("..")
	var coupables []string
	err := filepath.Walk(racine, func(chemin string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Les caches du dépôt (gomodcache, gopath) ne sont pas du code.
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		if strings.Contains(chemin, filepath.Join("internal", "version")) {
			return nil
		}
		brut, err := os.ReadFile(chemin)
		if err != nil {
			return err
		}
		for _, ligne := range littéralImage.FindAllString(string(brut), -1) {
			coupables = append(coupables, chemin+" : "+strings.TrimSpace(ligne))
		}
		for _, ligne := range imageYAML.FindAllString(string(brut), -1) {
			// Une image interpolée (`image: %[12]s`) n'est pas un littéral.
			if strings.Contains(ligne, "%") {
				continue
			}
			coupables = append(coupables, chemin+" : "+strings.TrimSpace(ligne))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parcours des sources : %v", err)
	}
	if len(coupables) > 0 {
		t.Fatalf(`une image est écrite en dur hors du registre :
  %s

LIRE L'IMAGE DEPUIS LE REGISTRE : var image = version.Image("<composant>")
Sinon le registre avance et le déploiement reste sur l'ancienne version — le
défaut que ce test empêche de réintroduire.`, strings.Join(coupables, "\n  "))
	}
}
