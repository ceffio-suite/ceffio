package secrets

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ChargerDepuisFichier complète l'environnement avec les valeurs d'un fichier rendu
// par l'injecteur d'OpenBao, SANS écraser ce qui est déjà défini.
//
// POURQUOI CE DÉTOUR EXISTE POUR LA CONSOLE : son image ne contient AUCUN shell —
// c'est un binaire unique, sans /bin/sh —, donc la méthode employée partout ailleurs
// (« set -a; . /secrets/env; set +a ») ne peut pas s'y appliquer. Le programme lit
// donc lui-même le fichier que l'injecteur a rendu. Le format reste le même que pour
// les autres composants : des lignes « export NOM='valeur' », pour qu'il n'y ait
// qu'une seule forme à connaître dans toute la suite.
//
// L'absence du fichier n'est PAS une erreur ici : elle signifie que l'injection n'a
// pas eu lieu. L'appelant décide si les valeurs étaient obligatoires — et il vaut
// mieux qu'il le décide, plutôt qu'un chargement muet qui laisserait tout vide.
func ChargerDepuisFichier(chemin string) error {
	f, err := os.Open(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("lecture de %s : %w", chemin, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ligne := strings.TrimSpace(sc.Text())
		if ligne == "" || !strings.HasPrefix(ligne, "export ") {
			continue
		}
		ligne = strings.TrimPrefix(ligne, "export ")
		nom, valeur, trouve := strings.Cut(ligne, "=")
		if !trouve {
			continue
		}
		nom = strings.TrimSpace(nom)
		// Les valeurs sont écrites entre apostrophes par le gabarit.
		valeur = strings.Trim(strings.TrimSpace(valeur), "'")
		if nom != "" && os.Getenv(nom) == "" {
			os.Setenv(nom, valeur)
		}
	}
	return sc.Err()
}
