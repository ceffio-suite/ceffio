package secrets

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ChargerDepuisFichier completes the environment with the values of a file
// rendered by the OpenBao injector, WITHOUT overwriting what is already set.
//
// WHY THIS DETOUR EXISTS FOR THE CONSOLE: its image contains NO shell —
// it is a single binary, without /bin/sh —, so the method used everywhere
// else ("set -a; . /secrets/env; set +a") cannot apply there. The program
// therefore reads itself the file the injector rendered. The format stays the
// same as for the other components: "export NAME='value'" lines, so there is
// only one shape to know across the whole suite.
//
// The absence of the file is NOT an error here: it means the injection did
// not happen. The caller decides whether the values were mandatory — and it
// is better that it decides, rather than a silent load leaving everything
// empty.
func ChargerDepuisFichier(chemin string) error {
	f, err := os.Open(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", chemin, err)
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
		// Values are written between single quotes by the template.
		valeur = strings.Trim(strings.TrimSpace(valeur), "'")
		if nom != "" && os.Getenv(nom) == "" {
			os.Setenv(nom, valeur)
		}
	}
	return sc.Err()
}
