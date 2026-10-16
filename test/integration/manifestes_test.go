// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// This file checks the manifests AS TEXT, across the four modules that carry a
// StorageClass. It exists because the compiler cannot see this class of bug.
//
// Three times in a row, a manifest went to a cluster broken while `go build`,
// `go vet`, `gofmt` and `go test` were all green:
//
//  1. Nextcloud  — `namespace: 6379`, the Valkey port written where the
//     namespace belonged, because one verb had been added to a nine-verb
//     Sprintf without numbering the others. Go shifts every verb that follows
//     the first indexed one when %[n]s and %s are mixed, silently.
//
//  2. Stalwart   — the agent annotations block (a multi-line YAML string)
//     landed in place of the StorageClass, because %[4]s pointed at
//     `annotations` while the class sat at position 5. The error was
//     « yaml: line 8: mapping values are not allowed in this context »,
//     pointing at the PVC, nowhere near the cause.
//
// Both are the SAME root error — an index that does not name what the author
// thought it named — and both are invisible to every tool in the Go toolchain.
// The only reliable check is to produce the text and look at it.
//
// HOW TO READ A FAILURE HERE: every assertion below is about where a value
// LANDS, not about the code that puts it there. A test that fails by naming
// the wrong line in the produced YAML has done its job.
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Les modules qui portent une StorageClass, avec la chaine qu'on attend dans
// le manifeste genere.
var modules = []struct {
	paquet string
	nom    string
}{
	{"internal/files", "files"},
	{"internal/mail", "mail"},
	{"internal/office", "office"},
	{"internal/data", "data"},
}

// TestAucunManifesteNADeFormatNonResolu balaie le source de chaque module et
// refuse ce que Go ecrit quand un verbe ne peut pas etre resolu.
//
// « %!s(MISSING) » et « %![3]s(EXTRA ...) » sont injectes DANS la sortie : ils
// arrivent donc tels quels dans le YAML, et kubectl echoue plus loin, sur une
// ligne sans rapport. Aucun de ces marqueurs ne peut rester.
func TestAucunManifesteNADeFormatNonResolu(t *testing.T) {
	for _, m := range modules {
		t.Run(m.nom, func(t *testing.T) {
			// On compile le paquet de test en isolant le manifeste, via go test
			// sur le paquet lui-meme quand il expose le texte.
			source := lireSource(t, m.paquet, m.nom)
			if strings.Contains(source, "%!") {
				t.Errorf("%s: un format non resolu est present dans le source", m.nom)
			}
		})
	}
}

// TestStorageClassNumeroteeEtNommee verifie le point precis qui a casse deux
// fois : l'index pose devant storageClassName doit nommer la classe, pas autre
// chose.
//
// On ne peut pas le savoir en compilant. On le sait en comparant l'index a la
// position de l'argument dans la liste — exactement l'erreur humaine commise.
func TestStorageClassNumeroteeEtNommee(t *testing.T) {
	for _, m := range modules {
		t.Run(m.nom, func(t *testing.T) {
			source := lireSource(t, m.paquet, m.nom)

			idx := indexStorageClass(t, source)
			args := argumentsSprintf(t, source)

			if idx < 1 || idx > len(args) {
				t.Fatalf("%s: index %d hors de la liste des %d arguments",
					m.nom, idx, len(args))
			}
			arg := strings.TrimSpace(args[idx-1])

			// L'argument doit designer la classe de stockage. Selon les
			// modules c'est storage.Classe() ou un parametre nomme classe.
			if !estArgumentDeClasse(arg) {
				t.Errorf("%s: storageClassName porte l'index %d, qui designe %q "+
					"et non la StorageClass — le manifeste recevra un bloc "+
					"annotations ou un port a la place du nom de classe",
					m.nom, idx, arg)
			}
		})
	}
}

func estArgumentDeClasse(arg string) bool {
	return strings.Contains(arg, "storage.Classe()") ||
		arg == "classe" || strings.HasSuffix(arg, " classe")
}

// indexStorageClass lit l'index ecrit devant storageClassName.
func indexStorageClass(t *testing.T, source string) int {
	t.Helper()
	for _, ligne := range strings.Split(source, "\n") {
		l := strings.TrimSpace(ligne)
		if !strings.Contains(l, "storageClassName:") && !strings.Contains(l, "storageClass:") {
			continue
		}
		i := strings.Index(l, "%[")
		if i < 0 {
			continue
		}
		fin := strings.Index(l[i:], "]s")
		if fin < 0 {
			continue
		}
		n := 0
		for _, c := range l[i+2 : i+fin] {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}

// argumentsSprintf lit la liste passee au fmt.Sprintf DONT LE MANIFESTE PORTE
// LA STORAGECLASS.
//
// TROIS PIEGES, tous rencontres en ecrivant ce test :
//
//  1. Le fichier contient plusieurs fmt.Sprintf. Prendre le premier ramene la
//     liste d'arguments d'un autre manifeste (files.go en a un des la ligne
//     102), et l'index teste ne veut plus rien dire.
//  2. Un « `, » apparait dans les commentaires : « such as `deploy/nextcloud`,
//     ... ». Partir du haut du fichier lit un commentaire.
//  3. La fonction fmt.Sprintf qui porte le manifeste est celle dont le bloc se
//     termine par storageClassName — c'est le seul ancrage fiable, parce que
//     c'est precisement ce qu'on cherche a verifier.
//
// Un faux positif coute autant qu'un faux negatif : il apprend a ignorer le
// test. D'ou l'ancrage sur le contenu plutot que sur la position.
func argumentsSprintf(t *testing.T, source string) []string {
	t.Helper()
	lignes := strings.Split(source, "\n")

	// On localise la ligne qui declare la StorageClass, puis on remonte au
	// fmt.Sprintf qui ouvre ce bloc.
	ligneClasse := -1
	for i, l := range lignes {
		if strings.Contains(l, "storageClassName:") || strings.Contains(l, "storageClass:") {
			ligneClasse = i
			break
		}
	}
	if ligneClasse < 0 {
		return nil
	}

	debut := 0
	for i := ligneClasse; i >= 0; i-- {
		if strings.Contains(lignes[i], "fmt.Sprintf(") {
			debut = i
			break
		}
	}

	for i := debut; i < len(lignes); i++ {
		ligne := lignes[i]
		if !strings.Contains(ligne, "`, ") {
			continue
		}
		// La liste peut deborder sur la ligne suivante.
		bloc := ligne[strings.Index(ligne, "`, ")+3:]
		if i+1 < len(lignes) && !strings.HasSuffix(strings.TrimSpace(bloc), ")") {
			bloc += lignes[i+1]
		}
		bloc = strings.TrimSuffix(strings.TrimSpace(bloc), ")")
		var out []string
		for _, a := range strings.Split(bloc, ",") {
			out = append(out, strings.TrimSpace(a))
		}
		return out
	}
	return nil
}

func lireSource(t *testing.T, paquet, nom string) string {
	t.Helper()
	racine := racineDuDepot(t)
	b, err := os.ReadFile(filepath.Join(racine, paquet, nom+".go"))
	if err != nil {
		t.Fatalf("lecture de %s/%s.go : %v", paquet, nom, err)
	}
	return string(b)
}

func racineDuDepot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("hors depot git : %v", err)
	}
	return strings.TrimSpace(string(out))
}
