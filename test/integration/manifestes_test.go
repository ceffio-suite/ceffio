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

// The modules that carry a StorageClass, with the string expected in the
// generated manifest.
var modules = []struct {
	paquet string
	nom    string
}{
	{"internal/files", "files"},
	{"internal/mail", "mail"},
	{"internal/office", "office"},
	{"internal/data", "data"},
}

// TestAucunManifesteNADeFormatNonResolu scans the source of each module and
// rejects what Go writes when a verb cannot be resolved.
//
// « %!s(MISSING) » and « %![3]s(EXTRA ...) » are injected INTO the output: they
// therefore arrive as-is in the YAML, and kubectl fails further down, on an
// unrelated line. None of these markers may remain.
func TestAucunManifesteNADeFormatNonResolu(t *testing.T) {
	for _, m := range modules {
		t.Run(m.nom, func(t *testing.T) {
			// We compile the test package isolating the manifest, via go test
			// on the package itself when it exposes the text.
			source := lireSource(t, m.paquet, m.nom)
			if strings.Contains(source, "%!") {
				t.Errorf("%s: un format non resolu est present dans le source", m.nom)
			}
		})
	}
}

// TestStorageClassNumeroteeEtNommee verifies the precise point that broke
// twice: the index placed in front of storageClassName must name the class,
// nothing else.
//
// Compiling cannot tell us. We know it by comparing the index with the
// position of the argument in the list — exactly the human error committed.
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

			// The argument must designate the storage class. Depending on
			// the module it is storage.Classe() or a parameter named classe.
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

// indexStorageClass reads the index written in front of storageClassName.
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

// argumentsSprintf reads the list passed to the fmt.Sprintf WHOSE MANIFEST
// CARRIES THE STORAGECLASS.
//
// THREE TRAPS, all met while writing this test:
//
//  1. The file contains several fmt.Sprintf calls. Taking the first one brings
//     back the argument list of another manifest (files.go has one from line
//     102), and the tested index no longer means anything.
//  2. A « `, » appears in the comments: « such as `deploy/nextcloud`, ... ».
//     Starting from the top of the file reads a comment.
//  3. The fmt.Sprintf call that carries the manifest is the one whose block
//     ends with storageClassName — it is the only reliable anchor, because it
//     is precisely what we are trying to verify.
//
// A false positive costs as much as a false negative: it teaches one to ignore
// the test. Hence the anchoring on content rather than on position.
func argumentsSprintf(t *testing.T, source string) []string {
	t.Helper()
	lignes := strings.Split(source, "\n")

	// We locate the line that declares the StorageClass, then go back up to
	// the fmt.Sprintf that opens that block.
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
		// The list can spill over onto the next line.
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
