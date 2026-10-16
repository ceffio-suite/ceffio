// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package files

import (
	"strings"
	"testing"
)

// The manifest is built with fmt.Sprintf and nine verbs. Mixing the two styles
// — %[n]s and plain %s — makes Go shift every verb after the first indexed
// one, silently: the compiler and `go vet` both accept the result.
//
// This is not hypothetical. It reached a deployment:
//
//	error parsing STDIN: error converting YAML to JSON:
//	yaml: line 21: could not find expected ':'
//
// The message points at a line of YAML, never at the format string, and the
// cause was a value landing one line above its own. So the only check that
// settles it is reading the produced text, which is what these tests do.
//
// If a verb is left unresolved, Go writes « %!s(MISSING) » or
// « %![3]s(EXTRA ...) » into the output. Both are easy to detect and neither
// can reach a cluster.

func manifesteDeTest(classe string) string {
	return manifesteNextcloud("ceffio-files", classe, "  annotations:\n    test: oui",
		"nextcloud:34.0.3", "pg", "nextcloud", "valkey", "6379")
}

func TestAucunFormatNonResolu(t *testing.T) {
	m := manifesteDeTest("longhorn")
	if strings.Contains(m, "%!") {
		i := strings.Index(m, "%!")
		debut := i - 40
		if debut < 0 {
			debut = 0
		}
		fin := i + 60
		if fin > len(m) {
			fin = len(m)
		}
		t.Fatalf("format non résolu dans le manifeste : %q", m[debut:fin])
	}
}

// The StorageClass is the whole point of the change: it has to arrive in the
// manifest exactly as configured, not dropped and not doubled.
func TestStorageClassArriveDansLeManifeste(t *testing.T) {
	for _, classe := range []string{"longhorn", "local-path"} {
		m := manifesteDeTest(classe)
		attendu := "storageClassName: " + classe
		if !strings.Contains(m, attendu) {
			t.Errorf("classe %q absente du manifeste", classe)
		}
	}
}

// Each value must land on its OWN line. A shifted verb puts two values on one
// line, which is exactly what broke the YAML in production.
func TestChaqueValeurSurSaLigne(t *testing.T) {
	m := manifesteDeTest("longhorn")
	for _, ligne := range []string{
		"  namespace: ceffio-files",
		"  storageClassName: longhorn",
		"        image: nextcloud:34.0.3",
		"  name: nextcloud-data",
	} {
		if !strings.Contains(m, ligne+"\n") {
			t.Errorf("ligne attendue absente ou mal formée : %q", ligne)
		}
	}
}

// The primary key index and the namespace are both %[1]s on purpose: the PVC
// and the Deployment share the namespace, and that must not have moved.
func TestNamespaceRepete(t *testing.T) {
	m := manifesteDeTest("longhorn")
	if n := strings.Count(m, "namespace: ceffio-files"); n < 2 {
		t.Errorf("le namespace apparaît %d fois, attendu au moins 2", n)
	}
}
