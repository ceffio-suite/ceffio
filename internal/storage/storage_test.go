// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package storage

import "testing"

// The default matters: it decides what a deployment that follows the
// documentation gets. Longhorn, because local-path cannot expand a volume
// and cannot back it up — the two properties the product requires.
func TestDefautEstLonghorn(t *testing.T) {
	t.Setenv(Variable, "")
	if got := Classe(); got != "longhorn" {
		t.Fatalf("défaut = %q, attendu longhorn", got)
	}
}

func TestVariablePiloteLaClasse(t *testing.T) {
	t.Setenv(Variable, "local-path")
	if got := Classe(); got != "local-path" {
		t.Fatalf("Classe() = %q, attendu local-path", got)
	}
}

// A value with spaces around it must not reach the manifest: it would name a
// StorageClass that does not exist, and the PVC would stay Pending.
func TestEspacesIgnores(t *testing.T) {
	t.Setenv(Variable, "  longhorn  ")
	if got := Classe(); got != "longhorn" {
		t.Fatalf("Classe() = %q, attendu longhorn sans espaces", got)
	}
}

// The end of the chain: the value has to arrive in the manifest unchanged.
// A wrong format index would print « %![2]s(MISSING) » into the YAML, which
// Kubernetes rejects — and the mistake is invisible at compile time.
func TestValeurArriveDansLeManifeste(t *testing.T) {
	t.Setenv(Variable, "longhorn")
	manifeste := "  storageClassName: " + Classe() + "\n"
	attendu := "  storageClassName: longhorn\n"
	if manifeste != attendu {
		t.Fatalf("manifeste = %q, attendu %q", manifeste, attendu)
	}
}
