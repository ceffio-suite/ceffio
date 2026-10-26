// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"strings"
	"testing"
)

// TestPolitiqueModule: a module's policy is READ ONLY and confined to its own
// prefix. The refusal is the part that matters — a path aimed at another
// component's secrets must fail at provisioning, not grant silently.
func TestPolitiqueModule(t *testing.T) {
	regle, err := PolitiqueModule("capture", []string{"kv/data/ceffio/capture/*"})
	if err != nil {
		t.Fatalf("a valid path was refused: %v", err)
	}
	for _, attendu := range []string{
		`path "kv/data/ceffio/capture/*"`,
		`path "kv/metadata/ceffio/capture/*"`,
		`path "sys/internal/ui/mounts/*"`,
	} {
		if !strings.Contains(regle, attendu) {
			t.Errorf("policy does not contain %q:\n%s", attendu, regle)
		}
	}
	if strings.Contains(regle, `"create"`) || strings.Contains(regle, `"update"`) {
		t.Errorf("policy grants a write capability:\n%s", regle)
	}

	for _, mauvais := range []string{
		"kv/data/ceffio/talk/*",       // another component's secrets
		"kv/data/ceffio/capture/../x", // escaping its own prefix
	} {
		if _, err := PolitiqueModule("capture", []string{mauvais}); err == nil {
			t.Errorf("PolitiqueModule accepted %q", mauvais)
		}
	}

	if _, err := PolitiqueModule("capture", nil); err == nil {
		t.Error("PolitiqueModule accepted an empty access")
	}
}
