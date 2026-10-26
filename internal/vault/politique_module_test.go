// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
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

// TestChaqueModuleDeclareUnAccesValide walks the registry: every declaration the
// provisioning loop will turn into a policy and a role must pass the prefix rule.
//
// WHY HERE RATHER THAN IN EACH MODULE: the loop in vault.go calls
// PolitiqueModule for every module, and the call happens during `ceffio vault` —
// long after a build would have caught a typo. A module that declares
// "kv/data/ceffio/longhorn-ui/oauth2-proxy" while its ID is "longhorn-oauth2"
// breaks the whole vault installation, not just its own pod.
func TestChaqueModuleDeclareUnAccesValide(t *testing.T) {
	for _, m := range module.All() {
		i := m.Info()
		for _, acces := range i.Vault {
			if acces.ServiceAccount == "" || acces.Namespace == "" {
				t.Errorf("module %q: incomplete identity %+v — the role would bind no "+
					"ServiceAccount", i.ID, acces)
			}
			regle, err := PolitiqueModule(i.ID, acces.Paths)
			if err != nil {
				t.Errorf("module %q: %v", i.ID, err)
				continue
			}
			// READ ONLY: the module contract forbids a declared write.
			for _, verbe := range []string{`"create"`, `"update"`, `"delete"`} {
				if strings.Contains(regle, verbe) {
					t.Errorf("module %q: the policy grants %s", i.ID, verbe)
				}
			}
		}
	}
}
