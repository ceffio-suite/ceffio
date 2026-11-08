// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sbom

import (
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// ModuleAttendu says whether a component's module is expected to run on this
// installation: a core module, or an optional one installed by default.
//
// HERE AND NOT IN THE CALLERS: the CLI and the console both compare the document
// with the cluster, and a rule duplicated in two frontends is a rule that will
// disagree with itself. An unknown module answers false — a component nobody can
// name is not a component we can call missing.
func ModuleAttendu(id string) bool {
	// The registry names modules by their Go path; the catalogue by their ID,
	// and the two differ by hyphens ("internal/modules/longhornui" ↔
	// "longhorn-ui"). Normalising both sides here beats a table of aliases that
	// would drift from the catalogue.
	court := normaliser(dernierSegment(id))
	for _, m := range module.All() {
		info := m.Info()
		if normaliser(info.ID) != court {
			continue
		}
		return info.Kind == module.Core || info.Default
	}
	// A MODULE THE CATALOGUE DOES NOT KNOW IS NOT "EXPECTED": reporting its
	// absence would invent an expectation nobody expressed.
	return false
}

// normaliser drops the separators that vary between the two spellings.
func normaliser(s string) string {
	s = strings.ReplaceAll(s, "-", "")
	return strings.ReplaceAll(s, "_", "")
}

// dernierSegment keeps the last path element: "internal/modules/capture" and
// "capture" name the same module.
func dernierSegment(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}
