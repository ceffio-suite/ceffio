//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package demo

import (
	"encoding/json"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// lireReglages decodes the group's entry, dropping keys the group no longer
// declares.
//
// WHY THE FILTER: a key left behind by a removed field must not come back in a
// form or in a terminal listing. The entry is a historical artefact; the group's
// declaration is the truth about what exists.
func lireReglages(brut string, g module.Group) (map[string]string, error) {
	if brut == "" {
		return map[string]string{}, nil
	}
	stoc := map[string]string{}
	if err := json.Unmarshal([]byte(brut), &stoc); err != nil {
		return nil, fmt.Errorf("demo: settings entry %q is not valid JSON: %w", cleReglages, err)
	}
	connus := map[string]bool{}
	for _, f := range g.Fields {
		connus[f.Key] = true
	}
	for k := range stoc {
		if !connus[k] {
			delete(stoc, k)
		}
	}
	return stoc, nil
}

// encoderReglages encodes the group's entry.
func encoderReglages(v map[string]string) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("demo: encoding settings: %w", err)
	}
	return string(b), nil
}
