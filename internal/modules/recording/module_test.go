// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package recording

import (
	"regexp"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestInfoValide vérifie le contrat d'affichage du module.
func TestInfoValide(t *testing.T) {
	m := &recordingModule{}
	info := m.Info()

	if info.ID == "" {
		t.Error("Info.ID must not be empty")
	}
	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	if !kebab.MatchString(info.ID) {
		t.Errorf("Info.ID %q is not kebab-case", info.ID)
	}
	if info.ID != "recording" {
		t.Errorf("Info.ID = %q, expected %q (the plan names it)", info.ID, "recording")
	}
	if info.Title == "" {
		t.Error("Info.Title must not be empty")
	}
	if info.Description == "" {
		t.Error("Info.Description must not be empty")
	}
	if len(info.Namespaces) == 0 {
		t.Error("Info.Namespaces must not be empty: the recorder lives in ceffio-video")
	}

	// Le plan impose Optional ET installé par défaut : `ceffio install` le
	// pose, `--without recording` l'écarte. Une inversion ici changerait
	// silencieusement ce que reçoit chaque installation.
	if info.Kind != module.Optional {
		t.Errorf("Kind = %v, expected module.Optional", info.Kind)
	}
	if !info.Default {
		t.Error("Info.Default must be true: recording ships with the default install")
	}
}
