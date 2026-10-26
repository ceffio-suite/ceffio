// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package capture

import (
	"regexp"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestInfoValide vérifie le contrat d'affichage et, surtout, les dépendances :
// a capture without the recorder has nothing to transcribe — and that is the
// only one: it joins the call through the signaling, not through HaRP.
func TestInfoValide(t *testing.T) {
	m := &captureModule{}
	info := m.Info()

	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	if !kebab.MatchString(info.ID) || info.ID != "capture" {
		t.Errorf("Info.ID = %q, attendu capture en kebab-case", info.ID)
	}
	if info.Title == "" || info.Description == "" {
		t.Error("Title et Description sont obligatoires")
	}
	if info.Kind != module.Optional {
		t.Errorf("Kind = %v, attendu module.Optional", info.Kind)
	}

	exigences := map[string]bool{}
	for _, d := range info.Requires {
		exigences[d] = true
	}
	if !exigences["recording"] {
		t.Errorf("Info.Requires ne contient pas recording (%v)", info.Requires)
	}
	// THE DEPENDENCY ON HaRP IS GONE, and it must not come back: it would
	// force exapps-daemon — and therefore the right for Nextcloud to start
	// containers — on an installation that only wants to record and transcribe.
	if exigences["exapps-daemon"] {
		t.Errorf("Info.Requires contient encore exapps-daemon (%v)", info.Requires)
	}

	// Les droits doivent couvrir les deux execs, sans quoi le service démarre
	// et échoue à la première écriture.
	vus := map[string]bool{}
	for _, p := range info.Permissions {
		vus[p.Namespace] = true
	}
	for _, attendu := range []string{"ceffio-video", "ceffio-files", "ceffio-data"} {
		if !vus[attendu] {
			t.Errorf("aucune permission déclarée pour %q", attendu)
		}
	}
}
