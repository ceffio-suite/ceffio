// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package exappsdaemon

import (
	"regexp"
	"testing"
)

// TestInfoValide vérifie le contrat d'affichage : les frontaux (CLI, console)
// montrent ces champs sans contrôle, donc une valeur vide ici deviendrait une
// ligne blanche ou un bouton sans nom — et un ID non kebab-case serait refusé
// par module.Register au démarrage.
func TestInfoValide(t *testing.T) {
	m := &harpModule{}
	info := m.Info()

	if info.ID == "" {
		t.Error("Info.ID must not be empty")
	}
	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	if !kebab.MatchString(info.ID) {
		t.Errorf("Info.ID %q is not kebab-case", info.ID)
	}
	if info.ID != "exapps-daemon" {
		t.Errorf("Info.ID = %q, expected %q (the plan names it)", info.ID, "exapps-daemon")
	}
	if info.Title == "" {
		t.Error("Info.Title must not be empty")
	}
	if info.Description == "" {
		t.Error("Info.Description must not be empty")
	}
	if len(info.Namespaces) == 0 {
		t.Error("Info.Namespaces must not be empty: the module has workloads in ceffio-exapps")
	}
}

// TestEnregistre verifie que l'init() a bien place le module dans le registre
// — sans quoi l'import blank de all.go ne servirait a rien.
func TestEnregistre(t *testing.T) {
	// Le simple fait que ce package compile et s'initialise exerce init();
	// l'assertion reelle vit dans internal/modules/all_test.go, qui lit le
	// registre global. Ici on verifie seulement la coherence de l'identifiant.
	if (&harpModule{}).Info().ID != "exapps-daemon" {
		t.Error("the registered ID must match the plan")
	}
}
