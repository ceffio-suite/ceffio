// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package exappsdaemon

import (
	"regexp"
	"testing"
)

// TestInfoValide checks the display contract: the frontends (CLI, console)
// show these fields without any check, so an empty value here would become a
// blank line or a nameless button — and a non kebab-case ID would be
// rejected by module.Register at startup.
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

// TestEnregistre verifies that init() did place the module in the registry
// — without which the blank import of all.go would serve no purpose.
func TestEnregistre(t *testing.T) {
	// The mere fact that this package compiles and initializes exercises
	// init(); the real assertion lives in internal/modules/all_test.go,
	// which reads the global registry. Here we only check the consistency
	// of the identifier.
	if (&harpModule{}).Info().ID != "exapps-daemon" {
		t.Error("the registered ID must match the plan")
	}
}
