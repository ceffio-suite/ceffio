// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package transcription

import (
	"regexp"
	"testing"
)

// TestInfoValide checks the display contract, and above all the dependency:
// "live-transcription" without "exapps-daemon" installed is an operation
// doomed to fail (it is HaRP that deploys the app). If Requires loses this
// entry, the registry can no longer grey out the button nor order the
// installation — hence the dedicated assertion.
func TestInfoValide(t *testing.T) {
	m := &transcriptionModule{}
	info := m.Info()

	if info.ID == "" {
		t.Error("Info.ID must not be empty")
	}
	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	if !kebab.MatchString(info.ID) {
		t.Errorf("Info.ID %q is not kebab-case", info.ID)
	}
	if info.ID != "live-transcription" {
		t.Errorf("Info.ID = %q, expected %q (the plan names it)", info.ID, "live-transcription")
	}
	if info.Title == "" {
		t.Error("Info.Title must not be empty")
	}
	if info.Description == "" {
		t.Error("Info.Description must not be empty")
	}
	if len(info.Namespaces) == 0 {
		t.Error("Info.Namespaces must not be empty: the ExApp workload lives in ceffio-exapps")
	}

	// THE DEPENDENCY, explicit: without it the app installs and never
	// activates, with no error pointing at the missing deployer.
	trouve := false
	for _, dep := range info.Requires {
		if dep == "exapps-daemon" {
			trouve = true
		}
	}
	if !trouve {
		t.Errorf("Info.Requires = %v, must contain %q", info.Requires, "exapps-daemon")
	}
}

// TestLigneAppareillee covers the only piece of logic specific to the
// module: the line-by-line recognition, taken from the console.
func TestLigneAppareillee(t *testing.T) {
	sortie := "Command:\n  app_api:app:list\nExApps:\n  live_transcription 1.2.3 [enabled]\n"
	if l := ligneAppareillee(sortie, "live_transcription"); l == "" {
		t.Error("ligneAppareillee found nothing in a listing that contains the app")
	}
	if l := ligneAppareillee("Command:\n  app_api:app:list\n", "live_transcription"); l != "" {
		t.Errorf("ligneAppareillee matched a command listing: %q", l)
	}
}
