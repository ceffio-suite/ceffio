// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import "testing"

// TestLaSyntheseNeListeQueLesServicesPresents: the closing summary lists the
// mail host only when the mail module is deployed.
//
// WHY THIS TEST EXISTS: the summary is the last thing an operator reads after
// an installation. `--without mail` used to leave the line `mail.<domain>` on
// screen anyway — a name that resolves, answers 404, and sends them looking for
// a mail server that does not exist.
func TestLaSyntheseNeListeQueLesServicesPresents(t *testing.T) {
	sans := servicesPublies(false)
	for _, s := range sans {
		if s.sub == "mail" {
			t.Fatal("mail is listed although the module is not installed")
		}
	}
	if len(sans) != 6 {
		t.Errorf("%d services listed, expected the six Core ones", len(sans))
	}

	avec := servicesPublies(true)
	var vu bool
	for _, s := range avec {
		if s.sub == "mail" {
			vu = true
		}
	}
	if !vu {
		t.Error("mail is not listed although the module is installed")
	}
	if len(avec) != len(sans)+1 {
		t.Errorf("%d services listed with mail, expected %d", len(avec), len(sans)+1)
	}
}
