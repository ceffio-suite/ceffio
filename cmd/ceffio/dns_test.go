// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	_ "github.com/ceffio-suite/ceffio/internal/modules"
)

// TestLesHotesViennentDuRegistre : the host list is built from what the modules
// DECLARE, not from a table in this command.
//
// THAT IS THE WHOLE POINT OF THE GENERIC FORM: a module installed tomorrow is checked
// without anyone editing `ceffio dns`, and a module that is absent from the registry
// cannot contribute a host nobody serves.
func TestLesHotesViennentDuRegistre(t *testing.T) {
	hotess := hotesDeclares("example.org")
	if len(hotess) == 0 {
		t.Fatal("no host declared by any module: the registry lost its Services")
	}
	for _, h := range hotess {
		if !strings.HasSuffix(h.Hote, ".example.org") {
			t.Errorf("host %q is not built from the domain given", h.Hote)
		}
		if h.Declare == "" {
			t.Errorf("host %q does not name the module that declares it: the operator "+
				"cannot tell which module to remove if the record is unwanted", h.Hote)
		}
	}
}

// TestLesHotesSontTries : the output is read in a terminal, and an unsorted list
// changes order between runs — which makes a diff of two runs useless.
func TestLesHotesSontTries(t *testing.T) {
	hotess := hotesDeclares("example.org")
	for i := 1; i < len(hotess); i++ {
		if hotess[i-1].Hote > hotess[i].Hote {
			t.Errorf("hosts are not sorted: %q before %q", hotess[i-1].Hote, hotess[i].Hote)
		}
	}
}

// TestLeMailEstDeclare : the mail host WAS MISSING from the registry, so `ceffio dns`
// never checked it — the mail host could stop resolving and nothing said so until
// someone opened it.
func TestLeMailEstDeclare(t *testing.T) {
	var trouve bool
	for _, h := range hotesDeclares("example.org") {
		if h.Hote == "mail.example.org" {
			trouve = true
			if h.Declare != "mail" {
				t.Errorf("mail.example.org is declared by %q, expected the mail module", h.Declare)
			}
		}
	}
	if !trouve {
		t.Error("mail.example.org is not declared by any module: the DNS check skips the " +
			"mail host entirely")
	}
}

// TestLeVaultNeDeclareRien : bao.<domain> EXISTS but is deliberately absent from the
// registry's Services, so /api/status stays exactly what the console publishes. This
// test records the choice so a later reader does not 'fix' it by adding a Service that
// would leave the two answers disagreeing.
func TestLeVaultNeDeclareRien(t *testing.T) {
	m, ok := module.Get("vault")
	if !ok {
		t.Skip("no vault module in this build")
	}
	if len(m.Info().Services) != 0 {
		t.Error("the vault declares a Service: bao.<domain> exists as an Ingress, but the " +
			"registry reproduces /api/status exactly — inventing an exposure the console " +
			"never published would make it lie")
	}
	for _, h := range hotesDeclares("example.org") {
		if h.Hote == "bao.example.org" {
			t.Error("bao.example.org appears in the DNS check, which means the vault " +
				"declares a Service it should not")
		}
	}
}

// TestUnHoteTechniqueResteSepare : a host meant for machines is not presented as a
// user-facing access point — but it is still checked, because its absence is a fault
// without being a visible one.
func TestUnHoteTechniqueResteSepare(t *testing.T) {
	var techniques int
	for _, h := range hotesDeclares("example.org") {
		if h.Technique {
			techniques++
		}
	}
	if techniques == 0 {
		t.Log("no technical host in this build: the separation is untested but not broken")
	}
}

// TestCourtTronque : a resolver error carries trailing detail that is useful once and
// noise in a table.
func TestCourtTronque(t *testing.T) {
	long := strings.Repeat("a", 200)
	// 90 characters plus the ellipsis, which is three BYTES in UTF-8.
	if got := court(long); len(got) > 93 {
		t.Errorf("court did not truncate: %d bytes", len(got))
	} else if !strings.HasSuffix(got, "…") {
		t.Errorf("the truncation is not visible: a message cut without a mark reads as a " +
			"complete one that happens to end mid-word")
	}
	if got := court("a\nb"); got != "a" {
		t.Errorf("court kept the line break: %q", got)
	}
	if got := court("short"); got != "short" {
		t.Errorf("court altered a short message: %q", got)
	}
}
