// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package transcription

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/exapps"
	"github.com/ceffio-suite/ceffio/internal/module"
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

// fauxMagasin is a module.Settings store held in a map: the settings logic is
// what these tests cover, not the ConfigMap.
type fauxMagasin struct {
	donnees  map[string]string
	ecriture int
}

func (f *fauxMagasin) Lire(_ context.Context, _, _, cle string) (string, error) {
	return f.donnees[cle], nil
}

func (f *fauxMagasin) Ecrire(_ context.Context, _, _ string, d map[string]string) error {
	f.ecriture++
	for k, v := range d {
		f.donnees[k] = v
	}
	return nil
}

func (f *fauxMagasin) Supprimer(_ context.Context, _, _, cle string) error {
	delete(f.donnees, cle)
	return nil
}

// TestSettingsDeclareLesLangues: the console draws this form without knowing
// what it means, so the shape IS the contract — a group id, a text field with
// a default, and a help text that names the accepted codes.
func TestSettingsDeclareLesLangues(t *testing.T) {
	groupes := (&transcriptionModule{}).Settings()
	if len(groupes) != 1 {
		t.Fatalf("Settings() returned %d groups, expected 1", len(groupes))
	}
	g := groupes[0]
	if g.ID != groupeLangues {
		t.Errorf("group id = %q, expected %q", g.ID, groupeLangues)
	}
	if len(g.Fields) != 1 {
		t.Fatalf("group %q has %d fields, expected 1", g.ID, len(g.Fields))
	}
	f := g.Fields[0]
	if f.Key != "codes" || f.Type != module.Text || !f.Required {
		t.Errorf("field = %+v, expected a required text field keyed codes", f)
	}
	if f.Default != "fr" {
		t.Errorf("default = %q, expected fr", f.Default)
	}
	if !strings.Contains(f.Help, "fr") {
		t.Errorf("help must name the accepted codes, got %q", f.Help)
	}
}

// TestCurrentSansMagasin: an installation that never saved the setting reads
// the default, and the default is the one LanguesParDefaut declares — never a
// second copy that could drift.
func TestCurrentSansMagasin(t *testing.T) {
	m := &transcriptionModule{}
	v, err := m.Current(context.Background(), module.Env{}, groupeLangues)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v["codes"] != strings.Join(exapps.LanguesParDefaut, ",") {
		t.Errorf("codes = %q, expected %v", v["codes"], exapps.LanguesParDefaut)
	}

	if _, err := m.Current(context.Background(), module.Env{}, "inconnu"); err != module.ErrUnknownGroup {
		t.Errorf("unknown group: err = %v, expected ErrUnknownGroup", err)
	}
}

// TestCurrentLitLeMagasin: the stored value wins over the default, and a
// malformed entry is an error rather than a silent fallback — silently
// ignoring a corrupted setting hides a hand edit that went wrong.
func TestCurrentLitLeMagasin(t *testing.T) {
	m := &transcriptionModule{}
	store := &fauxMagasin{donnees: map[string]string{cleReglages: `{"codes":"fr,ar"}`}}
	v, err := m.Current(context.Background(), module.Env{Settings: store}, groupeLangues)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v["codes"] != "fr,ar" {
		t.Errorf("codes = %q, expected fr,ar", v["codes"])
	}

	store.donnees[cleReglages] = `{`
	if _, err := m.Current(context.Background(), module.Env{Settings: store}, groupeLangues); err == nil {
		t.Error("a malformed entry must be reported, not replaced by the default")
	}
}

// TestApplyRefuseUnCodeInconnu: validation happens BEFORE anything is written
// or downloaded. Storing first and failing after would leave the platform
// configured for a language no model can serve.
func TestApplyRefuseUnCodeInconnu(t *testing.T) {
	m := &transcriptionModule{}
	store := &fauxMagasin{donnees: map[string]string{}}

	err := m.Apply(context.Background(), module.Env{Settings: store}, groupeLangues,
		module.Values{"codes": "fr,zz"})
	if err == nil {
		t.Fatal("Apply accepted an unknown language")
	}
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Errorf("err = %v, expected ErrInvalidSettings", err)
	}
	if store.ecriture != 0 {
		t.Errorf("the store was written %d times for an invalid value", store.ecriture)
	}
}

// TestLanguesConfigureesParDefaut closes the loop the installer takes: no
// stored setting means the default list, already validated.
func TestLanguesConfigureesParDefaut(t *testing.T) {
	langues, err := languesConfigurees(context.Background(), module.Env{})
	if err != nil {
		t.Fatalf("languesConfigurees: %v", err)
	}
	if strings.Join(langues, ",") != strings.Join(exapps.LanguesParDefaut, ",") {
		t.Errorf("langues = %v, expected %v", langues, exapps.LanguesParDefaut)
	}
}
