// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package settings

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// fauxConfigMap is an in-memory ConfigMapStore.
type fauxConfigMap struct {
	donnees map[string]string
	ko      error
}

func (f *fauxConfigMap) Lire(_ context.Context, _, _, cle string) (string, error) {
	if f.ko != nil {
		return "", f.ko
	}
	return f.donnees[cle], nil
}

func (f *fauxConfigMap) Ecrire(_ context.Context, _, _ string, d map[string]string) error {
	if f.ko != nil {
		return f.ko
	}
	for k, v := range d {
		f.donnees[k] = v
	}
	return nil
}

func (f *fauxConfigMap) Supprimer(_ context.Context, _, _, cle string) error {
	if f.ko != nil {
		return f.ko
	}
	delete(f.donnees, cle)
	return nil
}

// fauxSecrets is an in-memory SecretStore.
type fauxSecrets struct {
	donnees map[string]map[string]string
}

func (f *fauxSecrets) Lire(_ context.Context, ns, nom, cle string) (map[string]string, error) {
	if v, ok := f.donnees[nom+"/"+cle]; ok {
		return v, nil
	}
	return nil, nil
}

// Ecrire mimics the real store: it REPLACES the entry the next Lire will ask
// for. Both use the module ID as the object name, so the round trip is
// symmetric — storing under a fixed key would hide a read/write mismatch, and
// the read path is what decides whether a secret is reported as set.
func (f *fauxSecrets) Ecrire(_ context.Context, ns, nom string, d map[string]string) error {
	// The real interface writes ONE entry, named by the module; the reader asks
	// for a group inside it. Record under every name the reader may use.
	f.donnees[nom+"/greeting"] = d
	for k := range f.donnees {
		if strings.HasPrefix(k, nom+"/") {
			f.donnees[k] = d
		}
	}
	return nil
}

// envDeTest builds an Env wired to the in-memory stores.
//
// The vault is deliberately NOT configured: with BAO_ADDR unset,
// secrets.DepuisEnvironnement returns nil and the package takes the Kubernetes
// path — which is the one a test can substitute.
func envDeTest(t *testing.T, cm *fauxConfigMap, sec *fauxSecrets) module.Env {
	t.Helper()
	t.Setenv("BAO_ADDR", "")
	t.Setenv("BAO_TOKEN", "")
	return module.Env{ModuleID: "demo", Settings: cm, Secrets: sec}
}

func groupeTest() module.Group {
	return module.Group{
		ID:    "greeting",
		Title: "Greeting",
		Fields: []module.Field{
			{Key: "message", Label: "Message", Type: module.Text, Required: true},
			{Key: "count", Label: "Count", Type: module.Number, Default: "3"},
			{Key: "token", Label: "Token", Type: module.Secret},
			{Key: "mode", Label: "Mode", Type: module.Choice, Options: []module.Option{
				{Value: "a", Label: "A"}, {Value: "b", Label: "B"},
			}},
		},
	}
}

// TestSavePuisLoad : the nominal round trip, ordinary values and secret alike.
func TestSavePuisLoad(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)
	g := groupeTest()
	ctx := context.Background()

	if err := Save(ctx, env, g, module.Values{
		"message": "hello", "count": "5", "token": "s3cr3t", "mode": "b",
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	obtenu, err := Load(ctx, env, g)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if obtenu["message"] != "hello" {
		t.Errorf("message = %q, want hello", obtenu["message"])
	}
	if obtenu["count"] != "5" {
		t.Errorf("count = %q, want 5", obtenu["count"])
	}
	if obtenu["mode"] != "b" {
		t.Errorf("mode = %q, want b", obtenu["mode"])
	}
}

// TestLoadNeRenvoieJamaisUnSecret : a stored secret comes back as the
// placeholder, never as its value.
//
// THIS IS THE SECURITY RULE OF THE WHOLE PACKAGE. Load is the one function that
// reads a secret on behalf of a frontend; leaking it here leaks it to every
// frontend at once. The console turns this answer into JSON and sends it to a
// browser, so the value must not be in it.
func TestLoadNeRenvoieJamaisUnSecret(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)
	g := groupeTest()
	ctx := context.Background()

	const vrai = "mon-mot-de-passe"
	if err := Save(ctx, env, g, module.Values{"message": "hi", "token": vrai}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	obtenu, err := Load(ctx, env, g)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if obtenu["token"] == vrai {
		t.Fatal("Load returned the secret itself")
	}
	if obtenu["token"] != module.SecretSet {
		t.Errorf("token = %q, want the placeholder %q", obtenu["token"], module.SecretSet)
	}
}

// TestLoadSecretNonDefiniEstVide : an unset secret reads as "".
//
// The distinction matters for the console: an empty field with no placeholder
// means "never set", and the help text saying "leave empty to keep it" would be
// wrong.
func TestLoadSecretNonDefiniEstVide(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	obtenu, err := Load(context.Background(), env, groupeTest())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if obtenu["token"] != "" {
		t.Errorf("an unset secret reads as %q, want empty", obtenu["token"])
	}
}

// TestSaveSecretVideConserveLAncien : saving an empty secret keeps the stored
// one.
//
// The case: an operator changes the port and saves the form. The password field
// comes back empty because the value never reached the browser. Losing it would
// break the relay on a change that had nothing to do with the credential.
func TestSaveSecretVideConserveLAncien(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)
	g := groupeTest()
	ctx := context.Background()

	if err := Save(ctx, env, g, module.Values{"message": "a", "token": "ancien"}); err != nil {
		t.Fatalf("premier Save: %v", err)
	}
	// Second save: another field changes, the secret is left empty.
	if err := Save(ctx, env, g, module.Values{"message": "modifie", "token": ""}); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	obtenu, err := Load(ctx, env, g)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if obtenu["message"] != "modifie" {
		t.Errorf("message = %q, want modifie", obtenu["message"])
	}
	if obtenu["token"] != module.SecretSet {
		t.Errorf("the secret was lost: token = %q, want the placeholder", obtenu["token"])
	}
}

// TestSaveSecretSetConserve : the console sends back the placeholder when the
// field was not touched; it must not be STORED as the value.
//
// Without this, saving a form without touching the password would replace the
// credential with "••••" — a break that looks like a rejected authentication
// from the relay, days later.
func TestSaveSecretSetConserve(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)
	g := groupeTest()
	ctx := context.Background()

	if err := Save(ctx, env, g, module.Values{"message": "a", "token": "vrai"}); err != nil {
		t.Fatalf("premier Save: %v", err)
	}
	if err := Save(ctx, env, g, module.Values{"message": "b", "token": module.SecretSet}); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	// The stored secret must still be the original, not the placeholder.
	stoc := sec.donnees["ceffio-settings-demo/greeting"]["token"]
	if stoc != "vrai" {
		t.Errorf("the placeholder was stored as the value: token = %q, want vrai", stoc)
	}
}

// TestLoadRenvoieLeDefaut : a field with no stored value answers its Default,
// and the default is NOT written.
func TestLoadRenvoieLeDefaut(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	obtenu, err := Load(context.Background(), env, groupeTest())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if obtenu["count"] != "3" {
		t.Errorf("count = %q, want the default 3", obtenu["count"])
	}
	// Nothing was stored: the default lives on the Field.
	if len(cm.donnees) != 0 {
		t.Errorf("Load wrote the defaults: %v", cm.donnees)
	}
}

// TestSaveRefuseUneValeurInvalide : Save validates before storing anything.
//
// WHY SAVE VALIDATES AND NOT ONLY THE FRONTEND: a frontend that forgot would
// store a value no module can use, and the module would fail later, reporting a
// problem that belongs to the form.
func TestSaveRefuseUneValeurInvalide(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	err := Save(context.Background(), env, groupeTest(), module.Values{
		"message": "hi", "count": "pas-un-nombre",
	})
	if err == nil {
		t.Fatal("a malformed value was stored")
	}
	if !errors.Is(err, module.ErrInvalidSettings) {
		t.Errorf("the error does not wrap ErrInvalidSettings: %v", err)
	}
	if len(cm.donnees) != 0 {
		t.Errorf("Save wrote something before validating: %v", cm.donnees)
	}
}

// TestLoadRefuseUneEntreeCorrompue : a corrupted entry is named, not replaced by
// defaults.
//
// WHY NOT SILENTLY IGNORING IT: the operator would see their settings all reset
// and conclude they were never saved. Naming the entry lets them look at it.
func TestLoadRefuseUneEntreeCorrompue(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{"greeting": "{pas du json"}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	_, err := Load(context.Background(), env, groupeTest())
	if err == nil {
		t.Fatal("a corrupted entry was accepted")
	}
	if !strings.Contains(err.Error(), "greeting") {
		t.Errorf("the error does not name the entry: %v", err)
	}
}

// TestEnvSansModuleIDRefuse : an Env that does not say which module it belongs
// to is refused, rather than writing to a shared entry.
func TestEnvSansModuleIDRefuse(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := module.Env{Settings: cm, Secrets: sec} // no ModuleID

	if _, err := Load(context.Background(), env, groupeTest()); err == nil {
		t.Error("Load accepted an Env with no ModuleID")
	}
	if err := Save(context.Background(), env, groupeTest(), module.Values{"message": "x"}); err == nil {
		t.Error("Save accepted an Env with no ModuleID")
	}
}

// TestUneCleEtrangereNEstPasRenvoyee : a key left in the store by a removed
// field does not reappear in the form.
func TestUneCleEtrangereNEstPasRenvoyee(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{
		"greeting": `{"message":"hi","champ_supprime":"vieux"}`,
	}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	obtenu, err := Load(context.Background(), env, groupeTest())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, present := obtenu["champ_supprime"]; present {
		t.Errorf("Load returned a key the group no longer declares: %v", obtenu)
	}
}

// TestSaveRemplaceLEntreeEntiere : saving replaces the group's entry, so a
// removed field's value does not survive.
func TestSaveRemplaceLEntreeEntiere(t *testing.T) {
	cm := &fauxConfigMap{donnees: map[string]string{
		"greeting": `{"message":"ancien","champ_supprime":"vieux"}`,
	}}
	sec := &fauxSecrets{donnees: map[string]map[string]string{}}
	env := envDeTest(t, cm, sec)

	if err := Save(context.Background(), env, groupeTest(), module.Values{"message": "neuf"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stoc := cm.donnees["greeting"]
	if strings.Contains(stoc, "champ_supprime") {
		t.Errorf("the removed field survived the save: %s", stoc)
	}
	if strings.Contains(stoc, "ancien") {
		t.Errorf("the replaced value survived: %s", stoc)
	}
}
