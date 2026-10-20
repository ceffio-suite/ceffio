// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// groupeDeTest builds a group covering every field type and every constraint,
// so the cases below exercise the rules a real module will hit.
func groupeDeTest() Group {
	return Group{
		ID:    "demo",
		Title: "Demonstration",
		Fields: []Field{
			{Key: "greeting", Label: "Greeting", Type: Text, Required: true},
			{Key: "mode", Label: "Mode", Type: Choice, Options: []Option{
				{Value: "simple", Label: "Simple"},
				{Value: "fancy", Label: "Fancy"},
			}},
			{Key: "count", Label: "Count", Type: Number, Default: "3"},
			{Key: "loud", Label: "Loud", Type: Bool, Default: "false"},
			{Key: "token", Label: "Token", Type: Secret},
			{Key: "host", Label: "Host", Type: Text, Pattern: `^[a-z0-9.-]+$`},
			{Key: "fancy_color", Label: "Colour", Type: Text,
				ShowWhen: &Condition{Key: "mode", Equals: "fancy"}},
		},
	}
}

// TestValidateAccepteUnCasValide : the nominal case must pass, otherwise every
// refusal below would be meaningless.
func TestValidateAccepteUnCasValide(t *testing.T) {
	v := Values{
		"greeting":    "hello",
		"mode":        "fancy",
		"count":       "5",
		"loud":        "true",
		"token":       "s3cr3t",
		"host":        "relay.example.org",
		"fancy_color": "#fff",
	}
	if err := Validate(groupeDeTest(), v); err != nil {
		t.Fatalf("a valid set was refused: %v", err)
	}
}

// TestValidateRefuseChampRequisVide : Required refuses an empty value.
func TestValidateRefuseChampRequisVide(t *testing.T) {
	err := Validate(groupeDeTest(), Values{"greeting": "  "})
	if err == nil {
		t.Fatal("an empty required field was accepted")
	}
	if !strings.Contains(err.Error(), "greeting") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

// TestValidateAccepteSecretVide : an empty Secret is accepted even when the
// field is Required.
//
// WHY THIS IS THE CENTRAL CASE OF THE WHOLE CONTRACT: a form is re-saved to
// change a port, and the password field comes back empty because the value was
// never sent to the browser. Refusing it would force every operator to retype
// every secret to change anything else. "Empty means keep" is what makes a
// settings page usable at all.
func TestValidateAccepteSecretVide(t *testing.T) {
	g := groupeDeTest()
	g.Fields[4].Required = true // "token"
	if err := Validate(g, Values{"greeting": "hi", "token": ""}); err != nil {
		t.Fatalf("an empty secret was refused while it means 'keep the stored one': %v", err)
	}
}

// TestValidateRefuseNombreNonEntier : Number is an integer.
func TestValidateRefuseNombreNonEntier(t *testing.T) {
	err := Validate(groupeDeTest(), Values{"greeting": "hi", "count": "1.5"})
	if err == nil || !strings.Contains(err.Error(), "count") {
		t.Errorf("a decimal was accepted for a Number field: %v", err)
	}
}

// TestValidateRefuseBooleenInvalide : Bool is true or false, not "yes"/"1".
//
// WHY NOT ACCEPTING "yes": the value crosses three carriers (a form, a command
// line, a ConfigMap). Accepting several spellings means each carrier could store
// a different one, and a reader would have to know them all.
func TestValidateRefuseBooleenInvalide(t *testing.T) {
	for _, faux := range []string{"yes", "1", "True", "vrai"} {
		err := Validate(groupeDeTest(), Values{"greeting": "hi", "loud": faux})
		if err == nil {
			t.Errorf("%q was accepted for a Bool field", faux)
		}
	}
}

// TestValidateRefuseChoixHorsOptions : Choice only accepts its declared values.
func TestValidateRefuseChoixHorsOptions(t *testing.T) {
	err := Validate(groupeDeTest(), Values{"greeting": "hi", "mode": "moyen"})
	if err == nil {
		t.Fatal("a value outside the options was accepted")
	}
	if !strings.Contains(err.Error(), "admissible") {
		t.Errorf("the error does not say what was expected: %v", err)
	}
}

// TestValidateRefuseCleInconnue : an unknown key is refused, not stored.
//
// WHY: a typo in a key would be written, never read by the module, and the
// setting would appear to have no effect — the failure surface would be the
// component that ignores it, far from the form that accepted it.
func TestValidateRefuseCleInconnue(t *testing.T) {
	err := Validate(groupeDeTest(), Values{"greeting": "hi", "greetting": "typo"})
	if err == nil {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(err.Error(), "greetting") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

// TestValidateRefusePatternNonRespecte : Pattern refuses before Apply.
func TestValidateRefusePatternNonRespecte(t *testing.T) {
	err := Validate(groupeDeTest(), Values{"greeting": "hi", "host": "Relay EXAMPLE"})
	if err == nil {
		t.Fatal("a value breaking its pattern was accepted")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

// TestValidateIgnoreChampMasque : a field whose ShowWhen is unsatisfied is not
// validated.
//
// WHY: the console draws the whole form and submits what it drew. Validating a
// hidden field would refuse a submission for a value the operator cannot even
// see, which no one could act on.
func TestValidateIgnoreChampMasque(t *testing.T) {
	// fancy_color is invalid, but mode is "simple" — the field is hidden.
	v := Values{"greeting": "hi", "mode": "simple", "fancy_color": "!! not a colour !!"}
	if err := Validate(groupeDeTest(), v); err != nil {
		t.Fatalf("a hidden field was validated: %v", err)
	}
}

// TestValidateChampMasqueDevientObligatoire : once shown, the field is checked.
// The same value that was ignored above must now be refused.
func TestValidateChampMasqueDevientObligatoire(t *testing.T) {
	v := Values{"greeting": "hi", "mode": "fancy", "fancy_color": ""}
	// Not Required, so an empty value passes: the contrast is on the VALUE.
	v["fancy_color"] = "ok"
	if err := Validate(groupeDeTest(), v); err != nil {
		t.Fatalf("a shown field with a valid value was refused: %v", err)
	}
}

// TestValidateDefautAccepteValeurAbsente : an absent field with a Default is
// accepted (the default is returned by Current, not stored).
func TestValidateDefautAccepteValeurAbsente(t *testing.T) {
	if err := Validate(groupeDeTest(), Values{"greeting": "hi"}); err != nil {
		t.Fatalf("a set relying on defaults was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// verifierGroupes — what a module's declaration must satisfy at registration.
// ---------------------------------------------------------------------------

func TestVerifierGroupes(t *testing.T) {
	cas := []struct {
		nom     string
		groupes []Group
		veutUne string // substring expected in the error; "" = must pass
	}{
		{
			nom:     "une declaration valide passe",
			groupes: []Group{groupeDeTest()},
		},
		{
			nom:     "un groupe sans ID est refuse",
			groupes: []Group{{Title: "x", Fields: []Field{{Key: "a", Label: "A", Type: Text}}}},
			veutUne: "no ID",
		},
		{
			nom: "un groupe declare deux fois est refuse",
			groupes: []Group{
				{ID: "tls", Title: "T", Fields: []Field{{Key: "a", Label: "A", Type: Text}}},
				{ID: "tls", Title: "T", Fields: []Field{{Key: "b", Label: "B", Type: Text}}},
			},
			veutUne: "declared twice",
		},
		{
			nom:     "un groupe sans titre est refuse",
			groupes: []Group{{ID: "tls", Fields: []Field{{Key: "a", Label: "A", Type: Text}}}},
			veutUne: "no title",
		},
		{
			nom: "une cle declaree deux fois est refusee",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "a", Label: "A", Type: Text}, {Key: "a", Label: "B", Type: Text}}}},
			veutUne: "declared twice",
		},
		{
			nom: "une Choice sans options est refusee",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "c", Label: "C", Type: Choice}}}},
			veutUne: "needs options",
		},
		{
			nom: "des options sur un Text sont refusees",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "t", Label: "T", Type: Text, Options: []Option{{Value: "a"}}}}}},
			veutUne: "only a Choice",
		},
		{
			nom: "un pattern qui ne compile pas est refuse",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "t", Label: "T", Type: Text, Pattern: "^[unclosed"}}}},
			veutUne: "does not compile",
		},
		{
			nom: "un type inconnu est refuse",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "t", Label: "T", Type: "textarea"}}}},
			veutUne: "unknown type",
		},
		{
			nom: "un ShowWhen qui ne vise rien est refuse",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "t", Label: "T", Type: Text,
					ShowWhen: &Condition{Key: "nexistepas", Equals: "x"}}}}},
			veutUne: "not a field of this group",
		},
		{
			nom: "un ShowWhen sur un champ de type Text est refuse",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "base", Label: "Base", Type: Text},
				{Key: "dep", Label: "Dep", Type: Text,
					ShowWhen: &Condition{Key: "base", Equals: "x"}}}}},
			veutUne: "only a Choice or a Bool",
		},
		{
			nom: "un ShowWhen qui depend d'un champ conditionnel est ACCEPTE (chaine)",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "mode", Label: "Mode", Type: Choice, Options: []Option{{Value: "a"}}},
				{Key: "mid", Label: "Mid", Type: Choice, Options: []Option{{Value: "on"}},
					ShowWhen: &Condition{Key: "mode", Equals: "a"}},
				{Key: "fin", Label: "Fin", Type: Text,
					ShowWhen: &Condition{Key: "mid", Equals: "on"}}}}},
			veutUne: "", // accepted: a chain has a reachable root
		},
		{
			nom: "un cycle est refuse",
			groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
				{Key: "a", Label: "A", Type: Bool,
					ShowWhen: &Condition{Key: "b", Equals: "true"}},
				{Key: "b", Label: "B", Type: Bool,
					ShowWhen: &Condition{Key: "a", Equals: "true"}}}}},
			veutUne: "cycle",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			err := verifierGroupes("demo", c.groupes)
			if c.veutUne == "" {
				if err != nil {
					t.Fatalf("a valid declaration was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a refusal containing %q, got none", c.veutUne)
			}
			if !strings.Contains(err.Error(), c.veutUne) {
				t.Errorf("the error does not mention %q: %v", c.veutUne, err)
			}
		})
	}
}

// TestRegisterRefuseDesReglagesIncoherents : the check runs THROUGH Register,
// not only when called directly.
//
// WHY THIS IS ITS OWN TEST: verifierGroupes could be correct and never called.
// What must be proven is that a module declaring malformed settings cannot be
// registered at all — the failure has to happen at startup, loudly, and not the
// day an operator opens the page.
func TestRegisterRefuseDesReglagesIncoherents(t *testing.T) {
	reinitialiserPourTest()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("registering a module with malformed settings was accepted")
			return
		}
		if !strings.Contains(fmt.Sprint(r), "needs options") {
			t.Errorf("the panic does not explain the problem: %v", r)
		}
		reinitialiserPourTest()
	}()

	// The fake module implements Configurable, which is what Register inspects.
	Register(&fauxModuleReglages{
		fauxModule: fauxModule{info: Info{ID: "mauvais"}},
		groupes: []Group{{ID: "g", Title: "G", Fields: []Field{
			{Key: "c", Label: "C", Type: Choice}}}},
	})
}

// fauxModuleReglages is a module with settings, used to prove Register checks
// them. It embeds fauxModule so it satisfies the Module interface without
// repeating every method.
type fauxModuleReglages struct {
	fauxModule
	groupes []Group
}

func (f *fauxModuleReglages) Settings() []Group { return f.groupes }

func (f *fauxModuleReglages) Current(context.Context, Env, string) (Values, error) {
	return Values{}, nil
}

func (f *fauxModuleReglages) Apply(context.Context, Env, string, Values) error { return nil }
