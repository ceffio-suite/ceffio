// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// WHY THIS FILE EXISTS, and what it changes for the product.
//
// Installing, observing and removing a feature already needed only its own
// package: a new module touches its folder and one import line. SETTINGS did
// not. The TLS page and the SMTP page were written by hand inside the console,
// so the next feature with operator settings would have forced a console change
// again — the promise held for the module, not for what the module needs
// configured.
//
// After this file, a feature that has settings is added by writing its package:
// it DECLARES its groups and fields here, and the console, the CLI and the
// installer draw, validate, store and apply them without knowing what they
// mean.
//
// WHERE THE LINE IS DRAWN: this package describes settings — their shape, their
// constraints, how they are read. It does NOT store them (internal/settings
// does) and does not draw them (the console does). Keeping the description here
// is what lets every frontend share ONE definition; a description living in a
// frontend would be re-implemented by the next one.
//
// NO DEPENDENCY ON ANOTHER INTERNAL PACKAGE. This is a rule, not a preference:
// every module imports this package, so anything imported here becomes a
// dependency of every module — including on packages that modules must not
// reach (the console, the CLI). It is verified by a test.

// FieldType is the closed set of input kinds the console knows how to draw.
//
// WHY A CLOSED SET: the console must draw a form for a field it has never seen.
// An open set would mean frontends silently ignoring an unknown type, and a
// setting that cannot be edited is worse than one that does not exist — it looks
// configured. Adding a type is a contract change: declared here, drawn once in
// the console, and the day a module needs one of the remaining kinds, the
// contract is EXTENDED rather than the console specialised. A module-specific
// form is exactly what this file exists to prevent.
type FieldType string

const (
	// Text is a single-line free-form string.
	Text FieldType = "text"
	// Number is an integer. Not a float: a setting that needs decimals is a
	// setting whose unit should be changed (a duration in milliseconds rather
	// than seconds), which keeps it readable in a ConfigMap.
	Number FieldType = "number"
	// Bool is a checkbox.
	Bool FieldType = "bool"
	// Choice is a `<select>`; Options carries the admissible values.
	Choice FieldType = "choice"
	// Secret is write-only: it is never sent back to a browser. `Current`
	// answers SecretSet instead of the value, and an empty value on save means
	// "keep the stored one" rather than "erase it".
	Secret FieldType = "secret"
)

// SecretSet is what a Set secret looks like to a frontend.
//
// WHY A PLACEHOLDER AND NOT A BOOLEAN: the console draws the field from the
// value it receives. Returning the placeholder in the value slot means the
// drawing code is the same for every field, and that the page can say "already
// stored, leave empty to keep it" without a second flag to interpret.
const SecretSet = "••••"

// Option is one admissible value of a Choice field.
//
// The Label is what the operator reads; the Value is what is stored. They are
// separate because the stored value is read by code (a provider name, a
// challenge name) while the label is read by a human ("DNS-01 (wildcard
// certificates)").
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Condition shows a field only when another field of the same group holds a
// given value.
//
// WHY IT IS DECLARED AND NOT LEFT TO THE FRONTEND: the DNS provider fields only
// make sense once the challenge is dns01. A frontend that decided this itself
// would hard-code one module's logic — the drift this contract prevents. The
// module states the condition; every frontend applies it identically.
type Condition struct {
	Key    string `json:"key"`
	Equals string `json:"equals"`
}

// Field is one setting.
type Field struct {
	// Key is the stable identifier, snake_case: "relay_host". It is the key in
	// the stored JSON and the name in `ceffio module config key=value`, so it
	// must not follow a label that may be reworded.
	Key   string `json:"key"`
	Label string `json:"label"`
	// Help is one sentence, shown under the field. Empty means no help.
	Help string    `json:"help,omitempty"`
	Type FieldType `json:"type"`
	// Options is required for Choice and refused for every other type: a
	// select without values cannot be drawn.
	Options []Option `json:"options,omitempty"`
	// Default is what an unset field reads as. It is returned by Current, not
	// written on install: storing a default would freeze it, and changing the
	// default later would not reach existing installations.
	Default string `json:"default,omitempty"`
	// Required refuses an empty value in Validate. A Secret field that already
	// has a stored value is never "empty" — see Validate.
	Required bool `json:"required,omitempty"`
	// Pattern is an optional regexp checked before Apply, so a malformed value
	// is refused with the field's name rather than failing later, in a
	// component that reports it as its own problem.
	Pattern string `json:"pattern,omitempty"`
	// ShowWhen hides the field until another one holds a value.
	ShowWhen *Condition `json:"show_when,omitempty"`
}

// Group is a set of settings shown as one form.
//
// A module can declare several: the ingress module has `tls` for certificates
// and would have another if it gained separate concerns. Each group is stored,
// validated and applied as a unit.
type Group struct {
	// ID is stable and snake_case: "tls", "relay", "outgoing_mail". It appears
	// in the console route and in the storage path, so it must not follow a
	// title that may be reworded.
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Fields      []Field `json:"fields"`
}

// Values are settings as strings, whatever their declared type.
//
// WHY EVERYTHING IS A STRING: the values come from an HTML form, from a
// command line and from a ConfigMap — three string carriers. Converting at the
// edges (Validate parses, Apply converts) keeps one representation, instead of
// three types crossing the contract and each frontend converting on its own.
type Values map[string]string

// Configurable is implemented by modules that have operator settings.
//
// IT IS OPTIONAL: a module without settings implements nothing and the Module
// interface does not change. Making it a method on Module would force every
// module to write three empty methods to say "I have no settings", and would
// make the contract pay for the exception.
type Configurable interface {
	// Settings describes the groups this module exposes. It is static: the
	// console draws from it without installing anything, so it must not read
	// the cluster.
	Settings() []Group

	// Current returns the stored values of one group.
	//
	// A Secret field answers SecretSet when set and "" when unset — NEVER the
	// value itself. This is the one place where the rule is enforced, because
	// this is the only function that reads a secret on behalf of a frontend; a
	// caller that leaks it here leaks it to every frontend at once.
	Current(ctx context.Context, env Env, group string) (Values, error)

	// Apply validates, stores and applies one group.
	//
	// TWO RESPONSIBILITIES, and both are the module's: it knows where its
	// settings belong (a module whose credential is read by another component
	// must write it where that component reads) and how to make the change
	// effective (restarting a workload, updating a ClusterIssuer, running occ).
	//
	// An empty Secret means KEEP THE STORED ONE, so a form can be re-saved
	// without retyping a password. A module that cannot tell "empty" from
	// "erase" would force every operator to retype every secret to change a
	// port.
	Apply(ctx context.Context, env Env, group string, v Values) error
}

// TestResult is what a settings check reports.
type TestResult struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Steps is what was tried, in order. It is kept because a check that fails
	// is only useful if the operator can see WHERE it failed: "could not reach
	// the relay" without the steps leaves them guessing between the hostname,
	// the port and the credential.
	Steps []string `json:"steps,omitempty"`
}

// Testable is implemented by groups that can be checked before saving.
//
// WHY A SEPARATE INTERFACE AND NOT A METHOD ON Configurable: verification is
// not possible for every setting. A colour has nothing to test; a credential
// does. Forcing Test on a module with nothing to verify produces a button that
// always answers "OK", which teaches the operator to ignore it.
//
// A group that cannot be checked simply does not implement this, and the
// console shows no Test button rather than a misleading one.
type Testable interface {
	Test(ctx context.Context, env Env, group string, v Values) TestResult
}

// Erreurs de validation, exportées pour que les frontaux n'aient pas à
// analyser un message.
var (
	// ErrUnknownGroup is returned when a frontend asks for a group the module
	// does not declare.
	ErrUnknownGroup = errors.New("unknown settings group")
	// ErrInvalidSettings wraps every validation failure; use errors.Unwrap or
	// the message, which always names the field.
	ErrInvalidSettings = errors.New("invalid settings")
)

// Validate checks values against a group's fields.
//
// IT IS CALLED BY EVERY FRONTEND BEFORE Apply, so that a malformed value is
// refused identically whether it came from a form or from a command line —
// without this, each frontend would implement its own partial check, and a
// setting could be accepted in one place and refused in the other.
//
// An EMPTY SECRET IS ACCEPTED even when Required: it means "keep the stored
// value". Whether a value is actually stored is the module's business — it says
// so through Current — and rejecting here would make it impossible to save a
// form without retyping every password.
func Validate(g Group, v Values) error {
	connus := make(map[string]Field, len(g.Fields))
	for _, f := range g.Fields {
		connus[f.Key] = f
	}

	// Unknown keys are REFUSED, not ignored: a typo in a key would otherwise be
	// stored, never read, and the setting would appear to have no effect.
	for cle := range v {
		if _, ok := connus[cle]; !ok {
			return fmt.Errorf("%w: %s.%s: unknown field", ErrInvalidSettings, g.ID, cle)
		}
	}

	for _, f := range g.Fields {
		brut, fourni := v[f.Key]
		brut = strings.TrimSpace(brut)

		// A hidden field is not validated: its value is not meant to be read.
		// Refusing it would break a form that submits every field it drew.
		if f.ShowWhen != nil && v[f.ShowWhen.Key] != f.ShowWhen.Equals {
			continue
		}

		secreteVide := f.Type == Secret && brut == ""

		if brut == "" {
			if f.Required && !secreteVide {
				return fmt.Errorf("%w: %s.%s (%s) is required",
					ErrInvalidSettings, g.ID, f.Key, f.Label)
			}
			if !fourni && f.Default != "" {
				// Not provided and no default: nothing to check.
				continue
			}
			if brut == "" {
				continue
			}
		}

		switch f.Type {
		case Number:
			if _, err := strconv.Atoi(brut); err != nil {
				return fmt.Errorf("%w: %s.%s (%s) must be a whole number, got %q",
					ErrInvalidSettings, g.ID, f.Key, f.Label, brut)
			}
		case Bool:
			if brut != "true" && brut != "false" {
				return fmt.Errorf("%w: %s.%s (%s) must be true or false, got %q",
					ErrInvalidSettings, g.ID, f.Key, f.Label, brut)
			}
		case Choice:
			trouve := false
			for _, o := range f.Options {
				if o.Value == brut {
					trouve = true
					break
				}
			}
			if !trouve {
				return fmt.Errorf("%w: %s.%s (%s): %q is not one of the admissible values",
					ErrInvalidSettings, g.ID, f.Key, f.Label, brut)
			}
		case Text, Secret:
			// No type constraint beyond the optional pattern below.
		default:
			return fmt.Errorf("%w: %s.%s (%s) has an unknown type %q",
				ErrInvalidSettings, g.ID, f.Key, f.Label, f.Type)
		}

		if f.Pattern != "" {
			re, err := regexp.Compile(f.Pattern)
			if err != nil {
				// A pattern that does not compile is a programming error in the
				// module; the registry test catches it at startup, but refusing
				// here is what protects a caller that skipped the registry
				// check.
				return fmt.Errorf("%w: %s.%s has a pattern that does not compile: %v",
					ErrInvalidSettings, g.ID, f.Key, err)
			}
			if !re.MatchString(brut) {
				return fmt.Errorf("%w: %s.%s (%s): %q does not match %s",
					ErrInvalidSettings, g.ID, f.Key, f.Label, brut, f.Pattern)
			}
		}
	}
	return nil
}

// verifierGroupes controls the coherence of the groups a module declares.
//
// IT RUNS AT STARTUP, through the registry, for the same reason module IDs are
// checked there: a malformed declaration is a programming error, and it must
// fail loudly at boot rather than produce a form that cannot be drawn or a
// setting that is stored but never read. A Choice without options, a duplicate
// key or a ShowWhen pointing nowhere are all invisible until someone opens the
// page — hours later, on the operator's installation.
func verifierGroupes(id string, groupes []Group) error {
	vusGroupe := map[string]bool{}
	for _, g := range groupes {
		if g.ID == "" {
			return fmt.Errorf("module %q: a settings group has no ID", id)
		}
		if vusGroupe[g.ID] {
			return fmt.Errorf("module %q: settings group %q is declared twice", id, g.ID)
		}
		vusGroupe[g.ID] = true
		if g.Title == "" {
			return fmt.Errorf("module %q: settings group %q has no title", id, g.ID)
		}

		cles := make(map[string]bool, len(g.Fields))
		for _, f := range g.Fields {
			if f.Key == "" {
				return fmt.Errorf("module %q group %q: a field has no key", id, g.ID)
			}
			if cles[f.Key] {
				return fmt.Errorf("module %q group %q: field %q is declared twice", id, g.ID, f.Key)
			}
			cles[f.Key] = true
			if f.Label == "" {
				return fmt.Errorf("module %q group %q: field %q has no label", id, g.ID, f.Key)
			}

			switch f.Type {
			case Text, Number, Bool, Secret:
				if len(f.Options) > 0 {
					return fmt.Errorf("module %q group %q field %q: only a Choice takes options",
						id, g.ID, f.Key)
				}
			case Choice:
				if len(f.Options) == 0 {
					return fmt.Errorf("module %q group %q field %q: a Choice needs options",
						id, g.ID, f.Key)
				}
				vusOption := map[string]bool{}
				for _, o := range f.Options {
					if o.Value == "" {
						return fmt.Errorf("module %q group %q field %q: an option has no value",
							id, g.ID, f.Key)
					}
					if vusOption[o.Value] {
						return fmt.Errorf("module %q group %q field %q: option %q is declared twice",
							id, g.ID, f.Key, o.Value)
					}
					vusOption[o.Value] = true
				}
			default:
				return fmt.Errorf("module %q group %q field %q: unknown type %q",
					id, g.ID, f.Key, f.Type)
			}

			if f.Pattern != "" {
				if _, err := regexp.Compile(f.Pattern); err != nil {
					return fmt.Errorf("module %q group %q field %q: pattern does not compile: %v",
						id, g.ID, f.Key, err)
				}
			}

			if f.ShowWhen != nil {
				if f.ShowWhen.Key == "" {
					return fmt.Errorf("module %q group %q field %q: ShowWhen has no key",
						id, g.ID, f.Key)
				}
				// The condition must point at a field that EXISTS IN THE SAME
				// GROUP: across groups it could never be satisfied, and the
				// field would stay invisible forever with no error anywhere.
				if !cles[f.ShowWhen.Key] {
					// The target may be declared after: look at the whole
					// group before refusing.
					existe := false
					for _, autre := range g.Fields {
						if autre.Key == f.ShowWhen.Key {
							existe = true
							break
						}
					}
					if !existe {
						return fmt.Errorf("module %q group %q field %q: ShowWhen points at %q, "+
							"which is not a field of this group", id, g.ID, f.Key, f.ShowWhen.Key)
					}
				}
			}
		}

		// Every ShowWhen target must exist, checked once the group is complete.
		for _, f := range g.Fields {
			if f.ShowWhen == nil {
				continue
			}
			if !cles[f.ShowWhen.Key] {
				return fmt.Errorf("module %q group %q field %q: ShowWhen points at %q, "+
					"which is not a field of this group", id, g.ID, f.Key, f.ShowWhen.Key)
			}
			// The condition must be reachable: a ShowWhen on a field that is
			// itself hidden can never be satisfied.
			for _, cible := range g.Fields {
				if cible.Key != f.ShowWhen.Key {
					continue
				}
				if cible.ShowWhen != nil {
					return fmt.Errorf("module %q group %q field %q: ShowWhen depends on %q, "+
						"which is itself conditional — the field could never appear",
						id, g.ID, f.Key, cible.Key)
				}
				if cible.Type != Choice && cible.Type != Bool {
					return fmt.Errorf("module %q group %q field %q: ShowWhen depends on %q, "+
						"a %s — only a Choice or a Bool has a value one can compare",
						id, g.ID, f.Key, cible.Key, cible.Type)
				}
			}
		}
	}
	return nil
}
