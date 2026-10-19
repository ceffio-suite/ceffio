//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package demo

// The demo module's SETTINGS, and the proof that goes with them.
//
// WHY THIS FILE EXISTS: installing, observing and removing a feature already
// needed only its own package. SETTINGS did not — they were written by hand in
// the console, so the next feature with settings would have forced a console
// change. The module now DECLARES a group here, and the console, the CLI and
// the installer draw, validate, store and apply it without knowing what it
// means.
//
// WHAT IT COVERS, on purpose: every field type the contract offers (text,
// choice, secret, bool) and a ShowWhen, so a break in any of them shows up on
// a module that costs nothing to install. A module covering only a text field
// would leave the other four untested end to end.
//
// WHERE THE VALUES GO: the module's ConfigMap, like its other state. WHY NOT
// internal/settings: the default store would work, but writing them HERE makes
// the point of the test sharper — the module keeps its own state in its own
// object, exactly as a real feature would, and the settings contract never
// assumes anything about where a module puts them.

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	// groupeGreeting is the settings group this module declares.
	groupeGreeting = "greeting"
	// cleReglages is the ConfigMap key holding the group's values, as JSON.
	cleReglages = "settings.greeting"
)

// Settings declares the module's group.
//
// It is STATIC — no cluster read: the console draws a form for a module it has
// never installed, and a declaration that reached the cluster would make that
// impossible.
func (m *demoModule) Settings() []module.Group {
	return []module.Group{{
		ID:          groupeGreeting,
		Title:       "Greeting",
		Description: "How the demonstration module greets. It has no effect on the platform: the values are stored and read back, which is what the module exists to prove.",
		Fields: []module.Field{
			{
				Key:      "message",
				Label:    "Message",
				Help:     "The text the module stores. Required: an empty message is the one case the check below refuses.",
				Type:     module.Text,
				Required: true,
				Default:  "hello",
			},
			{
				Key:   "mode",
				Label: "Mode",
				Help:  "A choice, to exercise the select. \"fancy\" reveals the colour field below.",
				Type:  module.Choice,
				Options: []module.Option{
					{Value: "simple", Label: "Simple"},
					{Value: "fancy", Label: "Fancy"},
				},
				Default: "simple",
			},
			{
				Key:      "colour",
				Label:    "Colour",
				Help:     "Only asked for in fancy mode. It carries a pattern, so a malformed value is refused before anything is stored.",
				Type:     module.Text,
				Pattern:  `^#?[0-9A-Fa-f]{3,6}$`,
				ShowWhen: &module.Condition{Key: "mode", Equals: "fancy"},
			},
			{
				Key:   "token",
				Label: "Token",
				Help:  "A secret: it is never sent back to a page or to a terminal. Leaving it empty keeps the stored value.",
				Type:  module.Secret,
			},
			{
				Key:     "loud",
				Label:   "Loud",
				Help:    "A checkbox, to exercise the boolean.",
				Type:    module.Bool,
				Default: "false",
			},
		},
	}}
}

// Current reads the group's values from the ConfigMap.
//
// THE SECRET IS MASKED HERE, and this is the only place it could be read on
// behalf of a frontend. Answering module.SecretSet when a value is stored — and
// never the value — is what makes the rule hold for the console AND the CLI at
// once: neither of them has to remember it.
func (m *demoModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if env.Kube == nil {
		return nil, fmt.Errorf("demo: no Kubernetes client in the environment")
	}
	if _, ok := m.groupeDe(groupe); !ok {
		return nil, fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	g, _ := m.groupeDe(groupe)

	// The defaults are the starting point: an unset field answers what it
	// declares, and the default is RETURNED, never written — storing it would
	// freeze it, and changing it later would not reach existing installations.
	out := module.Values{}
	for _, f := range g.Fields {
		out[f.Key] = f.Default
	}

	cm, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Not installed yet: the defaults, with every secret unset.
		for _, f := range g.Fields {
			if f.Type == module.Secret {
				out[f.Key] = ""
			}
		}
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("demo: reading ConfigMap %s/%s: %w", nsSystem, configMapName, err)
	}

	stoc, err := lireReglages(cm.Data[cleReglages], g)
	if err != nil {
		return nil, err
	}
	for cle, v := range stoc {
		for _, f := range g.Fields {
			if f.Key != cle {
				continue
			}
			if f.Type == module.Secret {
				// A stored secret is reported as Set, whatever its value.
				if v != "" {
					out[cle] = module.SecretSet
				} else {
					out[cle] = ""
				}
				continue
			}
			out[cle] = v
		}
	}
	// A secret NEVER stored must read as unset, not as the default (a Secret
	// field declares none, but a module that did would still be wrong here).
	for _, f := range g.Fields {
		if f.Type == module.Secret {
			if _, ok := stoc[f.Key]; !ok {
				out[f.Key] = ""
			}
		}
	}
	return out, nil
}

// Apply validates, stores and reflects the values.
//
// THE EMPTY-SECRET RULE is honoured here, as it must be by every module: an
// empty secret keeps the stored one. This module implements its own storage, so
// it also implements its own rule — which is exactly why the rule is written in
// the contract AND demonstrated in code.
func (m *demoModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if env.Kube == nil {
		return fmt.Errorf("demo: no Kubernetes client in the environment")
	}
	g, ok := m.groupeDe(groupe)
	if !ok {
		return fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	// The contract's validation runs HERE, and the shared implementation is
	// called rather than re-implemented: a frontend that forgot to validate
	// must not be able to store something no other frontend would accept.
	if err := module.Validate(g, v); err != nil {
		return err
	}

	// What is already stored, so an empty secret can keep it.
	existants, err := m.Current(ctx, env, groupe)
	if err != nil {
		return err
	}

	// MERGE, then replace the group's entry. The other keys of the ConfigMap
	// belong to the module's Install (module, purpose) and must survive.
	cm, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("demo: not installed: install the module before saving its settings")
	}
	if err != nil {
		return err
	}

	aEcrire := map[string]string{}
	for _, f := range g.Fields {
		val := v[f.Key]
		if f.Type == module.Secret {
			// An empty secret KEEPS the stored one; the placeholder the
			// console received is not a value either.
			if strings.TrimSpace(val) == "" || val == module.SecretSet {
				if existants[f.Key] == module.SecretSet {
					// Read back from the ConfigMap: the placeholder means
					// "there is one", and the value is the one already stored.
					ancien, _ := lireReglages(cm.Data[cleReglages], g)
					aEcrire[f.Key] = ancien[f.Key]
				}
				continue
			}
		}
		aEcrire[f.Key] = val
	}

	poids, err := encoderReglages(aEcrire)
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[cleReglages] = poids
	if _, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("demo: writing settings into %s/%s: %w", nsSystem, configMapName, err)
	}
	return nil
}

// groupeDe returns the declared group with that ID.
func (m *demoModule) groupeDe(id string) (module.Group, bool) {
	for _, g := range m.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// Test checks the values without storing anything.
//
// WHY A MODULE WITH NOTHING TO CONNECT STILL HAS ONE: the demonstration module
// has no service of its own, but it has a value that must not be empty — and
// covering the path end to end is the point. It also exercises the STEPS, which
// the console displays when a check fails.
func (m *demoModule) Test(_ context.Context, _ module.Env, groupe string, v module.Values) module.TestResult {
	r := module.TestResult{Steps: []string{
		"reading the submitted values",
		"checking the message is not empty",
	}}
	if _, ok := m.groupeDe(groupe); !ok {
		r.Detail = "unknown group: " + groupe
		return r
	}
	if strings.TrimSpace(v["message"]) == "" {
		r.Steps = append(r.Steps, "message is empty")
		r.Detail = "the message must not be empty"
		return r
	}
	r.OK = true
	r.Steps = append(r.Steps, "message is set")
	r.Detail = "the message is set: nothing to connect to, this is all the check can say"
	return r
}
