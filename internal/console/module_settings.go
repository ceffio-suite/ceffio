// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// This file serves the GENERIC settings API: it knows nothing about TLS, SMTP or
// any other feature. It asks the module for its groups, hands the values to the
// page, validates and applies what comes back.
//
// WHY GENERIC, AND WHY IT MATTERS: the TLS page and the SMTP page were written
// by hand here, so a new feature with settings forced a console change. After
// this file, a feature is added by writing its own package: it declares its
// groups, and this route serves them. THE OBJECTIVE IS TESTABLE — a test checks
// that no module ID appears in this file or in the page, and that the registered
// routes belong to a closed list.
//
// WHAT THIS FILE MUST NEVER DO: return a secret's value. module.Values carries
// module.SecretSet for a stored secret, and the module's Current is responsible
// for that — but this layer serialises the answer, so it is the last place where
// a leak would be invisible.

// settingsView is what GET /api/modules/{id}/settings returns.
type settingsView struct {
	Module   string      `json:"module"`
	Groups   []groupView `json:"groups"`
	Testable bool        `json:"testable"`
	// Editable says whether the module is installed. A group shown for a module
	// that is not installed would be applied to nothing: Apply writes settings
	// a component that does not exist would read.
	Editable bool `json:"editable"`
}

// groupView is one group, with its fields and current values.
type groupView struct {
	module.Group
	// Values are the current settings. A Secret field carries module.SecretSet
	// or "" — never the value.
	Values module.Values `json:"values"`
	// Testable is per GROUP, not per module: a module can have one group that
	// can be checked and another that cannot.
	Testable bool `json:"testable"`
}

// handleModuleSettings serves GET /api/modules/{id}/settings.
func (s *Server) handleModuleSettings(w http.ResponseWriter, r *http.Request) {
	m, ok := moduleByID(r.PathValue("id"))
	if !ok {
		apiErr(w, http.StatusNotFound, "unknown module: "+r.PathValue("id"))
		return
	}
	cfg, ok := m.(module.Configurable)
	if !ok {
		// A module without settings answers 404 rather than an empty list: the
		// page asks for every module and must be able to tell "no settings"
		// from "settings that failed to load".
		apiErr(w, http.StatusNotFound, "module has no settings: "+r.PathValue("id"))
		return
	}

	env := s.moduleEnvReadOnly(m)
	vue := settingsView{Module: m.Info().ID, Testable: false, Editable: m.State(r.Context(), env).Status == module.Installed}
	_, testable := m.(module.Testable)

	for _, g := range cfg.Settings() {
		vals, err := cfg.Current(r.Context(), env, g.ID)
		if err != nil {
			// A group that fails to read is REPORTED with its error, and the
			// others are still served: a corrupted entry in one group must not
			// make the whole settings page unusable.
			vue.Groups = append(vue.Groups, groupView{Group: g, Testable: testable, Values: module.Values{
				"_error": err.Error(),
			}})
			continue
		}
		if vals == nil {
			vals = module.Values{}
		}
		vue.Groups = append(vue.Groups, groupView{Group: g, Testable: testable, Values: vals})
	}
	writeJSON(w, http.StatusOK, vue)
}

// handleModuleSettingsSave serves POST /api/modules/{id}/settings/{group}.
func (s *Server) handleModuleSettingsSave(w http.ResponseWriter, r *http.Request) {
	m, cfg, env, group, ok := s.resoudreReglages(w, r)
	if !ok {
		return
	}

	var valeurs module.Values
	if err := json.NewDecoder(r.Body).Decode(&valeurs); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	// The placeholder must not be written as a value: the page sends it back
	// for a secret the operator did not touch. Only the FIRST full settings
	// group is checked; wherever the placeholder came from, storing it would
	// replace a working credential with "••••".
	if err := cfg.Apply(r.Context(), env, group, valeurs); err != nil {
		if errors.Is(err, module.ErrInvalidSettings) || errors.Is(err, module.ErrUnknownGroup) {
			apiErr(w, http.StatusBadRequest, err.Error())
			return
		}
		apiErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The answer carries the NEW current values, so the page does not have to
	// re-read them: a secret it just saved comes back as the placeholder, and
	// the operator sees that it is now stored.
	apres, err := cfg.Current(r.Context(), env, group)
	if err != nil {
		apres = module.Values{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"module": m.Info().ID, "group": group, "values": apres,
	})
}

// handleModuleSettingsTest serves POST /api/modules/{id}/settings/{group}/test.
//
// It STORES NOTHING: an operator checks a relay before saving it, and a failed
// check must not leave an invalid configuration behind.
func (s *Server) handleModuleSettingsTest(w http.ResponseWriter, r *http.Request) {
	m, _, env, group, ok := s.resoudreReglages(w, r)
	if !ok {
		return
	}
	testable, ok := m.(module.Testable)
	if !ok {
		apiErr(w, http.StatusNotFound, "module has no test for its settings: "+m.Info().ID)
		return
	}

	var valeurs module.Values
	if err := json.NewDecoder(r.Body).Decode(&valeurs); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	// The values are validated first, so a typo is reported as a field error
	// rather than as a connection failure the operator would chase.
	if cfg, ok := m.(module.Configurable); ok {
		for _, g := range cfg.Settings() {
			if g.ID != group {
				continue
			}
			if err := module.Validate(g, valeurs); err != nil {
				apiErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, testable.Test(r.Context(), env, group, valeurs))
}

// resoudreReglages resolves the module, its Configurable interface, the Env and
// the group named in the path — the four checks every settings route needs.
//
// It writes the error itself and answers false, so the three handlers above
// share one error policy instead of repeating it: an unknown module, a module
// without settings and an unknown group are all 404, and the message names what
// was asked.
func (s *Server) resoudreReglages(w http.ResponseWriter, r *http.Request) (
	module.Module, module.Configurable, module.Env, string, bool,
) {
	id := r.PathValue("id")
	groupe := r.PathValue("group")
	m, ok := moduleByID(id)
	if !ok {
		apiErr(w, http.StatusNotFound, "unknown module: "+id)
		return nil, nil, module.Env{}, "", false
	}
	cfg, ok := m.(module.Configurable)
	if !ok {
		apiErr(w, http.StatusNotFound, "module has no settings: "+id)
		return nil, nil, module.Env{}, "", false
	}
	for _, g := range cfg.Settings() {
		if g.ID == groupe {
			return m, cfg, s.moduleEnvReadOnly(m), groupe, true
		}
	}
	apiErr(w, http.StatusNotFound, "unknown settings group: "+id+"/"+groupe)
	return nil, nil, module.Env{}, "", false
}
