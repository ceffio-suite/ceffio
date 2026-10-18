// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// Generic module endpoints: ONE page and ONE API for every registry module,
// replacing the hand-written HaRP and transcription handlers.
//
// WHY generic: each hand-written panel duplicated the same state/action
// plumbing and drifted (different JSON shapes, different blocking rules).
// The registry already carries everything the console needs — Info for the
// display, State for the truth, Blocked for the greyed-out button — so the
// endpoints only have to walk it. A new Optional module now appears in the
// console without any code change here or in web/index.html.

// moduleAll is the seam through which the console reads the registry.
//
// WHY a variable and not a direct module.All call in every handler:
// internal/console CANNOT import internal/modules — the package
// internal/modules/console imports internal/console (it wraps
// console.Deploy), so a blank import here would be an import cycle. At
// runtime the registry is already filled when the console starts, because
// cmd/ceffio blank-imports internal/modules. Tests swap this variable for a
// fake registry.
var moduleAll = module.All

// moduleByID finds a registered module by its registry identifier.
func moduleByID(id string) (module.Module, bool) {
	for _, m := range moduleAll() {
		if m.Info().ID == id {
			return m, true
		}
	}
	return nil, false
}

// moduleView is the JSON shape of a module for the browser: the registry
// Info WITHOUT Permissions, plus the observed State and the blocking reason.
//
// WHY Permissions is left out: the RBAC rules are an installer concern —
// they describe what the console's service account needs, not what the
// operator chooses. Serializing them would expose the cluster's permission
// model to every browser holding the admin key, for no display value.
type moduleView struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Kind        string           `json:"kind"` // "core" | "optional"
	Default     bool             `json:"default"`
	Requires    []string         `json:"requires,omitempty"`
	Namespaces  []string         `json:"namespaces,omitempty"`
	Services    []module.Service `json:"services,omitempty"`
	Resources   string           `json:"resources,omitempty"`
	Warning     string           `json:"warning,omitempty"`
	State       module.State     `json:"state"`
	Blocked     string           `json:"blocked,omitempty"`
}

// kindName serializes the Kind: the browser filters the module cards on
// "optional", and a raw integer would encode the meaning of module.Core in
// JavaScript.
func kindName(k module.Kind) string {
	if k == module.Core {
		return "core"
	}
	return "optional"
}

// moduleEnv builds the environment handed to registry modules: the shared
// Kubernetes client and the console domain. Out is chosen per call — the
// operation journal for install/uninstall, io.Discard for read-only state.
func (s *Server) moduleEnv(out io.Writer) module.Env {
	return module.Env{Domain: s.Domain, Kube: s.kube, Out: out}
}

// viewFor builds the browser view of one module.
//
// While an operation runs, the cluster is NOT read: the answer IS the
// operation (installing/removing). Reading the cluster mid-install would
// report a half-existing state as the truth, and the exec-based state reads
// (live transcription queries AppAPI through occ) are far too expensive for
// an endpoint the page polls every 3 s.
func (s *Server) viewFor(ctx context.Context, m module.Module) moduleView {
	info := m.Info()
	v := moduleView{
		ID:          info.ID,
		Title:       info.Title,
		Description: info.Description,
		Kind:        kindName(info.Kind),
		Default:     info.Default,
		Requires:    info.Requires,
		Namespaces:  info.Namespaces,
		Services:    info.Services,
		Resources:   info.Resources,
		Warning:     info.Warning,
	}
	if op, ok := s.ops.current(info.ID); ok && op.running {
		status := module.Installing
		if op.action == actionUninstall {
			status = module.Removing
		}
		v.State = module.State{
			Status: status,
			Detail: "operation started at " + op.startedAt.Format(time.RFC3339),
		}
		// Blocking further actions while one runs: the server would answer
		// 409 anyway, but the page can say why the buttons are greyed out.
		v.Blocked = "an operation is already in progress"
		return v
	}
	env := s.moduleEnv(io.Discard)
	v.State = m.State(ctx, env)
	v.Blocked = module.Blocked(ctx, env, m)
	return v
}

// handleModulesList serves GET /api/modules: every registered module, with
// its state and its blocking reason.
func (s *Server) handleModulesList(w http.ResponseWriter, r *http.Request) {
	views := make([]moduleView, 0, 16)
	for _, m := range moduleAll() {
		views = append(views, s.viewFor(r.Context(), m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": views})
}

// handleModuleDetail serves GET /api/modules/{id}.
func (s *Server) handleModuleDetail(w http.ResponseWriter, r *http.Request) {
	s.moduleDetail(w, r, r.PathValue("id"))
}

// moduleActionRequest is the body of POST /api/modules/{id}.
type moduleActionRequest struct {
	Action string `json:"action"` // "install" | "uninstall"
}

// handleModuleAction serves POST /api/modules/{id}: start an asynchronous
// install/uninstall. See module_ops.go for WHY it is asynchronous (202 +
// journal) instead of a synchronous request the proxy would cut.
func (s *Server) handleModuleAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, ok := moduleByID(id)
	if !ok {
		apiErr(w, http.StatusNotFound, "unknown module: "+id)
		return
	}

	var req moduleActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErr(w, http.StatusBadRequest, "unreadable body: "+err.Error())
		return
	}
	switch req.Action {
	case "install", "uninstall":
	default:
		apiErr(w, http.StatusBadRequest,
			"unknown action: "+req.Action+" (expected: install or uninstall)")
		return
	}

	// A Core module is the product itself: removing it from the console
	// would take the platform apart underneath the operator (and the
	// console, which is Core too, would be cutting its own branch). The
	// refusal lives server-side, not in a greyed-out button: a page opened
	// before a state change — or a direct API call — must hit the same rule.
	if m.Info().Kind == module.Core && req.Action == "uninstall" {
		apiErr(w, http.StatusForbidden,
			"module "+id+" is part of the core suite and cannot be uninstalled from the console")
		return
	}

	// One operation at a time per module: a second request while one runs
	// gets 409. tryStart checks and marks busy atomically, so two
	// concurrent POSTs cannot both be accepted.
	if _, free := s.ops.tryStart(id, action(req.Action)); !free {
		apiErr(w, http.StatusConflict,
			"an operation is already running on module "+id)
		return
	}
	s.runOperation(id, m, action(req.Action))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": true,
		"module":   id,
		"action":   req.Action,
		"message":  "operation started — follow its progress on GET /api/modules/" + id,
	})
}

// moduleDetail is the shared body of the detail endpoint and of the
// deprecated aliases: one module view plus its last operation (journal
// included), whether that operation is still running or finished.
func (s *Server) moduleDetail(w http.ResponseWriter, r *http.Request, id string) {
	m, ok := moduleByID(id)
	if !ok {
		apiErr(w, http.StatusNotFound, "unknown module: "+id)
		return
	}
	resp := map[string]any{"module": s.viewFor(r.Context(), m)}
	if op, ok := s.ops.current(id); ok {
		resp["operation"] = op.view()
	}
	writeJSON(w, http.StatusOK, resp)
}
