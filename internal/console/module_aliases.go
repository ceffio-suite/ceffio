// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"
)

// Deprecated aliases kept for browsers with a cached page and for scripts
// that predate the generic /api/modules endpoints.
//
// Deprecated: remove after v0.7 — the plan gives two minor releases of
// overlap (current version is v0.5.0) for operators to refresh their page
// or scripts; the console itself already uses /api/modules.
//
// WHY a pure delegation and not a copy of the old response: keeping two
// response shapes alive would keep two truths about the same module. The
// aliases answer with the SAME payload as GET/POST /api/modules/{id}, so a
// client reading either endpoint sees one state. Old field names
// (readyToInstall, weightNote…) are gone — the page shipped with this
// binary no longer asks for them.

// handleTranscriptionAlias serves /api/transcription: delegates to the
// "live-transcription" module.
//
// Deprecated: remove after v0.7.
func (s *Server) handleTranscriptionAlias(w http.ResponseWriter, r *http.Request) {
	s.serveModuleAlias(w, r, "live-transcription")
}

// handleExappsAlias serves /api/exapps: delegates to the "exapps-daemon"
// module (HaRP, the ExApp deployer).
//
// Deprecated: remove after v0.7.
func (s *Server) handleExappsAlias(w http.ResponseWriter, r *http.Request) {
	s.serveModuleAlias(w, r, "exapps-daemon")
}

// serveModuleAlias maps the old single-resource verbs onto the generic
// module endpoints: GET reads the module, POST starts an operation, and any
// other method is refused exactly like the generic route refuses it.
func (s *Server) serveModuleAlias(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := moduleByID(id); !ok {
		// Defensive: the registry is filled at startup; an absent module
		// here is a wiring bug, not a user error.
		apiErr(w, http.StatusNotFound, "module backing this endpoint is not registered: "+id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.moduleDetail(w, r, id)
	case http.MethodPost:
		// The generic handler re-resolves the ID from the path; the alias
		// rewrites the request so one code path decides acceptance, the
		// 403 on Core and the 409 on a busy module.
		r2 := r.Clone(r.Context())
		r2.SetPathValue("id", id)
		s.handleModuleAction(w, r2)
	default:
		apiErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
