// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// GET /api/modules/{id}/checks — the prerequisite checks a module declares.
//
// WHY IT IS A ROUTE OF ITS OWN AND NOT A FIELD OF THE MODULE VIEW: the checks
// measure things OUTSIDE the cluster (DNS records, ports, a reverse zone), and
// each one can wait seconds for a timeout. Putting them in the module list would
// make /api/modules — the endpoint the page polls every three seconds while an
// operation runs — as slow as the slowest check. The page asks for them once,
// from the module card, and only for the modules that declare them.
//
// WHY 404 WHEN THE MODULE IS NOT A Checker: an empty list would read as "this
// module verified everything", which is the opposite of "this module has nothing
// to verify". The browser distinguishes the two through the `checkable` flag on
// the module view, so the route's 404 is a server-side refusal for a direct API
// call, not the page's normal path.
func (s *Server) handleModuleChecks(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, ok := moduleByID(id)
	if !ok {
		apiErr(w, http.StatusNotFound, "unknown module: "+id)
		return
	}
	chk, ok := m.(module.Checker)
	if !ok {
		apiErr(w, http.StatusNotFound,
			"module "+id+" declares no checks (it does not implement module.Checker)")
		return
	}

	checks := chk.Checks(r.Context(), s.moduleEnvReadOnly(m))
	// An empty slice and no slice are different JSON: `null` makes the page
	// iterate over nothing with an extra guard, while `[]` is what "checked,
	// nothing to report" looks like on the wire.
	if checks == nil {
		checks = []module.Check{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"module": id,
		"checks": checks,
	})
}
