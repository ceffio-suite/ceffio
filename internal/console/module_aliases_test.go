// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	"k8s.io/client-go/kubernetes/fake"
)

// TestAliasSupprimes : the deprecated single-resource endpoints are gone.
//
// WHY THIS TEST EXISTS AFTER THE REMOVAL: the aliases carried a removal date
// ("after v0.7"), and the day they were deleted nothing would notice if one came
// back. A route kept "for compatibility" outlives its reason: what actually
// removed the need for them was the console page being served by the same binary
// as the API, so the two cannot drift — a stale page is impossible.
//
// The check is on the HTTP surface, not on the source: a handler re-added under
// another name would still be caught.
func TestAliasSupprimes(t *testing.T) {
	trans := &fakeModule{info: module.Info{ID: "live-transcription", Title: "Transcription", Kind: module.Optional}}
	harp := &fakeModule{info: module.Info{ID: "exapps-daemon", Title: "HaRP", Kind: module.Optional}}
	withFakeRegistry(t, trans, harp)
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	for _, chemin := range []string{"/api/transcription", "/api/exapps"} {
		rec := doReq(t, h, http.MethodGet, chemin, "")
		// 404 through the mux, or 405 if a catch-all answers: what must NOT
		// happen is a 200, which would mean the alias is back.
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s -> 200: the deprecated alias is back", chemin)
		}
	}

	// The generic endpoints they delegated to must still work, otherwise this
	// test would pass by breaking everything.
	rec := doReq(t, h, http.MethodGet, "/api/modules", "")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/modules -> %d: the generic endpoint must stay", rec.Code)
	}
}
