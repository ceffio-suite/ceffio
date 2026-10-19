// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// TestLaPageNEstPasMiseEnCache : the console page answers with no-cache.
//
// WHY THIS IS A TEST AND NOT ONLY A HEADER: the page and the API ship in the
// SAME BINARY, so a page from a previous version can call a route this one no
// longer serves — /api/smtp and /api/tls, for instance, which were removed when
// those settings became the modules'. A browser keeping the old page from its
// cache shows a console that looks broken, and the operator has no way of
// knowing that a reload fixes it.
//
// The deprecation aliases existed for exactly this case. They were removed as
// scheduled; this header removes the CAUSE instead of tolerating it, and the
// unknown-/api/ 404 answers a stale SCRIPT with a clear refusal rather than
// with the HTML page — which is what it returned before.
//
// The assertion is on the header a browser actually reads, not on the source:
// setting it on the API answers instead of the page would leave the test green
// and the defect real.
func TestLaPageNEstPasMiseEnCache(t *testing.T) {
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	rec := doReq(t, h, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / -> %d, the page is not served at all", rec.Code)
	}
	// The body must really be the page: a no-cache header on an error page
	// would satisfy the assertion while the console serves nothing.
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("GET / does not answer with the page: %.120s", rec.Body.String())
	}

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q, expected it to forbid caching.\n"+
			"A cached page can call a route this binary no longer serves, and the "+
			"operator sees a broken console until they clear the cache by hand.", cc)
	}
	// HTTP/1.0 clients ignore Cache-Control: the second header is what keeps an
	// old proxy from serving the previous page.
	if rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("Pragma = %q, expected no-cache for HTTP/1.0 clients", rec.Header().Get("Pragma"))
	}
}
