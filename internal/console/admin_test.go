// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveurMessagerie mounts a fake mail server and returns it with the console
// pointed at it. The handler receives every request, so a test can also check
// what the rotation did NOT send.
func serveurMessagerie(t *testing.T, h http.HandlerFunc) (*Server, *[]string) {
	t.Helper()
	var chemins []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chemins = append(chemins, r.Method+" "+r.URL.Path)
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return &Server{Domain: "ceffio.org", mailBase: ts.URL}, &chemins
}

// TestRotStalwartVerifieLaDelegationSansEcrire: the mail administrator has no
// local password — it is directory-backed — so the only correct action is to
// check that mail delegates to the platform's Keycloak realm.
//
// THE ASSERTION ON THE REQUEST LIST IS THE REGRESSION GUARD: the step used to
// send PATCH /api/principal/adminceffio, an endpoint removed in Stalwart 0.16
// that answers 404. A future "fix" that writes again must fail here first.
func TestRotStalwartVerifieLaDelegationSansEcrire(t *testing.T) {
	s, reqs := serveurMessagerie(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"https://keycloak.ceffio.org/realms/ceffio"}`))
	})

	if err := s.rotStalwart(httptest.NewRequest(http.MethodPost, "/api/admin/rotate", nil)); err != nil {
		t.Fatalf("rotStalwart = %v, expected success", err)
	}
	if len(*reqs) != 1 {
		t.Fatalf("requests = %v, expected exactly one", *reqs)
	}
	attendu := "GET /api/discover/adminceffio@ceffio.local"
	if (*reqs)[0] != attendu {
		t.Fatalf("request = %q, expected %q", (*reqs)[0], attendu)
	}
}

// TestRotStalwartRefuseUnAutreFournisseur: a mail server that delegates to
// another identity provider would accept the new password nowhere. Reporting
// ✓ there would be a lie, so the mismatch is an error that names both issuers.
func TestRotStalwartRefuseUnAutreFournisseur(t *testing.T) {
	s, _ := serveurMessagerie(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"issuer":"https://idp.example/realms/autre"}`))
	})

	err := s.rotStalwart(httptest.NewRequest(http.MethodPost, "/api/admin/rotate", nil))
	if err == nil {
		t.Fatal("rotStalwart = nil, expected a mismatch error")
	}
	for _, attendu := range []string{"https://idp.example/realms/autre", "https://keycloak.ceffio.org/realms/ceffio"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Errorf("error %q does not name %q", err, attendu)
		}
	}
}

// TestRotStalwartRefuseUneErreurHTTP: the discovery endpoint answering 404
// must not read as success. The body is problem+json on 1.0.3; including it
// in the message is what made the original failure diagnosable.
func TestRotStalwartRefuseUneErreurHTTP(t *testing.T) {
	s, _ := serveurMessagerie(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"type":"about:blank","status":404,"title":"Not Found"}`))
	})

	err := s.rotStalwart(httptest.NewRequest(http.MethodPost, "/api/admin/rotate", nil))
	if err == nil {
		t.Fatal("rotStalwart = nil, expected a 404 error")
	}
	if !strings.Contains(err.Error(), "discovery refused (404)") {
		t.Errorf("error = %q, expected it to mention the 404", err)
	}
}

// TestRotStalwartRefuseUneReponseSansFournisseur: a 200 without an issuer
// means the server does not delegate at all (internal directory). The step
// must say that, not report a silent success.
func TestRotStalwartRefuseUneReponseSansFournisseur(t *testing.T) {
	s, _ := serveurMessagerie(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})

	err := s.rotStalwart(httptest.NewRequest(http.MethodPost, "/api/admin/rotate", nil))
	if err == nil {
		t.Fatal("rotStalwart = nil, expected a missing-issuer error")
	}
	if !strings.Contains(err.Error(), "no OIDC issuer") {
		t.Errorf("error = %q, expected it to mention the missing issuer", err)
	}
}

// TestBaseMessagerieParDefaut: without an override, the URL is derived from
// the platform domain — the same host the console already probes for health.
func TestBaseMessagerieParDefaut(t *testing.T) {
	s := &Server{Domain: "exemple.org"}
	if got := s.baseMessagerie(); got != "https://mail.exemple.org" {
		t.Fatalf("baseMessagerie = %q", got)
	}
}
