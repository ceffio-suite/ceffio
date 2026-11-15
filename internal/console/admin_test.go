// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

// TestLeLienStalwartSuitLEtatDuModule: the mail administration link and the
// rotation step only appear when the mail module is installed.
//
// WHY THE PING IS NOT ENOUGH: an uninstalled mail module leaves no Ingress, and
// Traefik answers 404 for the host — a code below 500, so `stalwartJoignable`
// alone would call it present and send the operator to a page that does not
// exist. The module's state is the authority.
func TestLeLienStalwartSuitLEtatDuModule(t *testing.T) {
	absent := &Server{Domain: "example.com", kube: fake.NewSimpleClientset()}
	if absent.mailEstInstalle(context.Background()) {
		t.Error("no mail deployment: the module cannot be reported installed")
	}

	installe := &Server{Domain: "example.com", kube: fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: "ceffio-mail"},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: 1},
		})}
	if !installe.mailEstInstalle(context.Background()) {
		t.Error("the mail deployment is ready: the module must be reported installed")
	}

	// DEGRADED COUNTS TOO: a server that is starting still has an
	// administration page, and that is exactly when the operator needs it.
	degrade := &Server{Domain: "example.com", kube: fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: "ceffio-mail"},
		})}
	if !degrade.mailEstInstalle(context.Background()) {
		t.Error("a deployment with no ready replica is Degraded, which still has a page to show")
	}
}
