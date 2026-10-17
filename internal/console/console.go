// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package console implements the Ceffio administration console (MVP):
// a mini-API + web page serving (1) a stack status dashboard and
// (2) SSO user management (Keycloak realm). Protected by an admin token;
// full Keycloak SSO lockout comes as hardening.
//
// The server runs on the K3s node (kubectl + kcadm access) and is exposed via
// a Service/Endpoints → node + admin.<domain> ingress.
package console

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	realm    = "ceffio"
	kcNS     = "ceffio-identity"
	kcSvc    = "http://keycloak.ceffio-identity.svc:8080"
	ConsPort = 8088
)

// Server gathers the console's state (in-cluster clients).
type Server struct {
	Domain  string
	APIKey  string
	kube    kubernetes.Interface
	kcAdmin string // user admin Keycloak
	kcPass  string // Keycloak admin password
	// Nextcloud service account dedicated to the console (application
	// password, revocable). We do NOT use the admin account: its secret is
	// too broad, and changing its password would break the console.
	ncUser string
	ncPass string
	kcBase string // Keycloak API base URL (resolved Service ClusterIP)
}

// New creates the console server: in-cluster K8s client (or out-of-cluster
// kubeconfig), and Keycloak admin access read from the keycloak-admin secret.
func New(domain, apiKey string) (*Server, error) {
	s := &Server{Domain: domain, APIKey: apiKey}
	// Kubernetes client: in-cluster if possible, otherwise the default kubeconfig.
	if cfg, err := rest.InClusterConfig(); err == nil {
		cs, err := kubernetes.NewForConfig(cfg)
		if err == nil {
			s.kube = cs
		}
	}
	if s.kube == nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig(); err == nil {
			if cs, err := kubernetes.NewForConfig(cfg); err == nil {
				s.kube = cs
			}
		}
	}
	// The credentials come from the VAULT, set into the environment at startup
	// by the file the injector rendered. The fallback that read the Kubernetes
	// Secret was removed: the vault is the single source, and a value left in
	// Kubernetes ends up diverging without anyone noticing.
	s.kcAdmin = strings.TrimSpace(os.Getenv("KC_ADMIN"))
	s.kcPass = strings.TrimSpace(os.Getenv("KC_ADMIN_PASSWORD"))
	// Keycloak base URL: the Service ClusterIP (resolves equally well inside and outside a pod).
	s.kcBase = kcSvc
	if s.kube != nil {
		if svc, err := s.kube.CoreV1().Services(kcNS).Get(context.Background(), "keycloak", metav1.GetOptions{}); err == nil && svc.Spec.ClusterIP != "" {
			s.kcBase = "http://" + svc.Spec.ClusterIP + ":8080"
		}
	}

	// Nextcloud service account: the console reads and manages applications via
	// the OCS API. Env first, then the Secret (same pattern as Keycloak).
	//
	// WITHOUT THESE TWO VALUES, the OCS API answers 401 "Current user is not logged
	// in" — a message that does not say the identifier is missing, and wastes time
	// looking on the Nextcloud side.
	s.ncUser = strings.TrimSpace(os.Getenv("NC_USER"))
	s.ncPass = strings.TrimSpace(os.Getenv("NC_PASSWORD"))

	return s, nil
}

// Handler builds the console HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Icons BEFORE the catch-all: "/" matches everything in net/http's mux,
	// so the more specific routes are registered first and win.
	mux.HandleFunc("/favicon.ico", s.handleIcone)
	mux.HandleFunc("/favicon.svg", s.handleIcone)
	mux.HandleFunc("/favicon-32.png", s.handleIcone)
	mux.HandleFunc("/apple-touch-icon.png", s.handleIcone)
	mux.HandleFunc("/", s.handleIndex) // public page (the JS asks for the key for /api/*)
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("/api/users/", s.requireAuth(s.handleUsersByID))
	// Single administration account: identifier, password rotation.
	// A single account administers Nextcloud, Stalwart and this console — it lives
	// in Keycloak, so rotation is applied there and propagates everywhere.
	// Live transcription: heavy and not revisable in place, so installing and
	// removing it are explicit actions, not part of the initial deployment.
	mux.HandleFunc("/api/transcription", s.requireAuth(s.handleTranscription))
	// The deploy daemon (HaRP) and the transcription app are SEPARATE things:
	// one is infrastructure, the other a usage that depends on it. Each gets
	// its own state and actions, so the interface can say which one is missing
	// instead of leaving an installed-but-inactive app unexplained.
	mux.HandleFunc("/api/exapps", s.requireAuth(s.handleExapps))
	mux.HandleFunc("/api/admin", s.requireAuth(s.handleAdmin))
	mux.HandleFunc("/api/admin/rotate", s.requireAuth(s.handleAdminRotate))
	// NO /api/apps routes: application management happens in the INTERFACE OF
	// NEXTCLOUD. The native UI knows its catalogue (categories, compatibility,
	// reviews) better than a page rebuilt here, and it automatically follows
	// Nextcloud's evolution. We don't duplicate it.
	// The link to this UI is provided by /api/admin.
	// Platform SMTP: configuration, test and save. The test-before-save is the
	// key point — an untested config is worthless.
	mux.HandleFunc("/api/smtp", s.requireAuth(s.handleSmtp))
	mux.HandleFunc("/api/smtp/tester", s.requireAuth(s.handleSmtpTester))
	return mux
}

// requireAuth protects every endpoint with the admin token (Authorization: Bearer).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h != "Bearer "+s.APIKey {
			apiErr(w, http.StatusUnauthorized, "admin token required")
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var (
	errUnauthorized = errors.New("not authorized")
	_               = fmt.Sprintf
	_               = os.Stdout
)
