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

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/settings"
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

	// ops tracks the asynchronous module operations (one at a time per
	// module, with the in-memory journal). See module_ops.go.
	ops *opsManager

	// acme is the ACME configuration of THIS installation, resolved once at
	// startup from the container's environment and handed to every module
	// through module.Env.
	//
	// WHY RESOLVED ONCE AND NOT PER CALL: the pod's environment does not
	// change while it runs, so re-reading it per call would only add a
	// failure mode. Resolving it here also means an invalid value is
	// reported ONCE, at startup, in the console's own logs — instead of
	// silently degrading a certificate issuance weeks later.
	// ModuleID is deliberately NOT set here: it belongs to the module being
	// called, and moduleEnvReadOnly (or the install path) sets it. Two modules
	// sharing one Env without an ID would write their settings to the same
	// entry, and internal/settings refuses an empty ID for exactly that reason.
	acme acme.Reglages

	// settingsCM and settingsSec give modules access to the stores.
	//
	// They are interfaces declared in internal/module, held here as fields so a
	// test can substitute maps for both — the console tests then exercise the
	// settings routes without a cluster.
	settingsCM  module.ConfigMapStore
	settingsSec module.SecretStore
}

// New creates the console server: in-cluster K8s client (or out-of-cluster
// kubeconfig), and Keycloak admin access read from the keycloak-admin secret.
func New(domain, apiKey string) (*Server, error) {
	s := &Server{Domain: domain, APIKey: apiKey, ops: newOpsManager(), acme: acme.HTTP01(),
		// The stores are wired HERE, once, so every module reaches the same
		// ConfigMap and the same Secrets through module.Env. Leaving them nil
		// would make a module's settings save fail at runtime, on an
		// installation where everything else works.
		settingsCM: settings.ConfigMaps{}, settingsSec: settings.Secrets{}}

	// The ACME configuration is resolved ONCE, and an invalid value is
	// reported without preventing startup: the console is the only way an
	// operator can SEE and fix the configuration, so refusing to serve would
	// lock them out of the very page they need. The historical HTTP-01 is used
	// meanwhile, and the warning names the variable at fault.
	if reglages, err := acme.DepuisEnvironnement(); err == nil {
		s.acme = reglages
	} else {
		fmt.Fprintf(os.Stderr, "⚠ %v — the console assumes the %s challenge\n", err, acme.ChallengeHTTP)
	}
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

	// UNKNOWN /api/ PATHS ANSWER 404. Without this, the catch-all below serves
	// the HTML page with a 200 for anything, including a route that was removed:
	// measured, GET /api/nexistepas returned 200 text/html. A script calling a
	// deleted endpoint would receive a page instead of a refusal, and would try
	// to parse HTML as JSON — the failure surfaces far from its cause.
	//
	// It is also what made the deprecated aliases unnecessary: what removed the
	// need for them was the page being served by the same binary as the API, so
	// a stale page cannot exist. A stale SCRIPT now gets a clear 404.
	//
	// Registered before "/" because Go 1.22's mux gives the more specific
	// pattern priority, not the first registered one.
	mux.HandleFunc("/api/", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		apiErr(w, http.StatusNotFound, "no such endpoint: "+r.URL.Path)
	}))

	mux.HandleFunc("/", s.handleIndex) // public page (the JS asks for the key for /api/*)
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("/api/users/", s.requireAuth(s.handleUsersByID))
	// Single administration account: identifier, password rotation.
	// A single account administers Nextcloud, Stalwart and this console — it lives
	// in Keycloak, so rotation is applied there and propagates everywhere.
	// Generic module endpoints: ONE API for every registry module, replacing
	// the hand-written HaRP and transcription handlers. Install/uninstall run
	// asynchronously (202 + in-memory journal) — see module_ops.go for the
	// measured reason (a live-transcription install takes several minutes).
	mux.HandleFunc("GET /api/modules", s.requireAuth(s.handleModulesList))
	mux.HandleFunc("GET /api/modules/{id}", s.requireAuth(s.handleModuleDetail))
	mux.HandleFunc("POST /api/modules/{id}", s.requireAuth(s.handleModuleAction))
	// GENERIC settings routes: they know no module by name. A feature added
	// tomorrow is served here without touching this file — which is the whole
	// point of the settings contract, and what a test enforces.
	mux.HandleFunc("GET /api/modules/{id}/settings", s.requireAuth(s.handleModuleSettings))
	mux.HandleFunc("POST /api/modules/{id}/settings/{group}", s.requireAuth(s.handleModuleSettingsSave))
	mux.HandleFunc("POST /api/modules/{id}/settings/{group}/test", s.requireAuth(s.handleModuleSettingsTest))
	mux.HandleFunc("/api/admin", s.requireAuth(s.handleAdmin))
	mux.HandleFunc("/api/admin/rotate", s.requireAuth(s.handleAdminRotate))
	// NO /api/apps routes: application management happens in the INTERFACE OF
	// NEXTCLOUD. The native UI knows its catalogue (categories, compatibility,
	// reviews) better than a page rebuilt here, and it automatically follows
	// Nextcloud's evolution. We don't duplicate it.
	// The link to this UI is provided by /api/admin.
	// Platform SMTP: configuration, test and save. The test-before-save is the
	// key point — an untested config is worthless.
	// The TLS page: which ACME challenge is active, through which DNS provider,
	// and where the certificates stand. The credential it writes goes to
	// OpenBao — the console holds no right in cert-manager, by design, and the
	// solver reads it through the injector.
	mux.HandleFunc("/api/tls", s.requireAuth(s.handleTLS))
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
