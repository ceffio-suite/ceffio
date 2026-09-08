// Package console implémente la console d'administration Ceffio (MVP) :
// une mini-API + page web servant (1) un dashboard d'état de la pile et
// (2) la gestion des utilisateurs SSO (realm Keycloak). Protégée par un jeton
// admin ; le verrouillage SSO Keycloak complet vient en durcissement.
//
// Le serveur tourne sur le nœud K3s (accès kubectl + kcadm) et est exposé via
// un Service/Endpoints → nœud + ingress admin.<domain>.
package console

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

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

// Server rassemble l'état de la console (clients in-cluster).
type Server struct {
	Domain  string
	APIKey  string
	kube    kubernetes.Interface
	kcAdmin string // user admin Keycloak
	kcPass  string // mot de passe admin Keycloak
}

// New crée le serveur console : client K8s in-cluster (ou kubeconfig hors cluster),
// et accès admin Keycloak lu depuis le secret keycloak-admin.
func New(domain, apiKey string) (*Server, error) {
	s := &Server{Domain: domain, APIKey: apiKey}
	// Client Kubernetes : in-cluster si possible, sinon kubeconfig par défaut.
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
	// Credentials admin Keycloak (lues depuis le secret dans le cluster ou env).
	s.kcAdmin = strings.TrimSpace(os.Getenv("KC_ADMIN"))
	s.kcPass = strings.TrimSpace(os.Getenv("KC_ADMIN_PASSWORD"))
	return s, nil
}

// Handler construit le routeur HTTP de la console.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex) // page publique (le JS demande la clé pour /api/*)
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("/api/users/", s.requireAuth(s.handleUsersByID))
	return mux
}

// requireAuth protège chaque endpoint par le jeton admin (Authorization: Bearer).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h != "Bearer "+s.APIKey {
			apiErr(w, http.StatusUnauthorized, "jeton admin requis")
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

// kubectl helpers (gardés pour d'éventuels besoins hors-API).
func kubeCombined(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func kubeRun(args ...string) error {
	return exec.Command("kubectl", args...).Run()
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var (
	errUnauthorized = errors.New("non autorisé")
	_               = fmt.Sprintf
	_               = os.Stdout
)
