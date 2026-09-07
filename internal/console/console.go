// Package console implémente la console d'administration Ceffio (MVP) :
// une mini-API + page web servant (1) un dashboard d'état de la pile et
// (2) la gestion des utilisateurs SSO (realm Keycloak). Protégée par un jeton
// admin ; le verrouillage SSO Keycloak complet vient en durcissement.
//
// Le serveur tourne sur le nœud K3s (accès kubectl + kcadm) et est exposé via
// un Service/Endpoints → nœud + ingress admin.<domain>.
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
	"os/exec"
	"strings"
)

const (
	realm    = "ceffio"
	kcDepl   = "deploy/keycloak"
	kcNS     = "ceffio-identity"
	ConsPort = 8088
)

// Server rassemble l'état de la console.
type Server struct {
	Domain string
	APIKey string
}

// New crée le serveur console pour un domaine public + un jeton d'admin.
func New(domain, apiKey string) *Server {
	return &Server{Domain: domain, APIKey: apiKey}
}

// Handler construit le routeur HTTP de la console.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
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

// kubectl helpers (le serveur tourne sur le nœud, kubectl + kubeconfig dispo).
func kubeCombined(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func kubeRun(args ...string) error {
	return exec.Command("kubectl", args...).Run()
}

// runKcadm exécute kcadm dans le pod Keycloak (realm applicatif), combined output.
// kcadm imprime le résultat (ex. nouvel id) sur stderr → on capture les deux.
func runKcadm(ctx context.Context, args ...string) (string, error) {
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'"+realm+"'")
		}
	}
	cmd := `/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 && /opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")
	out, err := exec.CommandContext(ctx, "kubectl", "exec", "-n", kcNS, kcDepl, "--", "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
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
