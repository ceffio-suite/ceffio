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

// Server rassemble l'état de la console (clients in-cluster).
type Server struct {
	Domain  string
	APIKey  string
	kube    kubernetes.Interface
	kcAdmin string // user admin Keycloak
	kcPass  string // mot de passe admin Keycloak
	// Compte de service Nextcloud dedie a la console (mot de passe
	// d'application, revocable). On n'utilise PAS le compte admin : son secret
	// est trop large, et un changement de son mot de passe casserait la console.
	ncUser string
	ncPass string
	kcBase string // base URL API Keycloak (Service ClusterIP résolu)
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
	// Les identifiants viennent du COFFRE, posés dans l'environnement au démarrage
	// par le fichier que l'injecteur a rendu. Le repli qui lisait le Secret
	// Kubernetes a été retiré : le coffre est la source unique, et une valeur
	// laissée dans Kubernetes finit par diverger sans que personne ne le voie.
	s.kcAdmin = strings.TrimSpace(os.Getenv("KC_ADMIN"))
	s.kcPass = strings.TrimSpace(os.Getenv("KC_ADMIN_PASSWORD"))
	// Base URL Keycloak : ClusterIP du Service (résout aussi bien hors pod qu'en pod).
	s.kcBase = kcSvc
	if s.kube != nil {
		if svc, err := s.kube.CoreV1().Services(kcNS).Get(context.Background(), "keycloak", metav1.GetOptions{}); err == nil && svc.Spec.ClusterIP != "" {
			s.kcBase = "http://" + svc.Spec.ClusterIP + ":8080"
		}
	}

	// Compte de service Nextcloud : la console lit et gère les applications via
	// l'API OCS. Env en priorité, sinon le Secret (même schéma que Keycloak).
	//
	// SANS CES DEUX VALEURS, l'API OCS répond 401 « Current user is not logged
	// in » — un message qui ne dit pas que l'identifiant manque, et fait perdre
	// du temps à chercher du côté de Nextcloud.
	s.ncUser = strings.TrimSpace(os.Getenv("NC_USER"))
	s.ncPass = strings.TrimSpace(os.Getenv("NC_PASSWORD"))

	return s, nil
}

// Handler construit le routeur HTTP de la console.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex) // page publique (le JS demande la clé pour /api/*)
	mux.HandleFunc("/api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("/api/users", s.requireAuth(s.handleUsers))
	mux.HandleFunc("/api/users/", s.requireAuth(s.handleUsersByID))
	// Compte administrateur unique : identifiant, rotation du mot de passe.
	// Un seul compte administre Nextcloud, Stalwart et cette console — il vit
	// dans Keycloak, donc la rotation s'y applique et se propage partout.
	mux.HandleFunc("/api/admin", s.requireAuth(s.handleAdmin))
	mux.HandleFunc("/api/admin/rotate", s.requireAuth(s.handleAdminRotate))
	// PAS de routes /api/apps : la gestion des applications se fait dans
	// l'INTERFACE DE NEXTCLOUD. L'UI native connaît son catalogue (catégories,
	// compatibilité, avis) mieux qu'une page reconstruite ici, et elle suit
	// automatiquement les évolutions de Nextcloud. On ne la duplique pas.
	// Le lien vers cette UI est fourni par /api/admin.
	// SMTP de la plateforme : configuration, test et enregistrement. Le test
	// avant sauvegarde est le point clé — une config non testee ne vaut rien.
	mux.HandleFunc("/api/smtp", s.requireAuth(s.handleSmtp))
	mux.HandleFunc("/api/smtp/tester", s.requireAuth(s.handleSmtpTester))
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
