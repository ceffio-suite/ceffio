// Package sso orchestre l'authentification unique (SSO) via Keycloak sur les
// applications de la suite : création idempotente des clients OIDC (Nextcloud,
// Synapse) dans le realm ceffio et stockage de leurs secrets en Kubernetes.
//
// Secrets générés au runtime, jamais en Git. Réutilisables à volonté
// (idempotence : si le secret k8s existe, on ne touche à rien).
package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"regexp"
	"strings"
)

const (
	ns           = "ceffio-identity"
	realm        = "ceffio"
	keycloakDepl = "deploy/keycloak"
)

type client struct {
	app       string
	id        string
	redirects string
}

// clientsOIDC construit la liste des clients avec le domaine COURANT.
//
// Une redirect_uri doit être joignable par le NAVIGATEUR : les adresses
// internes du cluster (svc.cluster.local) et les anciens domaines de démo
// (demo.local) n'ont rien à y faire. Elles traînaient pourtant ici, figées —
// un vestige de l'installation d'origine.
//
// Chaque application reçoit son adresse publique, plus localhost pour le
// développement local.
func clientsOIDC(domain string) []client {
	return []client{
		{
			app:       "nextcloud",
			id:        "nextcloud",
			redirects: fmt.Sprintf("https://cloud.%s/apps/user_oidc/code,http://localhost/*", domain),
		},
		{
			app:       "synapse",
			id:        "synapse",
			redirects: fmt.Sprintf("https://matrix.%s/_synapse/client/oidc/callback,http://localhost/*", domain),
		},
		{
			// Jitsi ne fait pas d'OIDC lui-même : c'est l'adaptateur qui s'en
			// charge, et sa redirection revient sur le frontend Jitsi.
			app:       "jitsi",
			id:        "jitsi",
			redirects: fmt.Sprintf("https://meet.%s/*,http://localhost/*", domain),
		},
	}
}

// EnsureOIDCClients garantit l'existence des clients OIDC Keycloak (nextcloud,
// synapse) avec un secret généré stocké en secret Kubernetes. Idempotent et
// auto-réparant : recrée un client absent (en réutilisant le secret stocké),
// et (re)pose le secret si manquant.
func EnsureOIDCClients(ctx context.Context, domain string) error {
	fmt.Println("Déploiement du SSO Keycloak (Phase 8)...")
	if domain == "" {
		return fmt.Errorf("domaine requis pour construire les redirect_uri OIDC")
	}
	for _, c := range clientsOIDC(domain) {
		sec := c.app + "-oidc"
		uuid, err := ensureClient(ctx, c.id, c.redirects)
		if err != nil {
			return fmt.Errorf("client OIDC %s: %w", c.id, err)
		}
		// Réutilise le secret existant (les apps pointent dessus), sinon génère.
		secretVal, ok := readSecretVal(ctx, sec, "client-secret")
		if !ok {
			secretVal, err = genSecret(24)
			if err != nil {
				return err
			}
		}
		if err := setClientSecret(ctx, uuid, secretVal); err != nil {
			return fmt.Errorf("secret client %s: %w", c.id, err)
		}
		if err := createSecretS(ctx, sec, map[string]string{
			"client-id":     c.id,
			"client-secret": secretVal,
		}); err != nil {
			return err
		}
		if !ok {
			fmt.Printf("∙ client OIDC %s créé (secret → %s)\n", c.id, sec)
		} else {
			fmt.Printf("∙ client OIDC %s réconcilié (secret → %s)\n", c.id, sec)
		}
	}
	fmt.Println("✓ Clients OIDC Keycloak prêts (nextcloud, synapse, jitsi)")
	return nil
}

func ensureClient(ctx context.Context, clientID, redirects string) (string, error) {
	uuid, err := clientUUID(ctx, clientID)
	if err == nil && uuid != "" {
		return uuid, nil
	}
	out, err := runKcadm(ctx, "create", "clients",
		"-s", "clientId="+clientID,
		"-s", "enabled=true",
		"-s", "protocol=openid-connect",
		"-s", "publicClient=false",
		"-s", `redirectUris=["`+strings.ReplaceAll(redirects, ",", `","`)+`"]`)
	if err != nil {
		return "", err
	}
	id := parseID(out)
	if id == "" {
		return "", fmt.Errorf("création client %s sans id: %s", clientID, out)
	}
	return id, nil
}

func clientUUID(ctx context.Context, clientID string) (string, error) {
	out, err := runKcadm(ctx, "get", "clients", "-q", "clientId="+clientID, "--fields", "id")
	if err != nil {
		return "", err
	}
	var arr []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		return "", fmt.Errorf("parse clients: %w", err)
	}
	if len(arr) == 0 {
		return "", nil
	}
	return arr[0].ID, nil
}

func setClientSecret(ctx context.Context, uuid, secret string) error {
	out, err := runKcadm(ctx, "update", "clients/"+uuid, "-s", "secret="+secret)
	if err != nil {
		return fmt.Errorf("update secret: %w: %s", err, out)
	}
	return nil
}

func parseID(out string) string {
	re := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	return re.FindString(out)
}

// runKcadm exécute kcadm.sh dans le pod Keycloak (credentials admin relus depuis
// l'env du pod) et renvoie la sortie combinée.
func runKcadm(ctx context.Context, args ...string) (string, error) {
	// Injecte -r <realm> après le verbe : les clients OIDC vivent dans le realm
	// applicatif (ceffio), PAS master (realm admin de config credentials).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'"+realm+"'")
		}
	}
	cmd := `/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 && /opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")
	out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, keycloakDepl, "--", "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func secretExists(ctx context.Context, name string) bool {
	err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).Run()
	return err == nil
}

func readSecretVal(ctx context.Context, name, key string) (string, bool) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns, "-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func createSecretS(ctx context.Context, name string, data map[string]string) error {
	args := []string{"kubectl", "create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range data {
		args = append(args, "--from-literal="+k+"="+v)
	}
	args = append(args, "|", "kubectl", "apply", "-f", "-")
	cmd := k8s.Command(ctx, "sh", "-c", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
