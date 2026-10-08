// Package identity orchestre le déploiement de la couche identité (Phase 4) :
// l'utilisateur/secret PostgreSQL dédié, Keycloak (image officielle Quay, pinnée)
// branché sur la base `keycloak`, et la création du realm `ceffio`.
//
// Secrets : tous générés à l'exécution (crypto/rand), stockés dans des Kubernetes
// Secrets — jamais en clair dans Git (principe §111 du doc).
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"strings"
	"time"
)

// Versions pinnées (découvertes via l'API Quay, pas inventées).
const (
	keycloakImage = "quay.io/keycloak/keycloak:26.7.3"
	ns            = "ceffio-identity"
	// PostgreSQL : pod CNPG (pour créer le rôle) et service rw (pour se connecter).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "keycloak"
	dbUser    = "keycloak"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
)

// Deploy installe l'identité (Phase 4), de façon idempotente :
//  1. rôle + mot de passe PostgreSQL dédié à Keycloak
//  2. secret admin Keycloak (généré)
//  3. déploiement Keycloak (postgres) + service
//  4. création du realm "ceffio" via kcadm + vérification
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de l'identité (Phase 4)...")

	if err := ensureKeycloakDB(ctx); err != nil {
		return err
	}
	if err := ensureAdminSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitKeycloakReady(ctx); err != nil {
		return err
	}
	if err := ensureRealm(ctx); err != nil {
		return err
	}
	if err := verifyRealm(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Identité déployée (realm ceffio)")
	return nil
}

func ensureKeycloakDB(ctx context.Context) error {
	if secretExists(ctx, "keycloak-db") {
		return nil
	}
	fmt.Println("∙ création du rôle PostgreSQL dédié à Keycloak")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	// SQL passé en stdin (jamais en arg de commande).
	sql := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s';\nALTER DATABASE %s OWNER TO %s;\n",
		dbUser, pw, dbName, dbUser)
	if err := psqlExec(ctx, sql); err != nil {
		return err
	}
	return createSecret(ctx, "keycloak-db", map[string]string{
		"username": dbUser,
		"password": pw,
	})
}

func ensureAdminSecret(ctx context.Context) error {
	if secretExists(ctx, "keycloak-admin") {
		return nil
	}
	fmt.Println("∙ secret admin Keycloak (généré)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	return createSecret(ctx, "keycloak-admin", map[string]string{
		"username": "admin",
		"password": pw,
	})
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Keycloak " + keycloakImage)
	manifest := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: %s
  labels:
    app: keycloak
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
        - name: keycloak
          image: %s
          args: ["start-dev"]
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://%s:5432/%s
            - name: KC_DB_USERNAME
              valueFrom:
                secretKeyRef:
                  name: keycloak-db
                  key: username
            - name: KC_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: keycloak-db
                  key: password
            - name: KC_BOOTSTRAP_ADMIN_USERNAME
              valueFrom:
                secretKeyRef:
                  name: keycloak-admin
                  key: username
            - name: KC_BOOTSTRAP_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: keycloak-admin
                  key: password
            - name: KC_HEALTH_ENABLED
              value: "true"
            - name: KC_METRICS_ENABLED
              value: "true"
            # KC_HOSTNAME n'est PAS défini ici : sa valeur était figée sur
            # l'ancien domaine (auth.ceffio.local), et Keycloak s'en sert pour
            # construire les endpoints qu'il ANNONCE — la redirection SSO partait
            # donc vers un domaine inexistant. C'est la phase ingress
            # (adoptKeycloakHost) qui pose KC_HOSTNAME / KC_HOSTNAME_URL avec le
            # domaine courant. Un doublon figé ici ne ferait que la contredire.
            - name: KC_HOSTNAME_STRICT
              value: "false"
          ports:
            - name: http
              containerPort: 8080
            - name: management
              containerPort: 9000
          readinessProbe:
            httpGet:
              path: /health/ready
              port: management
            periodSeconds: 10
            failureThreshold: 6
          livenessProbe:
            httpGet:
              path: /health/live
              port: management
            initialDelaySeconds: 120
            periodSeconds: 15
            failureThreshold: 6
          resources:
            requests:
              memory: 1536Mi
              cpu: 250m
            limits:
              memory: 3Gi
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: %s
spec:
  selector:
    app: keycloak
  ports:
    - name: http
      port: 8080
      targetPort: 8080
`, ns, keycloakImage, dbService, dbName, ns)
	return apply(ctx, manifest)
}

func waitKeycloakReady(ctx context.Context) error {
	fmt.Println("∙ attente Keycloak Ready...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/keycloak", "-n", ns, "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keycloak pas prêt: %w", err)
	}
	return nil
}

// ensureRealm crée le realm "ceffio" via kcadm, de façon idempotente : on ne
// crée que si le realm n'est pas déjà dans la base. L'admin est relue depuis
// l'environnement du pod (aucun secret à passer).
func ensureRealm(ctx context.Context) error {
	out, err := queryKeycloakDB(ctx, `SELECT count(*) FROM realm WHERE name='ceffio';`)
	if err == nil && strings.TrimSpace(out) == "1" {
		fmt.Println("∙ realm ceffio déjà présent, rien à faire")
		return nil
	}
	fmt.Println("∙ création du realm ceffio (kcadm)")
	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", ns, "deploy/keycloak", "--",
		"sh", "-c",
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null && /opt/keycloak/bin/kcadm.sh create realms -s "realm=ceffio" -s enabled=true -s registrationAllowed=false -s loginWithEmailAllowed=true -s duplicateEmailsAllowed=false -s resetPasswordAllowed=true -s editUsernameAllowed=false -s sslRequired=external`)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("création du realm ceffio: %w", err)
	}
	return nil
}

// verifyRealm contrôle que le realm "ceffio" existe bien dans la base.
func verifyRealm(ctx context.Context) error {
	fmt.Println("∙ vérification du realm ceffio")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := queryKeycloakDB(ctx, `SELECT count(*) FROM realm WHERE name='ceffio';`)
		if err == nil && strings.TrimSpace(out) == "1" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("realm ceffio non trouvé dans la base après 30s")
}

func psqlExec(ctx context.Context, sql string) error {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w: %s", err, out)
	}
	return nil
}

func queryKeycloakDB(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-d", dbName, "-tAc", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql: %w: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func secretExists(ctx context.Context, name string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	args := []string{"create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range kv {
		args = append(args, "--from-literal="+k+"="+v)
	}
	out, err := k8s.Command(ctx, "kubectl", args...).Output()
	if err != nil {
		return fmt.Errorf("secret dry-run: %w", err)
	}
	return apply(ctx, string(out))
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
