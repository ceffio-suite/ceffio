// Package files orchestre le déploiement de la couche fichiers (Phase 5) :
// l'utilisateur/secret PostgreSQL dédié, l'admin Nextcloud, puis Nextcloud
// branché sur la base `nextcloud` et Redis. Données sur un PVC.
//
// Secrets générés au runtime (crypto/rand), jamais en clair dans Git (§111).
package files

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"strings"
	"time"
)

// Versions pinnées (découvertes via Docker Hub, pas inventées).
const (
	nextcloudImage = "docker.io/library/nextcloud:34.0.3"
	ns             = "ceffio-files"
	// PostgreSQL : pod CNPG (créer le rôle) et service rw (connexion).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "nextcloud"
	dbUser    = "nextcloud"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
	// Redis (déployé Phase 3).
	redisService = "ceffio-redis.ceffio-data.svc"
	redisPort    = "6379"
)

// Deploy installe la couche fichiers (Phase 5), de façon idempotente :
//  1. rôle + mot de passe PostgreSQL dédié à Nextcloud
//  2. secret admin Nextcloud (généré)
//  3. Nextcloud (postgres + redis + PVC data) + Service
//  4. vérification de l'instance (présence de l'admin dans la base)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche fichiers (Phase 5)...")

	if err := ensureNextcloudDB(ctx); err != nil {
		return err
	}
	if err := ensureAdminSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitNextcloudReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche fichiers déployée (Nextcloud installé)")
	return nil
}

func ensureNextcloudDB(ctx context.Context) error {
	if secretExists(ctx, "nextcloud-db") {
		return nil
	}
	fmt.Println("∙ création du rôle PostgreSQL dédié à Nextcloud")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	sql := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s';\nALTER DATABASE %s OWNER TO %s;\n",
		dbUser, pw, dbName, dbUser)
	if err := psqlExec(ctx, sql); err != nil {
		return err
	}
	return createSecret(ctx, "nextcloud-db", map[string]string{
		"username": dbUser,
		"password": pw,
	})
}

func ensureAdminSecret(ctx context.Context) error {
	if secretExists(ctx, "nextcloud-admin") {
		return nil
	}
	fmt.Println("∙ secret admin Nextcloud (généré)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	return createSecret(ctx, "nextcloud-admin", map[string]string{
		"username": "admin",
		"password": pw,
	})
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Nextcloud " + nextcloudImage)
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nextcloud-data
  namespace: %s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nextcloud
  namespace: %s
  labels:
    app: nextcloud
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nextcloud
  template:
    metadata:
      labels:
        app: nextcloud
    spec:
      containers:
        - name: nextcloud
          image: %s
          env:
            - name: POSTGRES_HOST
              value: %s
            - name: POSTGRES_DB
              value: %s
            - name: POSTGRES_USER
              valueFrom:
                secretKeyRef:
                  name: nextcloud-db
                  key: username
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: nextcloud-db
                  key: password
            - name: REDIS_HOST
              value: %s
            - name: REDIS_HOST_PORT
              value: "%s"
            - name: NEXTCLOUD_ADMIN_USER
              valueFrom:
                secretKeyRef:
                  name: nextcloud-admin
                  key: username
            - name: NEXTCLOUD_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: nextcloud-admin
                  key: password
            - name: NEXTCLOUD_TRUSTED_DOMAINS
              value: "cloud.demo.local localhost 10.42.0.0/24"
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            - name: data
              mountPath: /var/www/html
          readinessProbe:
            tcpSocket:
              port: http
          resources:
            limits:
              memory: 1Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: nextcloud-data
---
apiVersion: v1
kind: Service
metadata:
  name: nextcloud
  namespace: %s
spec:
  selector:
    app: nextcloud
  ports:
    - name: http
      port: 80
      targetPort: 80
`, ns, ns, nextcloudImage, dbService, dbName, redisService, redisPort, ns)
	return apply(ctx, manifest)
}

func waitNextcloudReady(ctx context.Context) error {
	fmt.Println("∙ attente Nextcloud Ready + installation...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/nextcloud", "-n", ns, "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nextcloud pas prêt: %w", err)
	}
	return waitNextcloudInstalled(ctx)
}

// waitNextcloudInstalled vérifie que l'admin existe (table oc_users), signe
// qu'Occurrent installation est terminée.
func waitNextcloudInstalled(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := queryNextcloudDB(ctx, `SELECT count(*) FROM oc_users;`)
		if err == nil && strings.TrimSpace(out) >= "1" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("instance Nextcloud non initialisée après 180s")
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

func queryNextcloudDB(ctx context.Context, sql string) (string, error) {
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

// ConfigureOIDC branche Nextcloud sur le SSO Keycloak : app user_oidc + provider.
// Idempotent (l'app et le provider tolèrent "déjà présent").
func ConfigureOIDC(ctx context.Context) error {
	fmt.Println("SSO Nextcloud ← Keycloak...")
	if err := ensureOccApp(ctx, "user_oidc"); err != nil {
		return err
	}
	clientID, err := readSecretValue(ctx, "ceffio-identity", "nextcloud-oidc", "client-id")
	if err != nil {
		return fmt.Errorf("secret nextcloud-oidc: %w", err)
	}
	clientSecret, err := readSecretValue(ctx, "ceffio-identity", "nextcloud-oidc", "client-secret")
	if err != nil {
		return fmt.Errorf("secret nextcloud-oidc: %w", err)
	}
	const discovery = "http://keycloak.ceffio-identity.svc:8080/realms/ceffio/.well-known/openid-configuration"
	out, err := runOccOutput(ctx, "user_oidc:provider", "Ceffio", "-c", clientID, "-s", clientSecret, "-d", discovery)
	if err != nil && !strings.Contains(out, "already") {
		return fmt.Errorf("user_oidc:provider: %w: %s", err, out)
	}
	fmt.Println("✓ SSO Nextcloud configuré (user_oidc + provider Ceffio)")
	return nil
}

func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err != nil && !strings.Contains(out, "already installed") && !strings.Contains(out, "already enabled") {
		return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
	}
	return nil
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, "deploy/nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

func readSecretValue(ctx context.Context, sNs, name, key string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", sNs, "-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", err
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}
