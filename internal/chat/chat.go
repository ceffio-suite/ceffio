// Package chat orchestre le déploiement de la couche chat (Phase 7) :
// Matrix Synapse (sur la base `synapse` + Redis) et Element Web.
//
// Le mot de passe DB n'est pas mis dans les manifests : Synapse le lit via la
// substitution d'env `{{ SYNAPSE_DB_PASSWORD }}` (§111 — jamais en clair en Git).
package chat

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Versions pinnées (découvertes via Docker Hub, pas inventées).
const (
	synapseImage = "docker.io/matrixdotorg/synapse:v1.160.0"
	elementImage = "docker.io/vectorim/element-web:v1.12.27"
	ns           = "ceffio-chat"
	serverName   = "matrix.ceffio.local"
	// PostgreSQL.
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "synapse"
	dbUser    = "synapse"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
	// Redis (Phase 3) — use pour cache persist (optionnel ici).
	redisService = "ceffio-redis.ceffio-data.svc"
)

// Deploy installe la couche chat (Phase 7), de façon idempotente :
//  1. rôle + secret PostgreSQL dédié à Synapse + secret registration
//  2. Synapse (postgres, media PVC) + Service
//  3. Element Web (config homeserver) + Service
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche chat (Phase 7)...")

	if err := ensureSynapseDB(ctx); err != nil {
		return err
	}
	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitSynapseReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche chat déployée (Synapse + Element)")
	return nil
}

func ensureSynapseDB(ctx context.Context) error {
	if secretExists(ctx, "synapse-db") {
		return nil
	}
	fmt.Println("∙ création du rôle PostgreSQL dédié à Synapse")
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
	return createSecretS(ctx, "synapse-db", map[string]string{"password": pw})
}

func ensureSecrets(ctx context.Context) error {
	if secretExists(ctx, "synapse-secrets") {
		return nil
	}
	fmt.Println("∙ secrets Synapse générés (registration, macaroon, form)")
	vals := map[string]string{}
	for _, key := range []string{"shared", "macaroon", "form"} {
		v, err := genSecret(16)
		if err != nil {
			return err
		}
		vals[key] = v
	}
	return createSecretS(ctx, "synapse-secrets", vals)
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Synapse " + synapseImage)
	dbPassword, err := readSecretValue(ctx, "synapse-db", "password")
	if err != nil {
		return err
	}
	registration, err := readSecretValue(ctx, "synapse-secrets", "shared")
	if err != nil {
		return err
	}
	macaroon, err := readSecretValue(ctx, "synapse-secrets", "macaroon")
	if err != nil {
		return err
	}
	form, err := readSecretValue(ctx, "synapse-secrets", "form")
	if err != nil {
		return err
	}
	manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: synapse-config
  namespace: %s
data:
  homeserver.yaml: |
    server_name: %s
    pid_file: /homeserver.pid
    listeners:
      - port: 8008
        type: http
        tls: false
        bind_addresses: ['0.0.0.0']
        x_forwarded: true
        resources:
          - names: [client, federation]
    database:
      name: psycopg2
      args:
        user: %s
        password: "%s"
        database: %s
        host: %s
        port: 5432
        cp_min: 5
        cp_max: 10
    media_store_path: /data/media_store
    enable_registration: false
    registration_shared_secret: "%s"
    macaroon_secret_key: "%s"
    form_secret: "%s"
    signing_key_path: /data/matrix.ceffio.local.signing.key
    trusted_key_servers:
      - server_name: "matrix.org"
    report_stats: false
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: synapse-media
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
  name: synapse
  namespace: %s
  labels:
    app: synapse
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: synapse
  template:
    metadata:
      labels:
        app: synapse
    spec:
      securityContext:
        fsGroup: 991
      containers:
        - name: synapse
          image: %s
          args: ["run"]
          securityContext:
            runAsUser: 991
            runAsGroup: 991
          env:
            - name: SYNAPSE_SERVER_NAME
              value: %s
            - name: SYNAPSE_CONFIG_PATH
              value: /etc/synapse/homeserver.yaml
            - name: SYNAPSE_DB_PASSWORD
              valueFrom:
                secretKeyRef: {name: synapse-db, key: password}
            - name: SYNAPSE_REGISTRATION
              valueFrom:
                secretKeyRef: {name: synapse-secrets, key: shared}
            - name: SYNAPSE_MACAROON
              valueFrom:
                secretKeyRef: {name: synapse-secrets, key: macaroon}
            - name: SYNAPSE_FORM
              valueFrom:
                secretKeyRef: {name: synapse-secrets, key: form}
          ports:
            - name: http
              containerPort: 8008
          readinessProbe:
            tcpSocket:
              port: http
          volumeMounts:
            - name: config
              mountPath: /etc/synapse
            - name: media
              mountPath: /data
          resources:
            limits:
              memory: 1Gi
      volumes:
        - name: config
          configMap: {name: synapse-config}
        - name: media
          persistentVolumeClaim: {claimName: synapse-media}
---
apiVersion: v1
kind: Service
metadata:
  name: synapse
  namespace: %s
spec:
  selector:
    app: synapse
  ports:
    - name: http
      port: 8008
      targetPort: 8008
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: element-config
  namespace: %s
data:
  config.json: |
    {
      "default_server_config": {
        "m.homeserver": {
          "base_url": "http://synapse.ceffio-chat.svc:8008"
        }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: element
  namespace: %s
  labels:
    app: element
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: element
  template:
    metadata:
      labels:
        app: element
    spec:
      containers:
        - name: element
          image: %s
          ports:
            - name: http
              containerPort: 80
          readinessProbe:
            tcpSocket:
              port: http
          volumeMounts:
            - name: config
              mountPath: /app/config.json
              subPath: config.json
      volumes:
        - name: config
          configMap: {name: element-config}
---
apiVersion: v1
kind: Service
metadata:
  name: element
  namespace: %s
spec:
  selector:
    app: element
  ports:
    - name: http
      port: 8080
      targetPort: 80
`, ns, serverName, dbUser, dbPassword, dbName, dbService,
		registration, macaroon, form,
		ns, ns, synapseImage, serverName, ns, ns, ns, elementImage, ns)
	return apply(ctx, manifest)
}

func waitSynapseReady(ctx context.Context) error {
	fmt.Println("∙ attente Synapse Ready (migrations DB)...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/synapse", "-n", ns, "--timeout=420s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("synapse pas prêt: %w", err)
	}
	return waitMatrixAPI(ctx)
}

func waitMatrixAPI(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, "deploy/synapse", "--",
			"sh", "-c", `curl -s -o /dev/null -w "%{http_code}" http://localhost:8008/_matrix/client/versions`).CombinedOutput()
		if err == nil && strings.Contains(string(out), "200") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("API Matrix non prête après 180s")
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

func secretExists(ctx context.Context, name string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

func createSecretS(ctx context.Context, name string, kv map[string]string) error {
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

func readSecretValue(ctx context.Context, name, key string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns,
		"-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", err
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ConfigureOIDC ajoute le SSO Synapse ← Keycloak (provider OIDC) au homeserver.yaml
// puis redémarre Synapse. Idempotent.
func ConfigureOIDC(ctx context.Context) error {
	fmt.Println("SSO Synapse ← Keycloak...")
	clientID, err := readOIDCSecret(ctx, "client-id")
	if err != nil {
		return err
	}
	clientSecret, err := readOIDCSecret(ctx, "client-secret")
	if err != nil {
		return err
	}
	yamlData, err := configMapData(ctx, "synapse-config", "homeserver.yaml")
	if err != nil {
		return err
	}
	if strings.Contains(yamlData, "oidc_providers:") {
		fmt.Println("∙ OIDC Synapse déjà configuré")
		return nil
	}
	block := fmt.Sprintf(`oidc_providers:
  - idp_id: keycloak
    idp_name: Ceffio
    issuer: "http://keycloak.ceffio-identity.svc:8080/realms/ceffio"
    client_id: "%s"
    client_secret: "%s"
    scopes: ["openid", "profile", "email"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
`, clientID, clientSecret)
	if err := applyConfigMapData(ctx, "synapse-config", map[string]string{"homeserver.yaml": yamlData + "\n" + block}); err != nil {
		return err
	}
	if err := rolloutRestart(ctx, "deploy/synapse"); err != nil {
		return err
	}
	if err := waitSynapseReady(ctx); err != nil {
		return err
	}
	fmt.Println("✓ SSO Synapse configuré (login Keycloak sur Element)")
	return nil
}

func readOIDCSecret(ctx context.Context, key string) (string, error) {
	return readSecretValueNS(ctx, "ceffio-identity", "synapse-oidc", key)
}

func readSecretValueNS(ctx context.Context, sNs, name, key string) (string, error) {
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

func configMapData(ctx context.Context, name, key string) (string, error) {
	tpl := "{.data." + strings.ReplaceAll(key, ".", "\\.") + "}"
	out, err := k8s.Command(ctx, "kubectl", "get", "cm", name, "-n", ns, "-o", "jsonpath="+tpl).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func applyConfigMapData(ctx context.Context, name string, data map[string]string) error {
	key := "homeserver.yaml"
	for k := range data {
		key = k
	}
	tmp, err := os.CreateTemp("", "cm-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := os.WriteFile(tmp.Name(), []byte(data[key]), 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap "+name+" -n "+ns+" --from-file="+key+"="+tmp.Name()+" --dry-run=client -o yaml | kubectl apply -f -")
	cmd.Env = k8s.Env()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func rolloutRestart(ctx context.Context, target string) error {
	cmd := k8s.Command(ctx, "kubectl", "rollout", "restart", target, "-n", ns)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
