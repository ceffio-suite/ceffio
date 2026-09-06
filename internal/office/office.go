// Package office orchestre le déploiement de la couche office (Phase 6) :
// le serveur ONLYOFFICE Docs Server (JWT), puis le connecteur dans Nextcloud.
//
// Secrets générés au runtime (JWT), jamais en clair dans Git (§111).
package office

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Versions pinnées (découvertes via Docker Hub / Quay, pas inventées).
const (
	officeImage = "docker.io/onlyoffice/documentserver:9.4.0.1"
	ns          = "ceffio-office"
	// Nom du service OnlyOffice pour le connecteur (URL interne).
	officeService = "http://onlyoffice.ceffio-office.svc"
	// Nextcloud (namespace ceffio-files) pour installer le connecteur.
	nextcloudNS = "ceffio-files"
)

// Deploy installe la couche office (Phase 6), de façon idempotente :
//  1. secret JWT ONLYOFFICE (généré, partagé avec le connecteur)
//  2. ONLYOFFICE Docs Server + PVC + Service
//  3. attente du healthcheck
//  4. connecteur ONLYOFFICE dans Nextcloud
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche office (Phase 6)...")

	if err := ensureJWTSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitOfficeReady(ctx); err != nil {
		return err
	}
	if err := connectNextcloud(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche office déployée (ONLYOFFICE + connecteur Nextcloud)")
	return nil
}

func ensureJWTSecret(ctx context.Context) error {
	if secretExists(ctx, "onlyoffice-secret") {
		return nil
	}
	fmt.Println("∙ secret JWT ONLYOFFICE (généré)")
	jwt, err := genSecret(24)
	if err != nil {
		return err
	}
	return createSecret(ctx, "onlyoffice-secret", map[string]string{"jwt": jwt})
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ ONLYOFFICE Docs Server " + officeImage)
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: onlyoffice-data
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
  name: onlyoffice
  namespace: %s
  labels:
    app: onlyoffice
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: onlyoffice
  template:
    metadata:
      labels:
        app: onlyoffice
    spec:
      containers:
        - name: onlyoffice
          image: %s
          env:
            - name: JWT_ENABLED
              value: "true"
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: onlyoffice-secret
                  key: jwt
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            - name: data
              mountPath: /var/www/onlyoffice/Data
          readinessProbe:
            tcpSocket:
              port: http
          resources:
            limits:
              memory: 2Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: onlyoffice-data
---
apiVersion: v1
kind: Service
metadata:
  name: onlyoffice
  namespace: %s
spec:
  selector:
    app: onlyoffice
  ports:
    - name: http
      port: 80
      targetPort: 80
`, ns, ns, officeImage, ns)
	return apply(ctx, manifest)
}

func waitOfficeReady(ctx context.Context) error {
	fmt.Println("∙ attente ONLYOFFICE Ready...")
	cmd := exec.CommandContext(ctx, "kubectl", "rollout", "status",
		"deployment/onlyoffice", "-n", ns, "--timeout=420s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("onlyoffice pas prêt: %w", err)
	}
	return waitHealthcheck(ctx)
}

// waitHealthcheck vérifie /healthcheck == "true" (l'app est fonctionnelle).
func waitHealthcheck(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "kubectl", "exec", "-n", ns, "deploy/onlyoffice", "--",
			"sh", "-c", `curl -s http://localhost/healthcheck`).CombinedOutput()
		if err == nil && strings.Contains(string(out), "true") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("healthcheck ONLYOFFICE non vert après 180s")
}

// connectNextcloud installe et configure le connecteur ONLYOFFICE dans Nextcloud.
func connectNextcloud(ctx context.Context) error {
	fmt.Println("∙ connecteur ONLYOFFICE dans Nextcloud")

	jwt, err := readSecretJWT(ctx)
	if err != nil {
		return err
	}

	if err := ensureOccApp(ctx, "onlyoffice"); err != nil {
		return err
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "documentServerUrl", "--value="+officeService); err != nil {
		return fmt.Errorf("documentServerUrl: %w", err)
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_secret", "--value="+jwt); err != nil {
		return fmt.Errorf("jwt_secret: %w", err)
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_header", "--value=Authorization"); err != nil {
		return fmt.Errorf("jwt_header: %w", err)
	}

	fmt.Println("∙ connecteur configuré")
	return nil
}

func runOcc(ctx context.Context, args ...string) error {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "--", "php", "occ"}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", occArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureOccApp installe (ou réinstalle sans erreur si déjà présente) une app.
func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already installed") || strings.Contains(out, "already enabled") {
		fmt.Printf("∙ app %s déjà installée\n", app)
		return nil
	}
	return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "--", "php", "occ"}, args...)
	out, err := exec.CommandContext(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

func readSecretJWT(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "secret", "onlyoffice-secret", "-n", ns,
		"-o", "jsonpath={.data.jwt}").Output()
	if err != nil {
		return "", fmt.Errorf("lecture du secret jwt: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", fmt.Errorf("décodage base64 jwt: %w", err)
	}
	return string(b), nil
}

func secretExists(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "secret", name, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	args := []string{"create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range kv {
		args = append(args, "--from-literal="+k+"="+v)
	}
	out, err := exec.CommandContext(ctx, "kubectl", args...).Output()
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
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
