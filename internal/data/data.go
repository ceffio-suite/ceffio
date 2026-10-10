// Package data orchestre le déploiement de la couche données (Phase 3) :
// opérateur CloudNativePG, cluster PostgreSQL (bases séparées) et Redis.
//
// Les mots de passe DB ne sont jamais mis dans les manifests : CloudNativePG
// les génère et les stocke dans des Secrets Kubernetes (principe §111 du doc).
package data

import (
	"context"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"strings"
	"time"
)

// Versions pinnées (découvertes via les dépôts, pas inventées).
const (
	cnpgChartVersion = "0.29.0"
	cnpgNamespace    = "cnpg-system"
	pgClusterName    = "ceffio-pg"
	pgNamespace      = "ceffio-data"
	redisImage       = "redis:7.4.11"
)

// Deploy installe la couche données (Phase 3), de façon idempotente :
//  1. opérateur CloudNativePG
//  2. cluster PostgreSQL (1 instance) avec les bases séparées
//  3. Redis (1 instance)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche données (Phase 3)...")

	if err := installCloudNativePG(ctx); err != nil {
		return err
	}
	if err := deployPostgres(ctx); err != nil {
		return err
	}
	if err := installRedis(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche données déployée")
	return nil
}

func installCloudNativePG(ctx context.Context) error {
	fmt.Println("∙ opérateur CloudNativePG " + cnpgChartVersion)
	if err := ensureRepo(ctx, "cnpg", "https://cloudnative-pg.github.io/charts"); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "helm", "upgrade", "--install", "cnpg", "cnpg/cloudnative-pg",
		"--namespace", cnpgNamespace, "--create-namespace",
		"--version", cnpgChartVersion)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func deployPostgres(ctx context.Context) error {
	// Attente de l'opérateur (deployment "cnpg-cloudnative-pg").
	for _, d := range []string{"cnpg-cloudnative-pg"} {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
			"deployment/"+d, "-n", cnpgNamespace, "--timeout=300s")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s pas prêt: %w", d, err)
		}
	}

	fmt.Println("∙ cluster PostgreSQL " + pgClusterName)
	manifest := fmt.Sprintf(`apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: %s
  namespace: %s
spec:
  instances: 1
  storage:
    size: 10Gi
    storageClass: local-path
  bootstrap:
    initdb:
      database: mysuite
      owner: mysuite
      postInitSQL:
        - CREATE DATABASE keycloak;
        - CREATE DATABASE nextcloud;
`, pgClusterName, pgNamespace)
	if err := apply(ctx, manifest); err != nil {
		return err
	}
	return waitPostgresReady(ctx)
}

func waitPostgresReady(ctx context.Context) error {
	fmt.Println("∙ attente PostgreSQL Ready...")
	deadline := time.Now().Add(300 * time.Second)
	for time.Now().Before(deadline) {
		out, err := k8s.Command(ctx, "kubectl", "get", "cluster", pgClusterName,
			"-n", pgNamespace, "-o", `jsonpath={.status.phase}`).Output()
		if err == nil && strings.Contains(string(out), "Cluster in healthy state") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("PostgreSQL %s non prêt après 300s", pgClusterName)
}

func installRedis(ctx context.Context) error {
	fmt.Println("∙ Redis " + redisImage)
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ceffio-redis
  namespace: ` + pgNamespace + `
  labels:
    app: ceffio-redis
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ceffio-redis
  template:
    metadata:
      labels:
        app: ceffio-redis
    spec:
      containers:
        - name: redis
          image: ` + redisImage + `
          ports:
            - containerPort: 6379
          resources:
            limits:
              memory: 2Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ceffio-redis
  namespace: ` + pgNamespace + `
spec:
  selector:
    app: ceffio-redis
  ports:
    - port: 6379
      targetPort: 6379
`
	return apply(ctx, manifest)
}

func ensureRepo(ctx context.Context, name, url string) error {
	cmd := k8s.Command(ctx, "helm", "repo", "add", name, url)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already exists") {
		return fmt.Errorf("helm repo add %s: %w: %s", name, err, out)
	}
	return nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
