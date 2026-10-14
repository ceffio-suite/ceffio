// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package data orchestrates the deployment of the data layer (Phase 3):
// the CloudNativePG operator, the PostgreSQL cluster (separate databases)
// and Valkey (Redis-compatible cache).
//
// WHY VALKEY AND NOT REDIS: since 7.4, Redis is distributed under
// RSALv2/SSPLv1 — licenses that are NOT open source. Valkey is the Linux
// Foundation fork, BSD-3-Clause, created by Redis's own maintainers when the
// license turned. Same protocol, same port, drop-in replacement. Shipping a
// suite whose own code is AGPL while bundling a non-open-source cache would
// contradict the product's promise.
//
// DB passwords are never put in the manifests: CloudNativePG generates them
// and stores them in Kubernetes Secrets (principle §111 of the doc).
package data

import (
	"context"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"strings"
	"time"
)

// Pinned versions (found via the repositories, not invented).
const (
	cnpgChartVersion = "0.29.0"
	cnpgNamespace    = "cnpg-system"
	pgClusterName    = "ceffio-pg"
	pgNamespace      = "ceffio-data"
	// Valkey 8.1.10: latest stable of the 8.x branch at the time of the license
	// migration (verified on Docker Hub, published 2026-09-21). Pinned exactly:
	// no "8", no "latest".
	valkeyImage = "docker.io/valkey/valkey:8.1.10"
)

// Deploy installs the data layer (Phase 3), idempotently:
//  1. CloudNativePG operator
//  2. PostgreSQL cluster (1 instance) with the separate databases
//  3. Valkey (1 instance, Redis-compatible)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the data layer (Phase 3)...")

	if err := installCloudNativePG(ctx); err != nil {
		return err
	}
	if err := deployPostgres(ctx); err != nil {
		return err
	}
	if err := installValkey(ctx); err != nil {
		return err
	}
	// AFTER the new Deployment and the alias Service are in place, never
	// before: the old pod keeps serving until its replacement is up.
	if err := retirerAncienValkey(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Data layer deployed")
	return nil
}

func installCloudNativePG(ctx context.Context) error {
	fmt.Println("∙ CloudNativePG operator " + cnpgChartVersion)
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
	// Wait for the operator (deployment "cnpg-cloudnative-pg").
	for _, d := range []string{"cnpg-cloudnative-pg"} {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
			"deployment/"+d, "-n", cnpgNamespace, "--timeout=300s")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s not ready: %w", d, err)
		}
	}

	fmt.Println("∙ PostgreSQL cluster " + pgClusterName)
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
	fmt.Println("∙ waiting for PostgreSQL Ready...")
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
	return fmt.Errorf("PostgreSQL %s not ready after 300s", pgClusterName)
}

func installValkey(ctx context.Context) error {
	fmt.Println("∙ Valkey " + valkeyImage)
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ceffio-valkey
  namespace: ` + pgNamespace + `
  labels:
    app: ceffio-valkey
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ceffio-valkey
  template:
    metadata:
      labels:
        app: ceffio-valkey
    spec:
      containers:
        - name: valkey
          image: ` + valkeyImage + `
          ports:
            - containerPort: 6379
          resources:
            limits:
              memory: 2Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ceffio-valkey
  namespace: ` + pgNamespace + `
spec:
  selector:
    app: ceffio-valkey
  ports:
    - port: 6379
      targetPort: 6379
---
# COMPATIBILITY ALIAS, for installations created before the rename.
#
# The Service used to be called ceffio-redis. Existing Nextcloud deployments
# still hold a REDIS_HOST pointing at that name, and their env cannot be
# updated in place (it is baked into the pod template). Both names therefore
# resolve to the same pods: service discovery is by label, so an alias costs
# one invisible ClusterIP and no traffic.
#
# It is created BEFORE the old resource could be removed, never after: an
# installation must never lose its cache because of a rename.
apiVersion: v1
kind: Service
metadata:
  name: ceffio-redis
  namespace: ` + pgNamespace + `
  labels:
    app.kubernetes.io/part-of: ceffio
    # A LABEL VALUE CANNOT CONTAIN SPACES: only alphanumerics, '-', '_' and '.'.
    # The prose belongs in an annotation, which accepts free text.
    ceffio.io/deprecated: "true"
  annotations:
    ceffio.io/replaced-by: "ceffio-valkey (renamed when the cache moved from Redis to Valkey)"
spec:
  selector:
    app: ceffio-valkey
  ports:
    - port: 6379
      targetPort: 6379
`
	return apply(ctx, manifest)
}

// retirerAncienValkey removes the Deployment that carried the old name.
//
// THE SERVICE IS KEPT (as an alias, see installValkey): a running Nextcloud
// still resolves ceffio-redis. The DEPLOYMENT is not: leaving it would keep a
// second, unmanaged pod alive on the same port, and two writers on one cache
// is worse than none. The alias Service re-points to the new pods by label, so
// removing the old Deployment moves the traffic rather than dropping it.
func retirerAncienValkey(ctx context.Context) error {
	cmd := k8s.Command(ctx, "kubectl", "delete", "deployment", "ceffio-redis",
		"-n", pgNamespace, "--ignore-not-found")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("removing the old ceffio-redis Deployment: %w: %s", err, out)
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		fmt.Println("  " + s)
	}
	return nil
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
