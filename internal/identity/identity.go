// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package identity orchestrates the deployment of the identity layer (Phase 4):
// the dedicated PostgreSQL user/secret, Keycloak (official pinned Quay image)
// wired to the `keycloak` database, and the creation of the `ceffio` realm.
//
// Secrets: all generated at runtime (crypto/rand), stored in Kubernetes Secrets
// — never in clear text in Git (doc principle §111).
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strings"
	"time"
)

// Pinned versions (discovered via the Quay API, not invented).
const (
	keycloakImage = "quay.io/keycloak/keycloak:26.7.3"
	ns            = "ceffio-identity"
	// PostgreSQL: CNPG pod (to create the role) and rw service (to connect).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "keycloak"
	dbUser    = "keycloak"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
)

// Deploy installs the identity layer (Phase 4), idempotently:
//  1. dedicated PostgreSQL role + password for Keycloak
//  2. Keycloak admin secret (generated)
//  3. Keycloak deployment (postgres) + service
//  4. creation of the "ceffio" realm via kcadm + verification
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the identity layer (Phase 4)...")

	if err := ensureKeycloakDB(ctx); err != nil {
		return err
	}
	if err := ensureServiceAccount(ctx); err != nil {
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

	fmt.Println("✓ Identity layer deployed (ceffio realm)")
	return nil
}

// ensureKeycloakDB guarantees the PostgreSQL role lives IN THE VAULT, and nowhere else.
//
// The password is REUSED if it exists: regenerating it would leave Keycloak with
// a password the database rejects, and the outage would only appear at restart.
func ensureKeycloakDB(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "db")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for keycloak/db: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ creating the dedicated PostgreSQL role for Keycloak")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	// SQL passed on stdin (never as a command argument).
	sql := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s';\nALTER DATABASE %s OWNER TO %s;\n",
		dbUser, pw, dbName, dbUser)
	if err := psqlExec(ctx, sql); err != nil {
		return err
	}
	entree["username"] = dbUser
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "keycloak", "db", entree)
}

// ensureAdminSecret guarantees the admin account lives IN THE VAULT.
func ensureAdminSecret(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{"username": "admin"}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	switch {
	case err == nil:
		for k, v := range actuelle {
			entree[k] = v
		}
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for keycloak/admin: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ Keycloak admin password generated (absent from the vault)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "keycloak", "admin", entree)
}

// ensureServiceAccount lays down the identity that the vault role designates (see the
// equivalent note on the Nextcloud side: laid down separately so as not to shift the
// arguments of an already-numbered manifest).
func ensureServiceAccount(ctx context.Context) error {
	return apply(ctx, fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: keycloak
  namespace: %s
`, ns))
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Keycloak " + keycloakImage)
	// TWO SOURCES FOR ONE FILE: the database and the admin account.
	annotations := vault.AnnotationsAgent(8, "keycloak", "kv/data/ceffio/keycloak/db",
		vault.GabaritMulti([]vault.Source{
			{Chemin: "kv/data/ceffio/keycloak/db", Paires: [][2]string{
				{"KC_DB_USERNAME", vault.ChampCoffre("username")},
				{"KC_DB_PASSWORD", vault.ChampCoffre("password")},
			}},
			{Chemin: "kv/data/ceffio/keycloak/admin", Paires: [][2]string{
				{"KC_BOOTSTRAP_ADMIN_USERNAME", vault.ChampCoffre("username")},
				{"KC_BOOTSTRAP_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			}},
		}))

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
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR (vault.AnnotationsAgent).
      annotations:
%s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES.
      serviceAccountName: keycloak
      containers:
        - name: keycloak
          image: %s
          # THE IMAGE ENTRYPOINT IS kc.sh: we call it back explicitly, with the
          # same arguments as before ("start-dev").
          command: ["/bin/bash", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /opt/keycloak/bin/kc.sh start-dev
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://%s:5432/%s
            - name: KC_HEALTH_ENABLED
              value: "true"
            - name: KC_METRICS_ENABLED
              value: "true"
            # KC_HOSTNAME is NOT set here: its value was frozen on the old domain
            # (auth.ceffio.local), and Keycloak uses it to build the endpoints it
            # ANNOUNCES — so the SSO redirect went to a nonexistent domain. It is
            # the ingress phase (adoptKeycloakHost) that sets KC_HOSTNAME /
            # KC_HOSTNAME_URL with the current domain. A hardcoded duplicate here
            # would only contradict it.
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
`, ns, annotations, keycloakImage, dbService, dbName, ns)
	return apply(ctx, manifest)
}

func waitKeycloakReady(ctx context.Context) error {
	fmt.Println("∙ waiting for Keycloak Ready...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/keycloak", "-n", ns, "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keycloak not ready: %w", err)
	}
	return nil
}

// ensureRealm creates the "ceffio" realm via kcadm, idempotently: we only create
// it if the realm is not already in the database. The admin is re-read from the
// pod environment (no secret to pass).
func ensureRealm(ctx context.Context) error {
	out, err := queryKeycloakDB(ctx, `SELECT count(*) FROM realm WHERE name='ceffio';`)
	if err == nil && strings.TrimSpace(out) == "1" {
		fmt.Println("∙ ceffio realm already present, nothing to do")
		return nil
	}
	fmt.Println("∙ creating the ceffio realm (kcadm)")
	if err := creerRealm(ctx); err != nil {
		return err
	}
	return nil
}

// creerRealm creates the "ceffio" realm via kcadm.
//
// ADMIN CREDENTIALS COME FROM THE VAULT and travel through STANDARD INPUT,
// never through the command line.
//
// THIS CODE USED TO READ $KC_BOOTSTRAP_ADMIN_* FROM THE POD ENVIRONMENT, and
// that can no longer work: the migration to the OpenBao injector removed those
// variables from the Deployment. They now live only in /secrets/env, which the
// CONTAINER'S STARTUP COMMAND sources for its own process. A `kubectl exec`
// opens a NEW shell that inherits none of it, so the variables were EMPTY,
// kcadm answered "Invalid user credentials", and the whole identity layer
// stopped there — with an error that pointed at a password problem that did
// not exist.
//
// The reasoning is the one already applied in internal/sso (runKcadm); this
// file had simply not been updated to match.
func creerRealm(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return fmt.Errorf("Keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return fmt.Errorf("incomplete keycloak/admin vault entry (username and password required)")
	}

	// IFS= read -r keeps the password intact (no trimming, no backslash
	// interpretation) while it comes in on stdin.
	script := `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + strings.ReplaceAll(utilisateur, "'", `'\''`) + `' --password "$motdepasse" >/dev/null && ` +
		`/opt/keycloak/bin/kcadm.sh create realms -s "realm=ceffio" -s enabled=true ` +
		`-s registrationAllowed=false -s loginWithEmailAllowed=true -s duplicateEmailsAllowed=false ` +
		`-s resetPasswordAllowed=true -s editUsernameAllowed=false -s sslRequired=external`

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", ns, "deploy/keycloak", "-c", "keycloak",
		"--", "sh", "-c", script)
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating the ceffio realm: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyRealm checks that the "ceffio" realm actually exists in the database.
func verifyRealm(ctx context.Context) error {
	fmt.Println("∙ verifying the ceffio realm")
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
	return fmt.Errorf("ceffio realm not found in the database after 30s")
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
