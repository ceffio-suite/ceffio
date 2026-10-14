// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package stacks handles the removal of replaced application stacks.
//
// Decision of 2026-10-09: Ceffio becomes a Nextcloud product. Talk (a
// Nextcloud app) replaces chat AND video — so Matrix (Synapse + Element) and
// Jitsi are removed, along with everything that accompanied them.
//
// WHY THIS PACKAGE EXISTS: on an ALREADY installed cluster, removing code is
// not enough. A `kubectl apply` never deletes an object it no longer knows
// about, and the environment variables set by a patch survive redeployments.
// Without explicit cleanup, the old containers keep running indefinitely.
// This is the lesson of the Jitsi SSO removal (internal/media/sans_sso.go),
// generalized here.
//
// Everything is idempotent: each deletion tolerates absence. This code can
// therefore run on every `install` / `redeploy` with no effect on a fresh
// installation.
package stacks

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// nsChat and nsVideo are the namespaces of the removed stacks. They are kept
// during cleanup, then deleted if empty.
const (
	nsChat  = "ceffio-chat"
	nsVideo = "ceffio-video"
)

// RetirerMatrixEtJitsi deletes from the cluster everything that belonged to
// the Matrix stack (Synapse + Element) and the Jitsi video stack.
//
// Deliberate order: we first stop the workloads (they consume), then the
// objects that fed them, then the data. The databases are deleted last —
// that is irreversible.
func RetirerMatrixEtJitsi(ctx context.Context, domain string) error {
	_ = domain

	restait := false

	// ------------------------------------------------------------------
	// 1. Jitsi — workloads
	// ------------------------------------------------------------------
	for _, d := range []string{"web", "prosody", "jicofo", "jvb"} {
		restait = supprimer(ctx, "deployment", d, nsVideo) || restait
		restait = supprimer(ctx, "service", d, nsVideo) || restait
	}

	// The jvb Service carried the LoadBalancer: UDP 10000 + TCP 4443.
	// Deleting it frees those ports on the node side (but NOT the OPNsense
	// NAT rule, which must be removed separately — see `ceffio expose`).

	restait = supprimer(ctx, "ingress", "meet", nsVideo) || restait

	// ------------------------------------------------------------------
	// 2. Matrix — workloads (Element then Synapse)
	// ------------------------------------------------------------------
	restait = supprimer(ctx, "deployment", "element", nsChat) || restait
	restait = supprimer(ctx, "service", "element", nsChat) || restait
	restait = supprimer(ctx, "configmap", "element-config", nsChat) || restait

	restait = supprimer(ctx, "deployment", "synapse", nsChat) || restait
	restait = supprimer(ctx, "service", "synapse", nsChat) || restait
	restait = supprimer(ctx, "configmap", "synapse-config", nsChat) || restait

	restait = supprimer(ctx, "ingress", "chat", nsChat) || restait
	restait = supprimer(ctx, "ingress", "matrix", nsChat) || restait

	// ------------------------------------------------------------------
	// 3. Secrets and PVCs
	// ------------------------------------------------------------------
	for _, s := range []string{"jitsi-secrets", "jitsi-jwt", "meet-tls"} {
		restait = supprimer(ctx, "secret", s, nsVideo) || restait
	}
	restait = supprimer(ctx, "pvc", "jitsi-config", nsVideo) || restait

	for _, s := range []string{"synapse-db", "synapse-secrets", "synapse-oidc", "chat-tls", "matrix-tls"} {
		restait = supprimer(ctx, "secret", s, nsChat) || restait
	}
	restait = supprimer(ctx, "pvc", "synapse-media", nsChat) || restait

	// ------------------------------------------------------------------
	// 4. Data: the `synapse` PostgreSQL database + role
	//    IRREVERSIBLE — hence the order (after everything else).
	// ------------------------------------------------------------------
	if err := supprimerBaseSynapse(ctx); err != nil {
		fmt.Printf("  ! deleting the \"synapse\" database: %v\n", err)
	}

	// ------------------------------------------------------------------
	// 5. The "synapse" OIDC client in Keycloak.
	//    "jitsi" was already removed along with the Jitsi SSO.
	// ------------------------------------------------------------------
	if err := supprimerClientKeycloak(ctx, "synapse"); err != nil {
		fmt.Printf("  ! OIDC client \"synapse\" not deleted: %v\n", err)
	}

	if restait {
		fmt.Println("∙ old Matrix/Jitsi stack removed from the cluster")
	}
	return nil
}

// supprimer deletes a resource, tolerating absence. Returns true if
// something was actually deleted (so as not to print a message on a fresh
// installation).
func supprimer(ctx context.Context, ressource, nom, namespace string) bool {
	cmd := k8s.Command(ctx, "kubectl", "delete", ressource, nom, "-n", namespace, "--ignore-not-found")
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  ! %s/%s (%s) : %s\n", ressource, nom, namespace, premiereLigne(string(out)))
		return false
	}
	s := strings.TrimSpace(string(out))
	if s == "" || strings.Contains(s, "No resources found") {
		return false
	}
	// A successful deletion prints "<resource> "<name>" deleted from …".
	return strings.Contains(s, " deleted ")
}

// supprimerBaseSynapse deletes Synapse's PostgreSQL database and role.
//
// Idempotent: IF EXISTS. Uses WITH (FORCE) to cut residual connections
// (otherwise a terminating Synapse pod would block the deletion).
func supprimerBaseSynapse(ctx context.Context) error {
	// Does the database exist? We avoid acting on a fresh installation.
	existe, err := execPsql(ctx, "SELECT 1 FROM pg_database WHERE datname='synapse'")
	if err != nil {
		return nil // database unreachable: nothing to do here, reported elsewhere
	}
	if strings.TrimSpace(existe) == "" {
		return nil // already absent
	}
	if _, err := execPsql(ctx, "DROP DATABASE IF EXISTS synapse WITH (FORCE)"); err != nil {
		return err
	}
	if _, err := execPsql(ctx, "DROP ROLE IF EXISTS synapse"); err != nil {
		// The role may be held by residual grants: non-blocking.
		fmt.Printf("  ! PostgreSQL role \"synapse\" not deleted: %v\n", err)
	}
	fmt.Println("∙ PostgreSQL database \"synapse\" deleted")
	return nil
}

// execPsql runs SQL against the postgres database (cluster administration).
func execPsql(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", "ceffio-data", "ceffio-pg-1", "--",
		"psql", "-U", "postgres", "-tAc", sql)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	return string(out), nil
}

// supprimerClientKeycloak removes an OIDC client from the application realm,
// along with its associated Kubernetes secret. Idempotent.
func supprimerClientKeycloak(ctx context.Context, clientID string) error {
	pod, err := podKeycloak(ctx)
	if err != nil || pod == "" {
		return nil // Keycloak absent: nothing to do
	}
	script := fmt.Sprintf(`
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 || exit 0
UUID=$(/opt/keycloak/bin/kcadm.sh get clients -r ceffio -q clientId=%s --fields id 2>/dev/null \
  | grep -o '"id" : "[^"]*"' | head -1 | sed 's/.*: "//;s/"//')
if [ -n "$UUID" ]; then
  /opt/keycloak/bin/kcadm.sh delete clients/"$UUID" -r ceffio >/dev/null 2>&1 && echo "deleted" || echo "failed"
fi`, clientID)

	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", "ceffio-identity", pod, "--", "sh", "-c", script)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	if strings.Contains(string(out), "deleted") {
		fmt.Printf("∙ OIDC client \"%s\" deleted from Keycloak\n", clientID)
	}
	// Possible Kubernetes secret.
	supprimer(ctx, "secret", clientID+"-oidc", nsChat)
	return nil
}

// podKeycloak returns the name of the running Keycloak pod.
func podKeycloak(ctx context.Context) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "get", "pods", "-n", "ceffio-identity",
		"-l", "app=keycloak", "--field-selector=status.phase=Running",
		"-o", `jsonpath={.items[0].metadata.name}`)
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func premiereLigne(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 180 {
		return s[:180] + "…"
	}
	return s
}
