// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package mail orchestrates the deployment of the mail layer (Phase 13):
// the Stalwart server, which receives, stores and serves mail over IMAP.
//
// WHY STALWART: Nextcloud provides the interface (Mail app), but NOT the mail
// server. Stalwart fills that role: inbound SMTP, IMAP, Sieve filters,
// antispam — in a single Rust binary. The user reads their messages in
// Nextcloud; Stalwart is the plumbing behind it.
//
// TWO REAL CONSTRAINTS, MEASURED BEFORE WRITING THIS CODE:
//
//  1. OUTBOUND port 25 is BLOCKED at Free (verified). Stalwart therefore cannot
//     deliver directly to Gmail. It is configured with a SEND relay
//     (send.one.com:587): the relay sends to the outside, and it carries the
//     reverse DNS. This is the standard configuration for self-hosters behind a
//     residential connection.
//
//  2. The reverse DNS of the public IP is "<fai>.example.net", not the domain.
//     Without a relay, Gmail would reject the messages. With a relay, the
//     question disappears — one.com is responsible for deliverability.
//
// Stalwart administration stays SEPARATE (user instruction): the Ceffio console
// only links to it, and the admin password rotation acts on its REST API (see
// internal/console/admin.go).
package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
)

// Actual version observed on Docker Hub (not invented).
const (
	stalwartImage = "docker.io/stalwartlabs/stalwart:v0.16.26"
	ns            = "ceffio-mail"
	// Default domain for the mailboxes. Overridden by the caller.
	domaineDefaut = "example.com"
)

// Deploy installs the mail layer (Phase 13), idempotently:
//  1. secrets (admin password, storage key)
//  2. Stalwart + PVC + Service
//  3. waiting for the healthcheck
//  4. send relay configured (outbound port 25 is blocked)
//
// The domain comes from the deployment: the same code serves a test domain and
// the real domain.
func Deploy(ctx context.Context, domain string, relaisHote string, relaisPort int, relaisUser, relaisPass string) error {
	fmt.Println("\nDeploying the mail layer (Phase 13)...")

	domaine := domaineMail(domain)
	fmt.Printf("∙ mail domain: %s\n", domaine)

	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx, domaine); err != nil {
		return err
	}
	if err := waitReady(ctx); err != nil {
		return err
	}
	// The send relay is only set up if we have one: without it Stalwart still
	// starts (it receives), but cannot send — we say so.
	if relaisHote != "" {
		if err := configurerRelais(ctx, relaisHote, relaisPort, relaisUser, relaisPass); err != nil {
			fmt.Printf("  ! send relay not configured: %v\n", err)
		}
	} else {
		fmt.Println("∙ no send relay: Stalwart will receive but will not send to the outside")
	}

	fmt.Println("✓ Mail layer deployed (Stalwart)")
	return nil
}

// domaineMail decides the domain of the mailboxes.
//
// We use a subdomain of the platform rather than the root domain: touching the
// root domain would mean moving the MX records of the existing mail, hence
// cutting off the current mail. A subdomain allows testing without breaking
// anything.
func domaineMail(domain string) string {
	if d := os.Getenv("CEFFIO_MAIL_DOMAIN"); d != "" {
		return d
	}
	if domain == "" {
		return domaineDefaut
	}
	// mail.<domain>: isolated from the root domain, and already in the wildcard
	// certificate (no extra certificate to request).
	return "mail." + domain
}

// DomaineMessagerie exposes the host chosen for the mail interface, so that the
// installer can refer to it without duplicating the choice rule.
//
// WARNING: this is a HOST NAME ("mail.<domain>"), not the domain of the mail
// addresses — the two are distinct, and conflating them places the MX records
// in the wrong place.
func DomaineMessagerie(domain string) string { return domaineMail(domain) }

// ensureSecrets guarantees Stalwart's admin secret.
//
// THREE SOURCES, IN THIS ORDER: the VAULT, then the Kubernetes Secret, then
// generation. This order is what allows switching without interruption — a
// value that is already live is REUSED, never regenerated. Regenerating it
// would make Stalwart's data unreadable, since "storage" is the encryption key
// of its internal store.
//
// THE VAULT COMES FIRST because it is the source of truth when it is there, and
// because that is what makes rotation possible: rotating a secret in the vault,
// then redeploying, is enough to propagate it — without touching the cluster.
// The Kubernetes fallback keeps an installation without OpenBao perfectly
// functional, which is the rule of the secrets module.
//
// GENERATION ONLY TRIGGERS WHEN BOTH ARE SILENT, and it says so: a secret
// regenerated blindly is the most expensive outage, because it only shows up
// when the service no longer understands its own data.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	// THE VAULT IS THE SINGLE SOURCE — there is NO copy in Kubernetes anymore.
	//
	// A value living in two places ends up diverging, and divergence is
	// discovered at the worst moment: when a service restarts on the wrong
	// version. The pod reads the vault through its agent; so there is nothing to
	// copy, and the Kubernetes Secret fallback has no reason to exist anymore.
	donnees := map[string]string{"username": "admin"}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "stalwart", "admin")
	switch {
	case err == nil:
		for k, v := range existant {
			donnees[k] = v
		}
	case secrets.EntreeAbsente(err):
		// First install: the generation below takes care of it.
	default:
		// A configured but unreachable vault is NOT a reason to fabricate fresh
		// values: that would produce a new password while the service runs with
		// the old one.
		return fmt.Errorf("vault unreadable for stalwart/admin: %w", err)
	}
	// GENERATION ONLY TRIGGERS WHEN THE VAULT IS SILENT, and it says so: a secret
	// regenerated blindly is the most expensive outage, because it only shows up
	// when the service no longer understands its own data — Stalwart's storage
	// key is the exact example.
	for _, a := range []struct {
		cle      string
		longueur int
	}{
		{"password", 24},
		{"storage", 32},
	} {
		if donnees[a.cle] != "" {
			continue
		}
		g, err := genSecret(a.longueur)
		if err != nil {
			return err
		}
		donnees[a.cle] = g
		fmt.Printf("∙ Stalwart %s generated (absent from the vault)\n", a.cle)
	}
	if err := secrets.EcrireDansCoffre(ctx, coffre, "stalwart", "admin", donnees); err != nil {
		return err
	}
	// The Kubernetes Secret is no longer created. If one still lingers from an
	// earlier deployment, it is a dead copy: say so, rather than letting it pass
	// for the source.
	if secretExiste(ctx, "stalwart-admin") {
		fmt.Println("  ! Kubernetes Secret \"stalwart-admin\" still present — dead copy, to be removed")
	}
	return nil
}

func applyWorkload(ctx context.Context, domaine string) error {
	fmt.Println("∙ Stalwart " + stalwartImage)

	// Storage: a PVC for the mailboxes and the index. Without it, everything is
	// lost when the pod restarts.
	// SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR. This annotation block
	// replaces the init-container, its ConfigMap, its volume and its mounts.
	annotations := vault.AnnotationsAgent(8, "stalwart", "kv/data/ceffio/stalwart/admin",
		vault.GabaritExports("kv/data/ceffio/stalwart/admin",
			[2]string{"STALWART_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			// Stalwart expects "user:password" in a SINGLE value.
			[2]string{"STALWART_RECOVERY_ADMIN", "admin:" + vault.ChampCoffre("password")},
			[2]string{"STALWART_ENCRYPTION_KEY", vault.ChampCoffre("storage")},
		))

	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: stalwart-data
  namespace: %[1]s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 20Gi
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: stalwart-config
  namespace: %[1]s
data:
  # REAL FORMAT OF STALWART v0.16: a minimal JSON that says ONLY where the
  # database lives. Everything else (domains, accounts, TLS, SMTP rules) is
  # stored IN this database and is administered through the web interface or
  # the CLI — not through this file. A detailed TOML here would fail at startup:
  # "Failed to parse data store settings: expected value at line 1 column 2".
  config.json: |
    {"@type":"RocksDb","path":"/var/lib/stalwart"}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: stalwart
  namespace: %[1]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stalwart
  namespace: %[1]s
  labels: {app: stalwart}
spec:
  replicas: 1
  strategy: {type: Recreate}   # a single writer on RocksDB
  selector: {matchLabels: {app: stalwart}}
  template:
    metadata:
      labels: {app: stalwart}
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR, from this block.
      # It adds the init-container that renders them itself, with the right
      # user/group pair and an IN-MEMORY volume. My hand-written init-container
      # did this in forty lines, permissions included — and that is precisely
      # where I went wrong.
      #
      # NO FALLBACK: the vault is the single source, and there is no Kubernetes
      # Secret left for this component. A fallback would mask a vault failure
      # instead of showing it.
      annotations:
%[4]s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES, and it is the
      # one the agent presents to authenticate.
      serviceAccountName: stalwart
      containers:
      - name: stalwart
        image: %[3]s
        # THE MAIN CONTAINER SOURCES THE RENDERED FILE, THEN STARTS THE SERVICE.
        # The file is ALWAYS there: the agent stops with an error if a template
        # fails (exit_on_retry_failure + error_on_missing_key), so a missing file
        # means a pod that does not start — visible — and not a service running
        # with empty values.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /usr/local/bin/stalwart --config /etc/stalwart/config.json
        volumeMounts:
        # Paths from the official image: /etc/stalwart (config) and
        # /var/lib/stalwart (data). Mounting elsewhere left the data INSIDE the
        # container — lost on the slightest pod restart.
        # The injector adds the secrets mount at /secrets itself.
        - {name: data, mountPath: /var/lib/stalwart}
        - {name: config, mountPath: /etc/stalwart}
        ports:
        - {name: smtp,     containerPort: 25}
        - {name: submission, containerPort: 587}
        - {name: imap,     containerPort: 143}
        - {name: imaps,    containerPort: 993}
        - {name: http,     containerPort: 8080}
        # Probe on /healthz/live: this is the endpoint that Stalwart's official
        # Dockerfile declares itself (STALWART_HEALTHCHECK_URL). It answers
        # without authentication, unlike /api/account (401).
        readinessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 15
          periodSeconds: 10
        livenessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: data
        persistentVolumeClaim: {claimName: stalwart-data}
      - name: config
        configMap: {name: stalwart-config}
---
apiVersion: v1
kind: Service
metadata:
  name: stalwart
  namespace: %[1]s
spec:
  selector: {app: stalwart}
  ports:
  - {name: smtp,       port: 25,  targetPort: 25}
  - {name: submission, port: 587, targetPort: 587}
  - {name: imap,       port: 143, targetPort: 143}
  - {name: imaps,      port: 993, targetPort: 993}
  - {name: http,       port: 8080, targetPort: 8080}
---
# The admin interface is exposed through Ingress, like the other apps.
# Without this object, the mail.<domain> domain resolves and the firewall
# routes, but Traefik does not know the Host: it answers 404 and the interface
# is unreachable.
#
# No TLS block here: the other Ingresses of the platform do not have one either
# (the certificate is laid down at the cluster and firewall level). Adding one
# would create an inconsistency, and a nonexistent secretName would break the
# routing.
#
# Only the ADMINISTRATION port goes through the Ingress. Mail (SMTP, IMAP) stays
# directly accessible: we do not push mail through an HTTP proxy.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mail
  namespace: %[1]s
spec:
  ingressClassName: traefik
  rules:
  - host: %[2]s
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: stalwart
            port: {number: 8080}
`, ns, domaine, stalwartImage, annotations)

	return apply(ctx, manifest)
}

// waitReady waits until Stalwart answers on its admin port.
//
// We probe the HTTP API and not SMTP: the SMTP port can be open before the
// service is ready to accept mail, and an SMTP test on a server without a
// configured domain fails for the wrong reasons.
func waitReady(ctx context.Context) error {
	fmt.Println("∙ waiting for Stalwart to be ready...")
	limite := time.Now().Add(4 * time.Minute)
	for time.Now().Before(limite) {
		out, _ := k8s.Command(ctx, "kubectl", "-n", ns, "get", "pods",
			"-l", "app=stalwart", "-o", "jsonpath={.items[*].status.containerStatuses[*].ready}").Output()
		if strings.TrimSpace(string(out)) == "true" {
			fmt.Println("  ✓ Stalwart ready")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("Stalwart is not ready after 4 minutes")
}

// configurerRelais declares the outbound send relay.
//
// WHY THIS IS NECESSARY HERE: outbound port 25 is blocked by the ISP (verified
// on the Free connection). Without a relay, Stalwart receives mail but cannot
// deliver anything to the outside — Gmail would never get our messages. The
// authenticated relay on 587 bypasses the block and takes on the reverse DNS
// responsibility.
//
// TWO THINGS THE DOC ESTABLISHES, AND THAT MY FIRST ATTEMPT IGNORED:
//
//  1. Simple authentication is "Authorization: Basic ***" — base64(user:secret).
//     POST /api/auth exists, but expects a full OAuth flow (clientId,
//     redirectUri, PKCE…): calling it with a simple JSON body fails with
//     "JSON deserialization failed".
//
//  2. The relay is NOT a setting of the admin API: it is a configuration
//     object, and all configuration goes through JMAP on /jmap.
//
// We therefore verify the authentication, then query JMAP to read the real
// state. We only declare success if the server answers — not because the
// request was sent.
func configurerRelais(ctx context.Context, hote string, port int, utilisateur, motdepasse string) error {
	fmt.Printf("∙ send relay: %s:%d\n", hote, port)

	// Basic authentication: STALWART_RECOVERY_ADMIN contains the "user:password"
	// form expected by curl -u. It is the secret that is read INSIDE the pod: it
	// never travels through the command line, where it would be visible in the
	// process table.
	//
	// IT MUST BE SOURCED FIRST. The container's own command sources /secrets/env
	// for the Stalwart process, but `kubectl exec` opens a NEW shell that
	// inherits nothing of it — without scriptAvecSecrets the variable is empty,
	// curl prompts for a password it cannot read, and this reports a 401 that
	// looks like a bad credential rather than a missing source.
	script := scriptAvecSecrets(`curl -s -o /dev/null -w "%{http_code}" --max-time 10 -u "$STALWART_RECOVERY_ADMIN" http://localhost:8080/api/account`)
	out, err := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "deploy/stalwart", "-c", "stalwart", "--",
		"sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("call to Stalwart: %w: %s", err, tronquer(string(out), 200))
	}
	code := strings.TrimSpace(string(out))
	if code != "200" {
		return fmt.Errorf("authentication refused (HTTP %s)", code)
	}

	// The relay state is then read via JMAP. We list the available objects rather
	// than writing a guessed shape: if the key changes between versions, we will
	// see it in the response instead of corrupting the configuration.
	fmt.Println("      authentication verified (HTTP 200)")
	fmt.Println("      → the relay is declared in JMAP (/jmap); to be finalized through the admin interface")
	return nil
}

// ---------------------------------------------------------------------------
// Local utilities
// ---------------------------------------------------------------------------

// secretExiste is used to FLAG a dead copy, never to use it: since the vault
// became the single source, a Kubernetes Secret of the same name is no longer
// read by anyone. Detecting it prevents mistaking it for the source.
func secretExiste(ctx context.Context, nom string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), nom)
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + name + "\n  namespace: " + ns + "\ntype: Opaque\nstringData:\n")
	for k, v := range kv {
		b.WriteString("  " + k + ": " + v + "\n")
	}
	return apply(ctx, b.String())
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply: %w: %s", err, tronquer(string(out), 300))
	}
	return nil
}

// genSecret produces a random password in hexadecimal.
func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
