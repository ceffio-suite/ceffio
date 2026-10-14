// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package files orchestrates the deployment of the files layer (Phase 5):
// the dedicated PostgreSQL user/secret, the Nextcloud admin, then Nextcloud
// wired to the `nextcloud` database and Redis. Data on a PVC.
//
// Secrets are generated at runtime (crypto/rand), never in clear text in Git (§111).
package files

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strconv"
	"strings"
	"time"
)

// Pinned versions (discovered on Docker Hub, not invented).
const (
	nextcloudImage = "docker.io/library/nextcloud:34.0.3"
	ns             = "ceffio-files"
	// PostgreSQL: CNPG pod (to create the role) and rw service (for the connection).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "nextcloud"
	dbUser    = "nextcloud"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
	// Redis (deployed in Phase 3).
	redisService = "ceffio-redis.ceffio-data.svc"
	redisPort    = "6379"
)

// Deploy installs the files layer (Phase 5), idempotently:
//  1. dedicated PostgreSQL role + password for Nextcloud
//  2. Nextcloud admin secret (generated)
//  3. Nextcloud (postgres + redis + data PVC) + Service
//  4. instance verification (admin present in the database)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the files layer (Phase 5)...")

	if err := ensureNextcloudDB(ctx); err != nil {
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
	if err := waitNextcloudReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Files layer deployed (Nextcloud installed)")
	return nil
}

// ensureNextcloudDB guarantees the PostgreSQL role lives IN THE VAULT, and nowhere else.
//
// The password comes from the vault if it is already there: a live value is REUSED,
// never regenerated. Regenerating it would leave Nextcloud with a password that the
// database rejects — the outage would only show up at the next restart.
func ensureNextcloudDB(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "nextcloud", "db")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
		// First install: we generate and create the role below.
	default:
		return fmt.Errorf("vault unreadable for nextcloud/db: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ creating the dedicated PostgreSQL role for Nextcloud")
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
	entree["username"] = dbUser
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "nextcloud", "db", entree)
}

// ensureAdminSecret guarantees the admin account lives IN THE VAULT.
func ensureAdminSecret(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{"username": "admin"}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "nextcloud", "admin")
	switch {
	case err == nil:
		for k, v := range actuelle {
			entree[k] = v
		}
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for nextcloud/admin: %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ Nextcloud admin password generated (absent from the vault)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "nextcloud", "admin", entree)
}

// ensureServiceAccount lays down the identity that the vault role designates. Without
// it, the pod does not start: the reference does not resolve.
//
// IT IS LAID DOWN SEPARATELY, and not appended to the big manifest: every document
// added to a format string shifts all the following arguments, and that is exactly
// the error that already cost one silently broken deployment.
func ensureServiceAccount(ctx context.Context) error {
	return apply(ctx, fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: nextcloud
  namespace: %s
`, ns))
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Nextcloud " + nextcloudImage)
	// THREE SOURCES FOR ONE FILE: the database credentials, the admin account, and the
	// send relay. The container does not need to know where each value comes from; it
	// loads one file, the injector composes it.
	annotations := vault.AnnotationsAgent(8, "nextcloud", "kv/data/ceffio/nextcloud/db",
		vault.GabaritMulti([]vault.Source{
			{Chemin: "kv/data/ceffio/nextcloud/db", Paires: [][2]string{
				{"POSTGRES_USER", vault.ChampCoffre("username")},
				{"POSTGRES_PASSWORD", vault.ChampCoffre("password")},
			}},
			{Chemin: "kv/data/ceffio/nextcloud/admin", Paires: [][2]string{
				{"NEXTCLOUD_ADMIN_USER", vault.ChampCoffre("username")},
				{"NEXTCLOUD_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			}},
		}))

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
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR (vault.AnnotationsAgent).
      annotations:
%s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES.
      serviceAccountName: nextcloud
      containers:
        - name: nextcloud
          image: %s
          # THE ORIGINAL ENTRYPOINT SCRIPT IS PRESERVED: it is the one that prepares
          # the instance. We only source the rendered file before launching it.
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /entrypoint.sh apache2-foreground
          env:
            - name: POSTGRES_HOST
              value: %s
            - name: POSTGRES_DB
              value: %s
            - name: REDIS_HOST
              value: %s
            - name: REDIS_HOST_PORT
              value: "%s"
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
`, ns, ns, annotations, nextcloudImage, dbService, dbName, redisService, redisPort, ns)
	return apply(ctx, manifest)
}

func waitNextcloudReady(ctx context.Context) error {
	fmt.Println("∙ waiting for Nextcloud Ready + installation...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/nextcloud", "-n", ns, "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nextcloud not ready: %w", err)
	}
	return waitNextcloudInstalled(ctx)
}

// waitNextcloudInstalled checks that the admin exists (oc_users table), a sign
// that the occ installation has finished.
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
	return fmt.Errorf("Nextcloud instance not initialized after 180s")
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

// ConfigureOIDC wires Nextcloud to the Keycloak SSO: user_oidc app + provider.
// Idempotent (the app and the provider tolerate "already present").
func ConfigureOIDC(ctx context.Context, domain string) error {
	fmt.Println("Nextcloud SSO ← Keycloak...")
	if err := ensureOccApp(ctx, "user_oidc"); err != nil {
		return err
	}
	// CLIENT ID AND SECRET COME FROM THE SAME VAULT ENTRY: splitting them would
	// open the door to a client ID from one client and a secret from another.
	entreeOIDC, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "nextcloud", "oidc")
	if err != nil {
		return fmt.Errorf("nextcloud OIDC client: %w", err)
	}
	// The vault returns fields exactly as stored, but command-line tools
	// (`bao kv get`, `jq`, etc.) append a newline to standard output. If we keep
	// that trailing \n in the secret, the fingerprint on the Nextcloud side
	// (which is trim()med by PHP or by the storage layer) will never match —
	// the consistency check would fail and, worse, Keycloak would receive a
	// client_secret slightly different from its own. We clean it up immediately.
	clientID := strings.TrimSpace(entreeOIDC["client-id"])
	clientSecret := strings.TrimSpace(entreeOIDC["client-secret"])
	// The discovery endpoint must be the PUBLIC name, not the cluster-internal
	// address. Nextcloud takes the endpoints announced by Keycloak: when queried
	// internally, it received "http://keycloak.ceffio-identity.svc:8080" and
	// redirected the browser to an address unreachable from outside
	// (observed: "keycloak...:8080" in the authorization URL).
	//
	// Keycloak carries KC_HOSTNAME_URL: queried by its public name, it announces
	// public endpoints — the ones the browser can actually reach.
	// The domain is therefore no longer hardcoded here: it comes from the deployment.
	if domain == "" {
		return fmt.Errorf("domain required to build the OIDC discovery endpoint")
	}
	discovery := "https://keycloak." + domain + "/realms/ceffio/.well-known/openid-configuration"

	// ONE CALL ONLY, ALWAYS WITH THE CREDENTIALS.
	//
	// This block used to send TWO "update" commands without credentials —
	// "user_oidc:provider Ceffio -d <url>" then
	// "user_oidc:provider Ceffio --update". But `occ user_oidc:provider` without
	// -c/-s REWRITES the provider with EMPTY values: the last step erased the
	// client_id, client_secret and discoveryUri that the first had just set.
	// Result observed in production: the login page returned 404 and the
	// Nextcloud SSO was dead.
	//
	// The right way to update an existing provider is to RESEND the complete
	// configuration. The command is idempotent in that sense: it creates the
	// provider if missing, replaces it otherwise.
	//
	// THE SECRET TRAVELS THROUGH A FILE, NEVER THROUGH AN ARGUMENT. `occ` accepts
	// --clientsecret-file precisely for this: a secret passed as an argument is
	// visible through `ps` in the pod, and ends up in command history. So we drop
	// the file, pass its PATH, then delete it.
	// THE SECRET TRAVELS THROUGH A TEMPORARY ENVIRONMENT VARIABLE.
	//
	// We target one specific pod, because `kubectl exec deploy/nextcloud` picks a
	// random pod and `occ` would not have the env var if the pod changed.
	// The `--clientsecret-env` option avoids putting the secret in argv (visible
	// through `ps`) or in a file (a source of permission/copy errors): it travels
	// in the environment of the single occ process, and disappears with it.
	pod, err := podNextcloud(ctx)
	if err != nil {
		return err
	}
	const envSecret = "CEFFIO_OIDC_SECRET"
	out, err := runOccOutputPodEnv(ctx, pod, envSecret, clientSecret,
		"user_oidc:provider", nomProvider,
		"-c", clientID, "-d", discovery, "--clientsecret-env="+envSecret)
	if err != nil && !strings.Contains(out, "already") {
		return fmt.Errorf("user_oidc:provider: %w: %s", err, out)
	}
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("incomplete OIDC client in the vault (client-id=%t, client-secret=%t): "+
			"the Nextcloud provider would be left without credentials",
			clientID != "", clientSecret != "")
	}

	// PURGE the discovery cache. Nextcloud remembers the endpoints obtained during
	// discovery and reuses them: without the purge, it kept redirecting to the old
	// domain (observed: auth.ceffio.local) while Keycloak was already announcing
	// the right address. The cache must follow the configuration.
	for _, cle := range []string{"provider-1-jwksCache", "provider-1-jwksCacheTimestamp"} {
		runOccOutput(ctx, "config:app:delete", "user_oidc", cle)
	}

	// VERIFY WHAT WAS ACTUALLY SAVED, not what we asked for. occ can exit
	// successfully after writing an incomplete provider — that is exactly what
	// had happened, and nothing reported it.
	if err := verifierProviderOIDC(ctx, nomProvider, clientID, clientSecret); err != nil {
		return err
	}
	fmt.Println("✓ Nextcloud SSO configured (user_oidc + Ceffio provider)")
	return nil
}

// nomProvider is the name of the OIDC provider in Nextcloud. It appears in the
// login URL (/apps/user_oidc/login/1) and in the app key names (provider-1-*),
// which we look up by this name rather than hardcoding them.
const nomProvider = "Ceffio"

// verifierProviderOIDC re-reads the configuration WRITTEN to the
// `oc_user_oidc_providers` table and decrypts the secret with the Nextcloud API.
//
// Since user_oidc 8.x, providers no longer live in `oc_appconfig`.
// Moreover, the stored secret is ENCRYPTED by Nextcloud: comparing fingerprints
// directly would always fail. We therefore go through the Nextcloud server
// itself to decrypt, then compare with the vault.
//
// The secret is never displayed: only fingerprints are compared.
func verifierProviderOIDC(ctx context.Context, nom, clientIDAttendu, secretAttendu string) error {
	// THE SECRET IS DECRYPTED BEFORE COMPARISON — without that, verification is
	// structurally impossible. Nextcloud stores this field ENCRYPTED
	// (LoginController and TokenService call `$this->crypto->decrypt`): a
	// fingerprint computed on the stored value compares ciphertext with
	// plaintext, and always fails. That is what the previous version of this
	// check did.
	//
	// We go through the Nextcloud server itself to decrypt: it alone has the
	// instance key. The script is dropped into the pod and then executed.
	const fichierVerif = "/tmp/.ceffio-oidc-verif.php"
	script := `<?php
require_once "/var/www/html/lib/base.php";
use OCP\IDBConnection;
use OCP\Security\ICrypto;
$id = $argv[1] ?? "";
$db = \OC::$server->get(IDBConnection::class);
$row = $db->executeQuery("SELECT client_id, client_secret, discovery_endpoint FROM oc_user_oidc_providers WHERE identifier = ?", [$id])->fetch();
if (!$row) { echo "ABSENT\n"; exit(0); }
try {
    $crypto = \OC::$server->get(ICrypto::class);
    $clair = $crypto->decrypt($row["client_secret"]);
} catch (\Throwable $e) {
    echo "INDECHIFFRABLE\n"; exit(0);
}
echo "client_id=" . $row["client_id"] . "\n";
echo "secret_sha=" . sha1($clair) . "\n";
echo "secret_len=" . strlen($clair) . "\n";
echo "discovery=" . $row["discovery_endpoint"] . "\n";`
	// Same pod as for the write: the check depends on the currently running Nextcloud.
	pod, err := podNextcloud(ctx)
	if err != nil {
		return err
	}
	if err := deposerFichierPod(ctx, pod, fichierVerif, script); err != nil {
		return err
	}
	defer supprimerFichierPod(ctx, pod, fichierVerif)
	out, err := runPhpPod(ctx, pod, fichierVerif, nom)
	if err != nil && !strings.Contains(out, "client_id=") {
		return fmt.Errorf("re-reading OIDC provider %q: %w: %s", nom, err, debuter(out, 200))
	}
	if err != nil && !strings.Contains(out, "client_id=") {
		return fmt.Errorf("re-reading OIDC provider %q: %w: %s", nom, err, debuter(out, 200))
	}
	if strings.Contains(out, "ABSENT") {
		return fmt.Errorf("OIDC provider %q does not exist after configuration: "+
			"the login page would return 404", nom)
	}
	if strings.Contains(out, "INDECHIFFRABLE") {
		return fmt.Errorf("OIDC provider %q carries a secret that Nextcloud can NOT "+
			"decrypt: the token exchange with Keycloak would fail", nom)
	}
	champs := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, "="); i > 0 {
			champs[strings.TrimSpace(l[:i])] = strings.TrimSpace(l[i+1:])
		}
	}
	if champs["client_id"] != clientIDAttendu {
		return fmt.Errorf("OIDC provider %q carries client_id=%q instead of %q",
			nom, champs["client_id"], clientIDAttendu)
	}
	if champs["secret_sha"] != fmt.Sprintf("%x", sha1.Sum([]byte(secretAttendu))) {
		return fmt.Errorf("OIDC provider %q does NOT carry the vault secret: "+
			"the token exchange with Keycloak would fail", nom)
	}
	if !strings.Contains(champs["discovery"], "realms/ceffio") {
		return fmt.Errorf("OIDC provider %q points to an unexpected discovery endpoint (%q)",
			nom, champs["discovery"])
	}
	return nil
}

func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err != nil && !strings.Contains(out, "already installed") && !strings.Contains(out, "already enabled") {
		return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
	}
	return nil
}

// runPhpPod runs PHP directly in the Nextcloud pod.
//
// WHY NOT runOccOutput: the latter prefixes its arguments with "occ", so
// "php -r …" becomes "occ php -r …" and fails on "Command \"php\" is not
// defined". A verification script does not go through occ.
func runPhpPod(ctx context.Context, pod, fichier string, args ...string) (string, error) {
	phpArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud",
		"--", "php", fichier}, args...)
	out, err := k8s.Command(ctx, "kubectl", phpArgs...).CombinedOutput()
	return string(out), err
}

// runCommandPod runs a raw shell command on the named Nextcloud pod.
//
// Useful for quick diagnostics that do not go through occ.
func runCommandPod(ctx context.Context, pod string, args ...string) (string, error) {
	cmdArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--"}, args...)
	out, err := k8s.Command(ctx, "kubectl", cmdArgs...).CombinedOutput()
	return string(out), err
}

// deposerFichierPod writes content to a file in the pod.
//
// THE CONTENT TRAVELS THROUGH AN EXPLICIT LOCAL FILE (/tmp/.ceffio-*), copied by
// `kubectl cp` and then deleted. This avoids both (a) a secret passed as a
// command argument — visible through `ps` — and (b) a `kubectl exec` writing to
// stdin, which proved unreliable in this context.
//
// The local file carries the SAME NAME as the remote file: this removes the
// `kubectl cp` surprises around temporary file names (random prefix
// incompatible with some paths).
func deposerFichierPod(ctx context.Context, pod, cheminPod, contenu string) error {
	local := cheminPod
	if err := os.WriteFile(local, []byte(contenu), 0600); err != nil {
		return fmt.Errorf("writing local file %s: %w", local, err)
	}
	defer os.Remove(local)

	out, err := k8s.Command(ctx, "kubectl", "cp", "-n", ns, local,
		pod+":"+cheminPod, "-c", "nextcloud").CombinedOutput()
	if err != nil {
		return fmt.Errorf("copying file to the pod (%s): %w: %s", cheminPod, err, debuter(string(out), 200))
	}
	return nil
}

// tailleFichierPod returns the size of a file in the pod, or -1 if it is absent.
func tailleFichierPod(ctx context.Context, pod, chemin string) int {
	// `wc -c <file>` prints "64 /tmp/file": the name is appended to the size and
	// breaks the conversion. We therefore use `sh -c "wc -c < file"`, which
	// prints ONLY the number.
	out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, pod,
		"-c", "nextcloud", "--", "sh", "-c", "wc -c < "+chemin).Output()
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1
	}
	return n
}

// supprimerFichierPod deletes a file from the pod. A clear-text secret must not
// outlive the operation that deposited it.
func supprimerFichierPod(ctx context.Context, pod, chemin string) {
	k8s.Command(ctx, "kubectl", "exec", "-n", ns, pod, "-c", "nextcloud",
		"--", "rm", "-f", chemin).Run()
}

// podNextcloud returns the name of a running Nextcloud pod.
//
// Required for operations that do not support `deploy/nextcloud`, such as
// `kubectl cp` to a specific container of a deployment.
//
// We filter on the NAME PREFIX and on the phase, not on a label: the deployment
// carries no usable label (`app.kubernetes.io/name` is absent), and a selector
// matching nothing yields an empty list — hence a failure disguised as "no
// pod", which cost a round trip.
func podNextcloud(ctx context.Context) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "pods", "-n", ns,
		"--field-selector=status.phase=Running",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}").Output()
	if err != nil {
		return "", fmt.Errorf("looking for the Nextcloud pod: %w", err)
	}
	for _, nom := range strings.Fields(string(out)) {
		if strings.HasPrefix(nom, "nextcloud-") {
			return nom, nil
		}
	}
	return "", fmt.Errorf("no running Nextcloud pod in %s", ns)
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// runOccOutputPod runs occ on the NAMED pod, not on the deployment.
//
// ESSENTIAL when a previous operation deposited a secret file into a particular
// pod: `kubectl exec deploy/nextcloud` picks a random pod among the replicas,
// and the file would be invisible from another pod.
func runOccOutputPod(ctx context.Context, pod string, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// runOccOutputPodEnv runs occ on the named pod, with an injected temporary
// environment variable. Useful to pass a secret without putting it in argv or
// in a file.
func runOccOutputPodEnv(ctx context.Context, pod, nomEnv, valeurEnv string, args ...string) (string, error) {
	// The secret is passed via `env VAR=val php occ ...`; the shell in the pod
	// interprets the assignment. The value is hex, so it contains no characters
	// that are problematic for the shell.
	envAssign := fmt.Sprintf("%s=%s", nomEnv, valeurEnv)
	occArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--",
		"env", envAssign, "php", "occ"}, args...)
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

// debuter returns the first n characters of a command output, on ONE line. Used
// in error messages: raw occ output can be thousands of lines and would drown
// the cause.
func debuter(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
