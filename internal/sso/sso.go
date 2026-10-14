// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package sso orchestrates single sign-on (SSO) via Keycloak for the suite's
// applications: idempotent creation of the OIDC clients (Nextcloud, Synapse) in
// the ceffio realm and storage of their secrets in Kubernetes.
//
// Secrets generated at runtime, never in Git. Freely reusable
// (idempotence: if the k8s secret exists, nothing is touched).
package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	ns           = "ceffio-identity"
	realm        = "ceffio"
	keycloakDepl = "deploy/keycloak"
)

type client struct {
	app       string
	id        string
	redirects string
}

// clientsOIDC builds the client list with the CURRENT domain.
//
// A redirect_uri must be reachable by the BROWSER: cluster-internal addresses
// (svc.cluster.local) and the old demo domains (demo.local) have no business
// being there. Yet they were lingering here, hardcoded — a leftover from the
// original installation.
//
// Each application gets its public address, plus localhost for local
// development.
func clientsOIDC(domain string) []client {
	return []client{
		{
			app:       "nextcloud",
			id:        "nextcloud",
			redirects: fmt.Sprintf("https://cloud.%s/apps/user_oidc/code,http://localhost/*", domain),
		},
		{
			// THE VAULT HAS A CLIENT OF ITS OWN, and two return addresses: the one for
			// the web interface, and the one for the command line. They are not the
			// same paths — the command line opens a small local server (8250) to
			// receive the response, since it is not a browser.
			app: "openbao",
			id:  "openbao",
			redirects: fmt.Sprintf(
				"https://bao.%s/ui/vault/auth/oidc/oidc/callback,https://bao.%s/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback",
				domain, domain),
		},
		// NB: no "jitsi" client — Jitsi is in free access (SSO removed on
		// 2026-10-09, see internal/media/sans_sso.go). Existing installations
		// see it removed by SupprimerClientOIDC.
	}
}

// EnsureOIDCClients guarantees the existence of the Keycloak OIDC clients
// (nextcloud, synapse) with a generated secret stored as a Kubernetes secret.
// Idempotent and self-healing: recreates a missing client (reusing the stored
// secret), and (re)lays down the secret if it is missing.
func EnsureOIDCClients(ctx context.Context, domain string) error {
	fmt.Println("Deploying the Keycloak SSO (Phase 8)...")
	if domain == "" {
		return fmt.Errorf("domain required to build the OIDC redirect_uri")
	}
	for _, c := range clientsOIDC(domain) {
		existant := secretExists(ctx, c.app+"-oidc")
		if err := assurerUnClient(ctx, c); err != nil {
			return err
		}
		if !existant {
			fmt.Printf("∙ OIDC client %s created (secret → %s-oidc)\n", c.id, c.app)
		} else {
			fmt.Printf("∙ OIDC client %s reconciled (secret → %s-oidc)\n", c.id, c.app)
		}
	}
	fmt.Println("✓ Keycloak OIDC clients ready")
	return nil
}

// assurerUnClient creates the client if missing, (re)sets its secret in
// Keycloak, and stores the whole thing in a Kubernetes Secret.
//
// FACTORED BECAUSE IT SERVES TWICE: for the full installation, and for the
// standalone vault deployment. Copying these four steps would have been enough
// for the two paths to diverge at the first fix.
func assurerUnClient(ctx context.Context, c client) error {
	uuid, err := ensureClient(ctx, c.id, c.redirects)
	if err != nil {
		return fmt.Errorf("OIDC client %s: %w", c.id, err)
	}
	// Reuses the existing secret (the apps point at it), otherwise generates one.
	//
	// THE VALUE IS TAKEN FROM THE VAULT, AND IT DOES NOT CHANGE: this secret is
	// known to Keycloak AND to the application connecting to it. Regenerating one
	// would break authentication between the two, and the symptom would be a
	// connection failure perfectly silent about the cause.
	//
	// THE ORDER OF SOURCES MATTERS, and it is not arbitrary: the vault first,
	// then KEYCLOAK ITSELF — it is the authority on its own client's secret, and
	// re-reading it there avoids inventing a new one while the application still
	// connects with the old one. Generating is only the last resort, when neither
	// the vault nor Keycloak knows.
	secretVal, ok := lireClientOIDC(ctx, c.app)
	if !ok {
		if depuisKeycloak, errKC := lireSecretClientKeycloak(ctx, uuid); errKC == nil && depuisKeycloak != "" {
			secretVal, ok = depuisKeycloak, true
			fmt.Printf("∙ OIDC client %s: secret taken back from Keycloak (absent from the vault)\n", c.id)
		}
	}
	if !ok {
		secretVal, err = genSecret(24)
		if err != nil {
			return err
		}
	}
	if err := setClientSecret(ctx, uuid, secretVal); err != nil {
		return fmt.Errorf("client secret %s: %w", c.id, err)
	}
	return ecrireClientOIDC(ctx, c.app, c.id, secretVal)
}

// lireClientOIDC reads the OIDC client from the VAULT.
func lireClientOIDC(ctx context.Context, app string) (string, bool) {
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), app, "oidc")
	if err != nil {
		return "", false
	}
	v := entree["client-secret"]
	return v, v != ""
}

// lireSecretClientKeycloak re-reads a client's secret FROM KEYCLOAK.
//
// WHY THIS SOURCE EXISTS: the vault may lag behind Keycloak — it is a reference
// copy, not the authentication registry. When the two have diverged, Keycloak
// is the one that is right, since it is the one the applications authenticate
// against.
func lireSecretClientKeycloak(ctx context.Context, uuid string) (string, error) {
	out, err := runKcadm(ctx, "get", "clients/"+uuid+"/client-secret")
	if err != nil {
		return "", err
	}
	var reponse struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &reponse); err != nil {
		return "", fmt.Errorf("unreadable Keycloak response: %w", err)
	}
	return reponse.Value, nil
}

// ecrireClientOIDC stores the OIDC client in the vault, at the component's location.
func ecrireClientOIDC(ctx context.Context, app, id, secret string) error {
	return secrets.EcrireDansCoffre(ctx, secrets.DepuisEnvironnement(), app, "oidc",
		map[string]string{"client-id": id, "client-secret": secret})
}

// AssurerClientCoffre guarantees the vault's OIDC client, and it alone.
//
// EXPORTED BECAUSE THE VAULT NEEDS IT AT ITS OWN DEPLOYMENT: `ceffio vault` must
// be re-runnable on its own, without replaying the whole stack — that is even
// its raison d'être. Knowledge of Keycloak stays in this package; the vault
// module asks for the client and reads the resulting Secret, rather than
// talking to Keycloak itself.
func AssurerClientCoffre(ctx context.Context, domain string) error {
	for _, c := range clientsOIDC(domain) {
		if c.id == "openbao" {
			return assurerUnClient(ctx, c)
		}
	}
	return fmt.Errorf("OIDC client \"openbao\" absent from the list: the vault cannot authenticate")
}

func ensureClient(ctx context.Context, clientID, redirects string) (string, error) {
	uuid, err := clientUUID(ctx, clientID)
	if err == nil && uuid != "" {
		return uuid, nil
	}
	out, err := runKcadm(ctx, "create", "clients",
		"-s", "clientId="+clientID,
		"-s", "enabled=true",
		"-s", "protocol=openid-connect",
		"-s", "publicClient=false",
		"-s", `redirectUris=["`+strings.ReplaceAll(redirects, ",", `","`)+`"]`)
	if err != nil {
		return "", err
	}
	id := parseID(out)
	if id == "" {
		return "", fmt.Errorf("client creation %s without id: %s", clientID, out)
	}
	return id, nil
}

func clientUUID(ctx context.Context, clientID string) (string, error) {
	out, err := runKcadm(ctx, "get", "clients", "-q", "clientId="+clientID, "--fields", "id")
	if err != nil {
		return "", err
	}
	var arr []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		return "", fmt.Errorf("parse clients: %w", err)
	}
	if len(arr) == 0 {
		return "", nil
	}
	return arr[0].ID, nil
}

func setClientSecret(ctx context.Context, uuid, secret string) error {
	out, err := runKcadm(ctx, "update", "clients/"+uuid, "-s", "secret="+secret)
	if err != nil {
		return fmt.Errorf("update secret: %w: %s", err, out)
	}
	return nil
}

func parseID(out string) string {
	re := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	return re.FindString(out)
}

// runKcadm runs kcadm.sh in the Keycloak pod and returns the combined output.
//
// ADMIN CREDENTIALS COME FROM THE VAULT, not from the pod environment. The
// Keycloak migration to the OpenBao injector removed KC_BOOTSTRAP_ADMIN_* from
// the deployment: they now live only in the rendered file, which only the
// startup command sources. EVERYTHING RUNNING AFTERWARDS in the container no
// longer sees them — kcadm included. The connection went out with an EMPTY user
// and answered "Invalid user credentials", a message that says nothing about
// the cause.
//
// THE PASSWORD TRAVELS THROUGH STANDARD INPUT, never through the command line: an
// argument is readable in /proc/<pid>/cmdline, and inspecting a process must not
// be enough to reveal a secret.
func runKcadm(ctx context.Context, args ...string) (string, error) {
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "keycloak", "admin")
	if err != nil {
		return "", fmt.Errorf("Keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return "", fmt.Errorf("incomplete keycloak/admin vault entry (username and password required)")
	}
	// Injects -r <realm> after the verb: OIDC clients live in the application
	// realm (ceffio), NOT master (the admin realm of config credentials).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'"+realm+"'")
		}
	}
	script := `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + utilisateur + `' --password "$motdepasse" >/dev/null 2>&1 && ` +
		`/opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")

	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-i", "-n", ns, keycloakDepl, "-c", "keycloak", "--", "sh", "-c", script)
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// THE ERROR MUST CARRY WHAT THE COMMAND SAID. A bare "exit status 1" says
		// nothing: kcadm writes the cause in its output, and discarding it forces
		// reproducing the command by hand to read it — which cost an hour.
		return strings.TrimSpace(string(out)),
			fmt.Errorf("kcadm %s: %w — %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func secretExists(ctx context.Context, name string) bool {
	err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).Run()
	return err == nil
}

func readSecretVal(ctx context.Context, name, key string) (string, bool) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns, "-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func createSecretS(ctx context.Context, name string, data map[string]string) error {
	args := []string{"kubectl", "create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range data {
		args = append(args, "--from-literal="+k+"="+v)
	}
	args = append(args, "|", "kubectl", "apply", "-f", "-")
	cmd := k8s.Command(ctx, "sh", "-c", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SupprimerClientOIDC deletes an OIDC client from the application realm and its
// associated Kubernetes secret. Idempotent: a missing client or secret is not
// an error.
//
// Used by the Jitsi SSO removal: the "jitsi" client served the OIDC adapter,
// removed along with it.
func SupprimerClientOIDC(ctx context.Context, clientID string) error {
	uuid, err := clientUUID(ctx, clientID)
	if err != nil {
		// clientUUID also fails when the client does not exist: in that case
		// there is nothing to delete.
		return nil
	}
	if uuid != "" {
		if out, err := runKcadm(ctx, "delete", "clients/"+uuid); err != nil {
			return fmt.Errorf("client removal %s: %w: %s", clientID, err, out)
		}
	}
	// NO MORE KUBERNETES SECRET TO REMOVE: the client lives in the vault, at
	// kv/ceffio/<component>/oidc. Nothing to erase here — and above all not the
	// vault, which must survive the deletion of a client we may recreate.
	return nil
}
