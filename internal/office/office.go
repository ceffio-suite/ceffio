// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package office orchestrates the deployment of the office layer (Phase 6):
// the ONLYOFFICE Docs Server (JWT), then the connector in Nextcloud.
//
// Secrets generated at runtime (JWT), never in clear text in Git (§111).
package office

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/storage"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strings"
	"time"
)

// Pinned versions (discovered via Docker Hub / Quay, not invented).
const (
	officeImage = "docker.io/onlyoffice/documentserver:9.4.0.1"
	ns          = "ceffio-office"
	// ONLYOFFICE service name for the connector (internal URL).
	//
	// THE TRAILING SLASH IS REQUIRED, and its absence is silent. The connector's
	// DocumentService.php builds the conversion URL by CONCATENATION:
	//     $urlToConverter = $documentServerUrl . "converter";
	// Without the slash, "…svc" + "converter" gives "…svcconverter" — an
	// unresolvable host, so EVERY document conversion fails (thumbnails,
	// previews, PDF exports) while opening an editor still works: the editor
	// uses another path. The symptom is a log full of
	// "cURL error 6: Could not resolve host" and an "ONLYOFFICE indisponible"
	// banner in Nextcloud, none of which point at a missing slash.
	//
	// internal/ingress writes the PUBLIC address with the same trailing slash.
	// Both must keep it: they are two values of the same setting, read by the
	// same code path.
	officeService = "http://onlyoffice.ceffio-office.svc/"
	// Nextcloud (ceffio-files namespace) for installing the connector.
	nextcloudNS = "ceffio-files"
)

// Deploy installs the office layer (Phase 6), idempotently:
//  1. ONLYOFFICE JWT secret (generated, shared with the connector)
//  2. ONLYOFFICE Docs Server + PVC + Service
//  3. waiting for the healthcheck
//  4. ONLYOFFICE connector in Nextcloud
func Deploy(ctx context.Context) error {
	fmt.Println("\nDeploying the office layer (Phase 6)...")

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

	fmt.Println("✓ Office layer deployed (ONLYOFFICE + Nextcloud connector)")
	return nil
}

func ensureJWTSecret(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	// THE VAULT IS THE SINGLE SOURCE — no more copies in Kubernetes.
	// The "onlyoffice-secret" Secret is no longer created: a value living in two
	// places ends up diverging, and the double write to Nextcloud would make that
	// divergence invisible until the day the signature no longer matches.
	donnees := map[string]string{}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "onlyoffice", "jwt")
	switch {
	case err == nil:
		donnees = existant
	case secrets.EntreeAbsente(err):
		// First install: we generate below.
	default:
		return fmt.Errorf("vault unreadable for onlyoffice/jwt: %w", err)
	}
	jwt := donnees["jwt"]
	if jwt == "" {
		// A live value is REUSED, never regenerated: a regenerated token would
		// break signing on the server side and the connector side at once, and the
		// symptom — "Invalid token" — does not say which of the two changed.
		genere, err := genSecret(24)
		if err != nil {
			return err
		}
		jwt = genere
		donnees = map[string]string{"jwt": jwt}
		fmt.Println("∙ ONLYOFFICE JWT token generated (absent from the vault)")
	}
	return secrets.EcrireDansCoffre(ctx, coffre, "onlyoffice", "jwt", donnees)
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ ONLYOFFICE Docs Server " + officeImage)
	// SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR.
	annotations := vault.AnnotationsAgent(8, "onlyoffice", "kv/data/ceffio/onlyoffice/jwt",
		vault.GabaritExports("kv/data/ceffio/onlyoffice/jwt",
			[2]string{"JWT_ENABLED", "true"},
			[2]string{"JWT_SECRET", vault.ChampCoffre("jwt")},
		))

	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: onlyoffice-data
  namespace: %[1]s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: %[7]s
  resources:
    requests:
      storage: 20Gi
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: onlyoffice
  namespace: %[2]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: onlyoffice
  namespace: %[3]s
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
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR, which adds the
      # init-container, the IN-MEMORY volume and the right user/group pair itself.
      annotations:
%[4]s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES.
      serviceAccountName: onlyoffice
      containers:
        - name: onlyoffice
          image: %[5]s
          # THE MAIN CONTAINER SOURCES THE RENDERED FILE, THEN RUNS THE ORIGINAL
          # ENTRYPOINT — the one from the image, which prepares the server.
          command: ["/bin/bash", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /bin/bash /app/ds/run-document-server.sh
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            # The injector adds the secrets mount at /secrets itself.
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
  namespace: %[6]s
spec:
  selector:
    app: onlyoffice
  ports:
    - name: http
      port: 80
      targetPort: 80
`, ns, ns, ns, annotations, officeImage, ns, storage.Classe())
	return apply(ctx, manifest)
}

func waitOfficeReady(ctx context.Context) error {
	fmt.Println("∙ waiting for ONLYOFFICE Ready...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/onlyoffice", "-n", ns, "--timeout=420s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("onlyoffice not ready: %w", err)
	}
	return waitHealthcheck(ctx)
}

// waitHealthcheck checks /healthcheck == "true" (the app is functional).
func waitHealthcheck(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, "deploy/onlyoffice", "-c", "onlyoffice", "--",
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
	return fmt.Errorf("ONLYOFFICE healthcheck not green after 180s")
}

// connectNextcloud installs and configures the ONLYOFFICE connector in Nextcloud.
func connectNextcloud(ctx context.Context) error {
	fmt.Println("∙ ONLYOFFICE connector in Nextcloud")

	jwt, err := readSecretJWT(ctx)
	if err != nil {
		return err
	}

	if err := ensureOccApp(ctx, "onlyoffice"); err != nil {
		return err
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "DocumentServerInternalUrl", "--value="+officeService); err != nil {
		return fmt.Errorf("DocumentServerInternalUrl: %w", err)
	}
	// DocumentServerUrl — the address the BROWSER loads the editor from — is
	// deliberately NOT set here. internal/ingress owns it, because only that
	// layer knows the public hostname and its TLS.
	//
	// WHY THIS MATTERS, and what it cost: this function used to write the
	// INTERNAL address (.svc) here, and the ingress wrote the public one later
	// in the sequence. A fresh install therefore ended up correct BY ORDER —
	// the later write overwrote the earlier one. Every other path lost: an
	// installation whose ingress wrote its value before this ran (or that
	// never re-ran the ingress) kept a browser-facing URL pointing at
	// "http://onlyoffice.ceffio-office.svc", a name that resolves INSIDE the
	// cluster only. The browser could not load the editor and Nextcloud
	// displayed "ONLYOFFICE indisponible, veuillez contacter votre
	// administrateur" — while the Document Server itself was healthy and
	// reachable, which is what made it expensive to diagnose.
	//
	// One writer per setting: the internal address here, the public one there.
	// The ONLYOFFICE connector reads the "jwt_secret" key (AppConfig::$_jwtSecret),
	// NOT "secret". Writing "secret" left the connector signing requests with an
	// empty secret → the Document Server answered error -8 "Invalid token" and
	// Nextcloud displayed "le jeton de sécurité n'était pas formé correctement".
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_secret", "--value="+jwt); err != nil {
		return fmt.Errorf("secret (JWT): %w", err)
	}
	// Opens BY DEFAULT all supported formats (OOXML + ODF) on single click.
	// defFormats is a JSON map {format: bool}. Without it, ODF files download on click.
	const defFormats = `{"docx":true,"docxf":true,"oform":true,"xlsx":true,"csv":true,"pptx":true,"odt":true,"odf":true,"ots":true,"ott":true,"ods":true,"odp":true,"odg":true,"pdf":true,"txt":true,"doc":true,"xls":true,"ppt":true,"rtf":true,"html":true}`
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "defFormats", "--value="+defFormats); err != nil {
		return fmt.Errorf("defFormats: %w", err)
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_header", "--value=Authorization"); err != nil {
		return fmt.Errorf("jwt_header: %w", err)
	}

	fmt.Println("∙ connector configured")
	return nil
}

func runOcc(ctx context.Context, args ...string) error {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", occArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureOccApp installs (or reinstalls without error if already present) an app.
func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already installed") || strings.Contains(out, "already enabled") {
		fmt.Printf("∙ app %s already installed\n", app)
		return nil
	}
	return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// readSecretJWT returns the signing token, FROM THE VAULT, with no fallback.
//
// THIS IS THE DOUBLE-WRITE POINT, and therefore the crux here: the same token
// feeds ONLYOFFICE AND the connector configuration in Nextcloud. We read it in
// the same place for both — otherwise a rotation would touch only one of them,
// signing would stop matching, and the symptom would be an authentication error
// on documents rather than a half-done rotation.
func readSecretJWT(ctx context.Context) (string, error) {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "onlyoffice", "jwt")
	if err != nil {
		return "", fmt.Errorf("JWT token unreadable in the vault: %w", err)
	}
	jwt := entree["jwt"]
	if jwt == "" {
		// An empty token is not copied "in the meantime": it would produce a
		// connector that silently rejects every signature.
		return "", fmt.Errorf("JWT token absent from the onlyoffice/jwt vault entry")
	}
	return jwt, nil
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
