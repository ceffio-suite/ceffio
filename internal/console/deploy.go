// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
)

const (
	deployNS   = "ceffio-system"
	deployName = "ceffio-admin"
	imageName  = "localhost/ceffio-console"
	// Bump MANDATORY on every change of the console page or code:
	// buildAndImportImage skips the rebuild if the tag already exists in
	// containerd. Without a bump, the old image keeps being served.
	imageTag = "1.32.7"
	imageRef = imageName + ":" + imageTag
)

// Deploy installs the administration console IN the cluster (Phase 11):
//   - local OCI image (binary + embedded web page) imported into containerd
//   - ceffio-admin Deployment + ServiceAccount + Role (read pods/ingress/certs)
//   - ceffio-console-key Secret (persisted admin key) + env KC_ADMIN
//   - ClusterIP Service + admin.<domain> Ingress + certificate
//
// Replaces the old model (systemd + Endpoints→node).
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying the administration console (Phase 11)...")

	if err := buildAndImportImage(ctx); err != nil {
		return err
	}
	if err := ensureConsoleKey(ctx); err != nil {
		return err
	}
	// The Keycloak credentials are read IN THE VAULT by the injector, like all
	// other components. The console is the ONLY service whose image contains
	// no shell: it cannot "source" /secrets/env, it reads it itself at startup
	// (secrets.ChargerDepuisFichier).
	if err := applyConsoleManifest(ctx, domain); err != nil {
		return err
	}
	if err := waitConsoleReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Administration console deployed (https://admin." + domain + ")")
	return nil
}

// buildAndImportImage builds the console OCI image and imports it into
// containerd k3s. Idempotent: skips if the image is already present.
//
// Design constraints (learned from scratch builds) — the target machine is a
// PRODUCTION server, not a dev workstation:
//   - no Go toolchain: we do NOT compile on site. We reuse the running binary
//     (os.Executable), which is by construction a Ceffio binary for the right
//     platform. Requiring `go` made Phase 11 fail on any fresh machine
//     ("exec: \"go\": executable file not found").
//   - no Docker daemon: the image is assembled directly as OCI (tar) then
//     imported into the k3s containerd via ctr. Requiring `docker build`/`save`
//     is unjustifiable on a K3s host.
func buildAndImportImage(ctx context.Context) error {
	if imagePresent(ctx) {
		fmt.Println("∙ console image already present (" + imageRef + ")")
		return nil
	}
	fmt.Println("∙ building + importing console image " + imageRef)

	// 1. Binary to embed: the running one (already a Ceffio executable).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("current binary not found: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if fi, err := os.Stat(self); err != nil || fi.Size() == 0 {
		return fmt.Errorf("current binary unreadable (%s): %v", self, err)
	}

	// 2. Minimal OCI assembly (Dockerfile FROM scratch equivalent), WITHOUT Docker:
	//    config + tar.gz layer containing /usr/local/bin/ceffio and the CAs.
	tmp, err := os.MkdirTemp("", "ceffio-console-oci-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	layer, diffID, err := buildLayerFromBinary(tmp, self)
	if err != nil {
		return err
	}
	ociTar, err := buildOCIImage(tmp, layer, diffID)
	if err != nil {
		return err
	}

	// 3. Import into the k3s containerd. Two mechanisms, in order:
	//    a) `k3s ctr images import` (supported path: handles the full OCI index
	//       and records the reference in the k8s.io namespace);
	//    b) fallback to the raw containerd import.
	//    We go through `k3s ctr` when available: it is the client aligned with
	//    the cluster runtime, which resolves the namespace correctly.
	imp := k8s.Command(ctx, "sh", "-c", strings.Join([]string{
		"(command -v k3s >/dev/null && sudo k3s ctr images import " + ociTar + ") ||",
		"(command -v ctr >/dev/null && sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images import " + ociTar + ") ||",
		"(sudo crictl -r unix:///run/k3s/containerd/containerd.sock --image-endpoint unix:///run/k3s/containerd/containerd.sock load " + ociTar + ")",
	}, " "))
	imp.Stdout = os.Stdout
	imp.Stderr = os.Stderr
	if err := imp.Run(); err != nil {
		return fmt.Errorf("containerd import: %w", err)
	}

	// 4. Verification: the image must be VISIBLE to the CRI, otherwise the pod
	//    would stay in ImagePullBackOff (the historical "resolver" bug).
	if !imagePresent(ctx) {
		return fmt.Errorf("image %s imported but not resolved by the CRI — "+
			"the pod would stay in ImagePullBackOff (reference not found in the k8s.io namespace)", imageRef)
	}
	return nil
}

// buildLayerFromBinary creates the minimal tar.gz layer: the binary + the CAs.
// Returns (compressed layer path, diffID = sha256 of the uncompressed tar).
//
// Caution: for a `tar+gzip` layer, `rootfs.diff_ids` must contain the SHA256
// of the NON-compressed tar (identifier of the uncompressed layer), while the
// manifest references the digest of the .tar.gz. Confusing the two makes the
// containerd import fail.
//
// The raw tar is held in memory (~40 MB binary: acceptable, and it avoids a
// second read pass), then compressed to the final file.
func buildLayerFromBinary(tmp, bin string) (layerPath, diffID string, err error) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)

	if err := addFileToTar(tw, bin, "usr/local/bin/ceffio"); err != nil {
		return "", "", err
	}
	for _, ca := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"} {
		if data, rerr := os.ReadFile(ca); rerr == nil {
			if err := tw.WriteHeader(&tar.Header{Name: "etc/ssl/certs/ca-certificates.crt", Mode: 0o644, Size: int64(len(data))}); err != nil {
				return "", "", err
			}
			if _, err := tw.Write(data); err != nil {
				return "", "", err
			}
			break
		}
	}
	if err := tw.Close(); err != nil {
		return "", "", err
	}

	// diff_id = sha256 of the uncompressed tar.
	sum := sha256.Sum256(raw.Bytes())
	diffID = hex.EncodeToString(sum[:])

	layerPath = filepath.Join(tmp, "layer.tar.gz")
	f, err := os.Create(layerPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		return "", "", err
	}
	if err := gz.Close(); err != nil {
		return "", "", err
	}
	return layerPath, diffID, nil
}

func addFileToTar(tw *tar.Writer, src, name string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// buildOCIImage assembles an OCI tar (oci-layout + index) importable by ctr.
//
// layerPath: the .tar.gz layer; diffID: sha256 of the UNCOMPRESSED tar
// (rootfs.diff_ids). The manifest, for its part, references the digest of the .tar.gz.
func buildOCIImage(tmp, layerPath, diffID string) (string, error) {
	layerSHA, layerSize, err := fileSHA256(layerPath)
	if err != nil {
		return "", err
	}

	config := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config": map[string]any{
			"Entrypoint": []string{"/usr/local/bin/ceffio"},
			"ExposedPorts": map[string]any{
				"8088/tcp": map[string]any{},
			},
		},
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []string{"sha256:" + diffID},
		},
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	configSHA := sha256Hex(configBytes)

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    "sha256:" + configSHA,
			"size":      len(configBytes),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest":    "sha256:" + layerSHA,
			"size":      layerSize,
		}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	manifestSHA := sha256Hex(manifestBytes)

	index := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    "sha256:" + manifestSHA,
			"size":      len(manifestBytes),
			"annotations": map[string]string{
				"org.opencontainers.image.ref.name": imageRef,
			},
			"platform": map[string]string{"architecture": "amd64", "os": "linux"},
		}},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		return "", err
	}

	out := filepath.Join(tmp, "image.tar")
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tw := tar.NewWriter(f)

	writeEntry := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := writeEntry("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return "", err
	}
	if err := writeEntry("index.json", indexBytes); err != nil {
		return "", err
	}
	if err := writeEntry("blobs/sha256/"+manifestSHA, manifestBytes); err != nil {
		return "", err
	}
	if err := writeEntry("blobs/sha256/"+configSHA, configBytes); err != nil {
		return "", err
	}
	// The layer is copied as-is (streaming, no RAM loading).
	if err := addFileToTar(tw, layerPath, "blobs/sha256/"+layerSHA); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	return out, nil
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func imagePresent(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "sh", "-c",
		"sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images ls -q | grep -F '"+imageRef+"'").CombinedOutput()
	return err == nil && strings.Contains(string(out), imageName)
}

// ensureConsoleKey guarantees the administration key IN THE VAULT, and nowhere else.
//
// IT IS REUSED IF IT EXISTS: it is what authenticates calls to the console
// API. Regenerating it would cut access without warning, and the symptom
// would be a 401 on a key that "looks" valid.
func ensureConsoleKey(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "console", "api")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("vault unreadable for console/api: %w", err)
	}
	if entree["key"] != "" {
		return nil
	}
	key, err := genSecret(32)
	if err != nil {
		return err
	}
	entree["key"] = key
	fmt.Println("∙ console administration key generated (missing from the vault)")
	return secrets.EcrireDansCoffre(ctx, coffre, "console", "api", entree)
}

// applyConsoleManifest applies RBAC + Deployment + Service + Ingress.
// NOTE on the Keycloak credentials: they are read LOCALLY (secret copied
// into this namespace before this manifest). A secretKeyRef cannot cross
// namespaces, and the secret lives in ceffio-identity while the console runs
// in ceffio-system — so the variables stayed empty, and the `optional: true`
// masked the failure: the pod started then answered "credentials missing" to
// every request. We do NOT set optional: a missing secret must fail the pod,
// not produce an unusable console.
func applyConsoleManifest(ctx context.Context, domain string) error {
	// THE SECRETS COME FROM THE VAULT, through the file the injector renders.
	//
	// THREE SOURCES: the console key, the Keycloak administration account, and
	// the Nextcloud service account. The console image contains NO shell: it
	// cannot "source" this file like the other components, it reads it itself
	// at startup, in the same format.
	annotations := vault.AnnotationsAgent(8, "console", "kv/data/ceffio/console/api",
		vault.GabaritMulti([]vault.Source{
			{Chemin: "kv/data/ceffio/console/api", Paires: [][2]string{
				{"CEFFIO_KEY", vault.ChampCoffre("key")},
			}},
			{Chemin: "kv/data/ceffio/keycloak/admin", Paires: [][2]string{
				{"KC_ADMIN", vault.ChampCoffre("username")},
				{"KC_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			}},
			{Chemin: "kv/data/ceffio/console/nextcloud-api", Paires: [][2]string{
				{"NC_USER", vault.ChampCoffre("username")},
				{"NC_PASSWORD", vault.ChampCoffre("password")},
			}},
		}))

	manifest := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ceffio-admin
rules:
- apiGroups: [""]
  resources: [pods, namespaces]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [ingresses]
  verbs: [get, list, watch]
- apiGroups: [cert-manager.io]
  resources: [certificates]
  verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ceffio-admin
subjects:
- kind: ServiceAccount
  name: ceffio-admin
  namespace: ` + deployNS + `
roleRef:
  kind: ClusterRole
  name: ceffio-admin
  apiGroup: rbac.authorization.k8s.io
---
# Right to run occ in the Nextcloud pod, LIMITED to this namespace.
#
# WHY HERE AND NOT IN THE ClusterRole: a ClusterRole applies to every
# namespace. On the contrary, we want to restrict this right to ceffio-files
# and to it alone — the console can exec in Nextcloud, never elsewhere. A
# local Role + RoleBinding express that.
#
# This right serves the SYSTEM settings of Nextcloud (mail_smtp*, which do not
# go through the OCS API). Application management does not need it.
#
# The right over Secrets is limited to ONE SINGLE one (resourceNames): the
# console re-reads the SMTP password to test a configuration without retyping
# it, but can NOT read the other Secrets of the namespace (database,
# encryption keys…).
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ceffio-console-occ
  namespace: ceffio-files
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: [get, list]
- apiGroups: [""]
  resources: [pods/exec]
  verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ceffio-console-occ
  namespace: ceffio-files
subjects:
- kind: ServiceAccount
  name: ceffio-admin
  namespace: ` + deployNS + `
roleRef:
  kind: Role
  name: ceffio-console-occ
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
  labels: {app: ceffio-admin}
spec:
  replicas: 1
  selector: {matchLabels: {app: ceffio-admin}}
  template:
    metadata:
      labels: {app: ceffio-admin}
      annotations:
` + annotations + `
    spec:
      serviceAccountName: ceffio-admin
      containers:
      - name: console
        image: ` + imageRef + `
        imagePullPolicy: IfNotPresent
        args: ["console", "--domain", "` + domain + `", "--addr", ":8088"]
        # NO SECRET VALUE HERE ANYMORE: they arrive through the file the
        # injector renders, and which the console reads itself at startup — its
        # image contains no shell, so it cannot "source" it
        # like the other components.
        ports:
        - {name: http, containerPort: 8088}
        readinessProbe:
          tcpSocket: {port: 8088}
          initialDelaySeconds: 5
          periodSeconds: 10
        resources: {limits: {memory: 128Mi}}
---
apiVersion: v1
kind: Service
metadata:
  name: ceffio-admin
  namespace: ` + deployNS + `
spec:
  selector: {app: ceffio-admin}
  ports:
  - {name: http, port: 8088, targetPort: 8088}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: admin
  namespace: ` + deployNS + `
  annotations:
    cert-manager.io/cluster-issuer: ceffio-ca-issuer
spec:
  ingressClassName: traefik
  tls:
  - hosts: [admin.` + domain + `]
    secretName: admin-tls
  rules:
  - host: admin.` + domain + `
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ceffio-admin
            port:
              number: 8088
`
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitConsoleReady(ctx context.Context) error {
	fmt.Println("∙ waiting for console pod Ready...")
	return k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/ceffio-admin", "-n", deployNS, "--timeout=180s").Run()
}

// genSecret is reused (same convention as the other layers).
func secretExists(ctx context.Context, name string) bool {
	return k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", deployNS).Run() == nil
}

// copierSecret copies a secret from one namespace to another.
//
// Why this detour: Kubernetes does NOT allow a secretKeyRef to cross
// namespaces. The keycloak-admin secret lives in ceffio-identity, the console
// runs in ceffio-system — so the reference stayed unfindable and the
// environment variables were empty, silently (all the more so since the
// reference carried `optional: true`).
//
// The copy is idempotent: we read the source and (re)apply the copy.
// No value is displayed or logged.
func copierSecret(ctx context.Context, nsSource, nom, nsCible string) error {
	if nsSource == nsCible {
		return nil
	}
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", nsSource,
		"-o", "json").Output()
	if err != nil {
		return fmt.Errorf("reading secret %s/%s: %w", nsSource, nom, err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		return fmt.Errorf("secret unreadable: %w", err)
	}
	// We clean the metadata specific to the source: keeping it would make the
	// copy carry the uid, timestamps and resourceVersion of the original,
	// which the API refuses at creation.
	delete(doc, "metadata")
	doc["metadata"] = map[string]any{
		"name":      nom,
		"namespace": nsCible,
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying secret to %s: %w: %s", nsCible, err, oneLine(string(out)))
	}
	fmt.Printf("✓ Secret %s copied to %s (references do not cross namespaces)\n", nom, nsCible)
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.TrimSpace(s)
}
