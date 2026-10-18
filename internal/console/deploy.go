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
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// CONSOLE IMAGE MECHANISM — ONE SINGLE MANIFEST, ONLINE AS WELL AS OFFLINE.
//
// The image reference is unique and computed: imageRepo + the tag derived
// from the version of the BINARY currently running (version.ImageTag()). No
// tag is written by hand anymore: a forgotten tag kept the old image running
// indefinitely (buildAndImportImage skips the rebuild if the tag already
// exists in containerd).
//
// WHY ghcr.io AND NOT localhost/ ANYMORE: with localhost/, the image only
// existed once built on site, and the pod manifest differed depending on
// whether the machine could reach a registry or not. With the GHCR
// reference, the applied Deployment is the SAME in both cases
// (imagePullPolicy: IfNotPresent): if the image is already in containerd —
// imported locally or pulled earlier — the kubelet serves it without
// network; otherwise it pulls the published version from GHCR. An online
// installation and an offline installation therefore converge on the same
// manifest.
//
// Decision order in buildAndImportImage:
//  1. the image is already present in containerd → do nothing;
//  2. RELEASE version (tag not starting with "dev-") → attempt a
//     `crictl pull` of the published image; on failure (offline machine),
//     build and import locally;
//  3. DEVELOPMENT version (tag "dev-…", never published) → build and
//     import locally, with no pull attempt.
const (
	deployNS   = "ceffio-system"
	deployName = "ceffio-admin"
	// imageRepo: public repository of the console images published by the CI.
	imageRepo = "ghcr.io/ceffio-suite/ceffio"
)

// imageRef is the ONE AND ONLY image reference used by the console (build,
// import, Deployment manifest, verifications).
//
// A package variable initialized once, and not a constant: the tag comes
// from version.ImageTag(), which is a function — forbidden in a Go const.
// Initializing it once also avoids re-hashing the binary (~40 MB) on every
// call, ImageTag() computing the binary hash for development builds.
var imageRef = imageRepo + ":" + version.ImageTag()

// Deploy installs the administration console IN the cluster (Phase 11):
//   - console image (published on GHCR, or built locally + imported into
//     containerd — same reference either way, see file header)
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

	// BEFORE the manifest: the pod's agent template reads this secret at
	// startup, and a missing key leaves the pod in Init forever.
	if err := ensureNextcloudAccount(ctx); err != nil {
		return err
	}
	// The Keycloak credentials are read IN THE VAULT by the injector, like all
	// other components. The console is the ONLY service whose image contains
	// no shell: it cannot "source" /secrets/env, it reads it itself at startup
	// (secrets.ChargerDepuisFichier).

	// The namespace-scoped rights are the SUM of the module registry (see
	// AdminRights). Computed BEFORE the manifest: an empty sum must abort the
	// deployment, not ship a console that denies every action.
	rights, err := AdminRights()
	if err != nil {
		return err
	}
	if err := applyConsoleManifest(ctx, domain, rights); err != nil {
		return err
	}
	printGrantedRights(rights)
	if err := waitConsoleReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Administration console deployed (https://admin." + domain + ")")
	return nil
}

// buildAndImportImage guarantees the console image in containerd k3s.
// Idempotent: skips if the image is already present.
//
// Three paths, in order (see the file header for the why): image already
// present → nothing; release → crictl pull, otherwise local build;
// development → local build only.
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
	// 1. Already present in containerd: do nothing. This is the normal case
	//    of a redeployment, and also that of an online machine where the
	//    kubelet has already pulled the image from GHCR.
	if imagePresent(ctx) {
		fmt.Println("∙ console image already present (" + imageRef + ")")
		return nil
	}

	// 2. RELEASE version: the image is published on GHCR, we first try to
	//    pull it. On failure (offline machine, unreachable registry), we
	//    fall back to the local build — the manifest stays the same thanks
	//    to imagePullPolicy: IfNotPresent.
	if !strings.HasPrefix(version.ImageTag(), "dev-") {
		fmt.Println("∙ release build: pulling console image " + imageRef)
		if pullImage(ctx) {
			return nil
		}
		fmt.Println("∙ pull failed (offline?): falling back to local build + import")
	}

	// 3. DEVELOPMENT version: the tag "dev-<hash>" is never published, the
	//    local build is the only possible path.
	fmt.Println("∙ building + importing console image " + imageRef)

	// Local build, in four steps (a to d):

	// a. Binary to embed: the running one (already a Ceffio executable).
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

	// b. Minimal OCI assembly (Dockerfile FROM scratch equivalent), WITHOUT Docker:
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

	// c. Import into the k3s containerd. Two mechanisms, in order:
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

	// d. Verification: the image must be VISIBLE to the CRI, otherwise the pod
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
	// We compare on the COMPLETE reference (repository + tag), not on a
	// fragment: "ceffio" alone would match every other Ceffio image of the
	// same organisation, and "ghcr.io" all of them.
	out, err := exec.CommandContext(ctx, "sh", "-c",
		"sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images ls -q | grep -F '"+imageRef+"'").CombinedOutput()
	return err == nil && strings.Contains(string(out), imageRef)
}

// pullImage attempts to pull the published image from GHCR via crictl.
// Returns true if the image is visible to the CRI after the pull.
//
// WHY crictl AND NOT ctr: the pull must land in the k8s.io namespace with
// the kubelet's resolver (authentication, mirrors), otherwise the pod would
// stay in ImagePullBackOff despite an image "present". crictl talks to the
// CRI exactly like the kubelet.
//
// Failure is NOT an error: an offline machine must be able to deploy, and
// the caller then falls back to the local build.
func pullImage(ctx context.Context) bool {
	// Same approach as the rest of the file: `sh -c` with `command -v` to
	// test availability, and sudo because the containerd socket is only
	// readable by root. k3s ships its own crictl (`k3s crictl`) when no
	// system crictl is installed.
	pull := k8s.Command(ctx, "sh", "-c", strings.Join([]string{
		"(command -v crictl >/dev/null && sudo crictl pull " + imageRef + ") ||",
		"(command -v k3s >/dev/null && sudo k3s crictl pull " + imageRef + ")",
	}, " "))
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr
	if err := pull.Run(); err != nil {
		return false
	}
	return imagePresent(ctx)
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

// filesNS: the Nextcloud namespace. This package already addresses it by
// name in admin.go (pods, service) — named here too so the two do not drift.
const filesNS = "ceffio-files"

// ensureNextcloudAccount guarantees the Nextcloud service account the console
// authenticates with, AND ITS APPLICATION PASSWORD IN THE VAULT.
//
// THIS SECRET WAS NEVER PRODUCED BY ANYTHING. The Deployment's agent template
// declares it (kv/data/ceffio/console/nextcloud-api), so OpenBao's injector
// waited for a key that does not exist — silently and forever:
//
//	[WARN] agent: (view) vault.read(kv/data/ceffio/console/nextcloud-api):
//	       no secret exists at kv/data/...
//
// The console pod sat in Init:0/1 and the deployment ended on
// « waiting for console pod Ready... » with no explanation. The secret was
// expected, nothing created it, and the manifest could not start without it.
//
// Created here, idempotently, in this order:
//
//  1. an application password for the admin account, generated by Nextcloud
//     itself through occ (an app password, not the account password: it is
//     revocable on its own and does not lock the account out on rotation);
//  2. written to the vault at the path the agent reads.
//
// The admin account is used ONLY to mint that password. The console then
// authenticates with the application password alone — never with the admin
// credentials, whose secret is too broad.
func ensureNextcloudAccount(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	// Already there: reuse it. Regenerating on every run would revoke the
	// password the running console is using, and the symptom would be a 401
	// on a secret that "looks" valid.
	if entree, err := secrets.LireEntreeCoffre(ctx, coffre, "console", "nextcloud-api"); err == nil {
		if entree["username"] != "" && entree["password"] != "" {
			return nil
		}
	} else if !secrets.EntreeAbsente(err) {
		return fmt.Errorf("vault unreadable for console/nextcloud-api: %w", err)
	}

	// occ generates the application password itself and prints it on its own
	// line. NO ACCOUNT PASSWORD IS NEEDED: run without a TTY and without
	// --password-from-env, occ creates the token on its own and says so —
	//
	//   No password provided. The generated app password will therefore have
	//   limited capabilities.
	//
	// That limitation is exactly what we want here: the token opens the
	// Nextcloud API for the console and cannot be used to change the account
	// password. Passing the admin password instead would widen the token for
	// no reason, and would mean reading the admin secret on every deployment.
	cmd := k8s.Command(ctx, "kubectl", "-n", filesNS, "exec", "deploy/nextcloud", "-c", "nextcloud", "--",
		"php", "occ", "user:auth-tokens:add", "admin", "--name", "ceffio-console")
	sortie, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("creating the console application password: %w", err)
	}
	mdpApp := dernierJeton(string(sortie))
	if mdpApp == "" {
		return fmt.Errorf("occ returned no application password: %s", tronquer(string(sortie), 200))
	}

	fmt.Println("∙ Nextcloud service account for the console (application password)")
	return secrets.EcrireDansCoffre(ctx, coffre, "console", "nextcloud-api", map[string]string{
		"username": "admin",
		"password": mdpApp,
	})
}

// dernierJeton keeps the LAST line that looks like an application password.
//
// occ prints progress on stdout before the value, and the value itself is a
// 72-character alphanumeric group. Taking the last matching line avoids
// depending on the exact wording of the surrounding messages, which has
// changed between Nextcloud majors.
func dernierJeton(sortie string) string {
	jeton := ""
	for _, ligne := range strings.Split(sortie, "\n") {
		l := strings.TrimSpace(ligne)
		if len(l) < 40 {
			continue
		}
		alphanum := true
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				alphanum = false
				break
			}
		}
		if alphanum {
			jeton = l
		}
	}
	return jeton
}

// applyConsoleManifest applies RBAC + Deployment + Service + Ingress.
// NOTE on the Keycloak credentials: they are read LOCALLY (secret copied
// into this namespace before this manifest). A secretKeyRef cannot cross
// namespaces, and the secret lives in ceffio-identity while the console runs
// in ceffio-system — so the variables stayed empty, and the `optional: true`
// masked the failure: the pod started then answered "credentials missing" to
// every request. We do NOT set optional: a missing secret must fail the pod,
// not produce an unusable console.
func applyConsoleManifest(ctx context.Context, domain string, rights []NamespaceRights) error {
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
			// THE ACME SETTINGS OF THIS INSTALLATION, AND WHY THEY COME FROM
			// THE VAULT RATHER THAN FROM THE POD MANIFEST.
			//
			// The console container declares NO env at all: everything it reads
			// comes from the file the injector renders. Writing the challenge
			// into the Deployment would have worked for a fresh install and
			// broken every existing one — and worse, it would have made the
			// console report the DEFAULT while the ingress layer used another
			// value, which is precisely the divergence the TLS page exists to
			// prevent.
			//
			// The values are written by the installation (internal/vault) and
			// read back here, so the page always shows what the cluster is
			// actually configured with.
			{Chemin: "kv/data/ceffio/tls/acme", Paires: [][2]string{
				{"CEFFIO_ACME_CHALLENGE", vault.ChampCoffre("challenge")},
				{"CEFFIO_DNS_PROVIDER", vault.ChampCoffre("provider")},
				{"CEFFIO_DNS_ZONE", vault.ChampCoffre("zone")},
				{"CEFFIO_DNS_WEBHOOK_GROUP", vault.ChampCoffre("webhook_group")},
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
# READ, at cluster level: the Overview tab, the certificates and the
# infrastructure read pods, ingress and certificates of ALL namespaces.
- apiGroups: [""]
  resources: [pods, namespaces]
  verbs: [get, list, watch]
- apiGroups: ["apps"]
  resources: [deployments]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [ingresses]
  verbs: [get, list, watch]
- apiGroups: [cert-manager.io]
  resources: [certificates]
  verbs: [get, list, watch]
---
# THE CONSOLE ADMINISTERS THE WHOLE PLATFORM, NOT JUST TWO NAMESPACES.
#
# Deploying the platform, reading its state, the certificates, the Nextcloud
# applications, the ExApps: everything goes through this console. A right
# limited to ceffio-exapps and ceffio-system prevented it from administering
# what it is supposed to administer, and the error surfaced as an RBAC
# denial at the moment of the click:
#
#   User "system:serviceaccount:ceffio-system:ceffio-admin" cannot create
#   resource "namespaces" …
#
# THE SCOPE IS THAT OF THE PLATFORM NAMESPACES, and it is deliberately
# narrower than a cluster-admin:
#
#   - a ClusterRole for the resources that belong to no namespace
#     (the namespaces themselves, and the role definitions);
#   - a RoleBinding in each ceffio-* namespace and ceffio-exapps,
#     granting write access where the platform lives;
#   - NO right on kube-system, longhorn-system or cert-manager: those are
#     infrastructure building blocks, they are not driven from this console.
#
# The namespace is the only cluster-wide object, and that is unavoidable:
# creating one belongs to no namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ceffio-admin
rules:
# Cluster-wide read: the Infrastructure tab and the Certificates page
# list pods, ingress and certificates of the whole platform.
- apiGroups: [""]
  resources: [pods, namespaces]
  verbs: [get, list, watch]
- apiGroups: ["apps"]
  resources: [deployments]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [ingresses]
  verbs: [get, list, watch]
- apiGroups: [cert-manager.io]
  resources: [certificates]
  verbs: [get, list, watch]
# Write access on the objects that belong to no namespace.
# create and update, NOT delete: the installation creates the namespace and
# the deployer never touches it afterwards. "Remove" removes the workloads
# and the volumes, never the namespace — it belongs to the platform, not to
# the console. Removing delete reduces the right to the strict minimum.
- apiGroups: [""]
  resources: [namespaces]
  verbs: [create, update, patch]
# NO RIGHT ON clusterroles, AND THAT IS A SECURITY RULE, NOT A CHOICE.
#
# The console had this right and used it to create the ClusterRole it
# needed — which Kubernetes refuses:
#
#	attempting to grant RBAC permissions not currently held
#
# An account cannot grant itself what it does not hold: that is the
# protection against privilege escalation. All RBAC rights are therefore
# laid down by the DEPLOYER, which runs with an administrator kubeconfig,
# and the console only consumes them. Removing this right makes the error
# impossible rather than fixing it after the fact.
---
# NAMESPACE-SCOPED RIGHTS, GENERATED FROM THE MODULE REGISTRY.
#
# One Role + one RoleBinding per namespace, carrying the SUM of what every
# registered module declares in Info.Permissions (AdminRights below). They
# replace the hand-written ClusterRole ceffio-admin-namespaces and its ten
# RoleBindings: the console's rights now follow the catalog, so a module that
# appears, moves or disappears updates the grant with no edit here — and a
# hand-written binding forgotten used to surface only as an RBAC denial on the
# first click, with no visible link to the deployment. The exact-reproduction
# of the legacy grant is pinned by the non-regression test (rbac_nonregression_test.go).
` + AdminRolesManifest(rights) + `
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
    cert-manager.io/cluster-issuer: ` + ingress.PourDomaine(domain) + `
    traefik.ingress.kubernetes.io/router.middlewares: ceffio-system-ceffio-redirect-https@kubernetescrd
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
	if err := cmd.Run(); err != nil {
		return err
	}
	// The pre-registry ClusterRole ceffio-admin-namespaces and its RoleBindings
	// are deleted AFTER the new grant is applied: never leave a window where
	// the console holds neither.
	removeLegacyRBAC(ctx, rights)
	return nil
}

// printGrantedRights shows, per namespace, what the console may now do.
//
// WHY PRINT IT AT ALL: the grant is no longer a block of YAML an operator can
// read in this file — it is computed from the registry at deploy time. The
// printed list is what makes the computed privilege AUDITABLE on the very
// terminal that ran the installation, and what lets a future operator diff
// two installations when a module changed.
func printGrantedRights(rights []NamespaceRights) {
	fmt.Println("\n  CONSOLE RBAC — namespace-scoped rights (sum of the module registry)")
	fmt.Println("  ───────────────────────────────────────────────────────────────────")
	for _, r := range rights {
		fmt.Printf("  %s:\n", r.Namespace)
		for _, rule := range r.Rules {
			group := rule.APIGroups[0]
			if group == "" {
				group = "(core)"
			}
			fmt.Printf("    %-28s %-46s [%s]\n", group, strings.Join(rule.Resources, ", "), strings.Join(rule.Verbs, ", "))
		}
	}
	fmt.Println("  (cluster-scoped read rights and the occ account-management role stay in deploy.go)")
	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────
// CONSOLE RBAC, GENERATED FROM THE MODULE REGISTRY (batch B6).
//
// WHAT STAYS HARD-CODED, AND WHY: the cluster-scoped READ rights (the
// ClusterRole ceffio-admin above: pods, namespaces, deployments, ingresses,
// certificates for the dashboard and the certificates page), the namespace
// create/update/patch right, and the ceffio-console-occ Role (account
// management through occ in ceffio-files). These are the console's OWN
// rights: they exist for the console itself, not for any module it manages,
// so no module can declare them — and putting them in the registry would
// mean a module removal could blind the dashboard.
//
// Everything else — the write rights inside the platform namespaces — is
// the SUM of Info.Permissions across the registry, computed below.
// ─────────────────────────────────────────────────────────────────────────

// NamespaceRights is the complete set of rules the console holds in ONE
// namespace: the union of every module's Info.Permissions entries for that
// namespace, merged and canonically ordered.
type NamespaceRights struct {
	Namespace string
	Rules     []rbacv1.PolicyRule
}

// AdminRights computes the namespace-scoped rights of the console as the SUM
// of what every registered module declares in Info.Permissions.
//
// WHY THE SUM AND NOT A HAND-WRITTEN LIST: the console installs, observes
// and removes whatever the registry contains. A hand-written ClusterRole
// had to be updated by hand every time a module appeared or moved — and a
// forgotten line surfaced as an RBAC denial on the first click, far from
// the change that caused it. With the sum, the grant follows the catalog.
//
// The merge works on (namespace, apiGroup, resource, verb) TUPLES: two
// modules declaring the same right contribute it once, and a module
// declaring a subset of another's changes nothing. The result is therefore
// order-independent, and the non-regression test can compare it, tuple by
// tuple, with the grant the hand-written ClusterRole produced.
//
// An EMPTY sum is an error, not an empty manifest: deploying a console with
// no namespace-scoped rights would produce a product that denies every
// action, and the denial would look like a cluster problem, not like a
// registry problem.
func AdminRights() ([]NamespaceRights, error) {
	// namespace → apiGroup → resource → verb set.
	acc := map[string]map[string]map[string]map[string]bool{}

	for _, m := range moduleAll() {
		info := m.Info()
		for _, p := range info.Permissions {
			if p.Namespace == "" {
				continue
			}
			for _, rule := range p.Rules {
				// Rules narrowed to specific object names (or non-resource
				// URLs) are REFUSED rather than merged: the tuple model
				// cannot represent the restriction, and dropping
				// resourceNames would silently WIDEN the grant.
				if len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 {
					return nil, fmt.Errorf("module %q declares resourceNames/nonResourceURLs in namespace %s: AdminRights cannot merge those without widening them", info.ID, p.Namespace)
				}
				groups := rule.APIGroups
				if len(groups) == 0 {
					// An absent apiGroups list means the core group.
					groups = []string{""}
				}
				for _, g := range groups {
					for _, res := range rule.Resources {
						for _, verb := range rule.Verbs {
							if acc[p.Namespace] == nil {
								acc[p.Namespace] = map[string]map[string]map[string]bool{}
							}
							if acc[p.Namespace][g] == nil {
								acc[p.Namespace][g] = map[string]map[string]bool{}
							}
							if acc[p.Namespace][g][res] == nil {
								acc[p.Namespace][g][res] = map[string]bool{}
							}
							acc[p.Namespace][g][res][verb] = true
						}
					}
				}
			}
		}
	}

	if len(acc) == 0 {
		return nil, fmt.Errorf("no registered module declares Permissions: refusing to deploy the console with zero namespace-scoped rights (empty registry, or the modules lost their declarations)")
	}

	namespaces := make([]string, 0, len(acc))
	for ns := range acc {
		namespaces = append(namespaces, ns)
	}
	// Sorted: the generated YAML must be byte-identical between two runs,
	// or equality tests and `kubectl apply` diffs become unstable.
	sort.Strings(namespaces)

	out := make([]NamespaceRights, 0, len(namespaces))
	for _, ns := range namespaces {
		out = append(out, NamespaceRights{Namespace: ns, Rules: canonicalRules(acc[ns])})
	}
	return out, nil
}

// canonicalRules rebuilds PolicyRules from the accumulated tuples, in a
// deterministic order: apiGroups sorted (the core group "" first), then
// resources sharing the SAME verb set merged into one rule (the shape the
// hand-written ClusterRole had), sorted by verb set then by resource list.
func canonicalRules(byGroup map[string]map[string]map[string]bool) []rbacv1.PolicyRule {
	groups := make([]string, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	var rules []rbacv1.PolicyRule
	for _, g := range groups {
		// verbKey (sorted, comma-joined) → resources holding exactly those verbs.
		byVerbs := map[string][]string{}
		for res, verbs := range byGroup[g] {
			key := strings.Join(sortedSet(verbs), ",")
			byVerbs[key] = append(byVerbs[key], res)
		}
		keys := make([]string, 0, len(byVerbs))
		for k := range byVerbs {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			resources := byVerbs[k]
			sort.Strings(resources)
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups: []string{g},
				Resources: resources,
				Verbs:     strings.Split(k, ","),
			})
		}
	}
	return rules
}

// sortedSet returns the keys of a set, sorted — the small helper that makes
// every list leaving AdminRights deterministic.
func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AdminRolesManifest renders one Role + one RoleBinding per namespace,
// bound to the console's ServiceAccount (ceffio-admin in deployNS).
//
// Exported for the same reason AdminRights is: the non-regression test
// parses this exact YAML (what kubectl applies) back into rbacv1 objects and
// compares it with the legacy grant — proving the pipeline end to end, not
// just the intermediate data.
//
// WHY A Role PER NAMESPACE INSTEAD OF ONE ClusterRole + RoleBindings (the
// previous shape): the rights are no longer the same everywhere — each
// namespace carries exactly the sum its modules declared. A shared
// ClusterRole could only express the union of ALL namespaces, which would
// grant every module's rights everywhere: a wider privilege nobody decided.
//
// WHY THE OBJECTS ARE NAMED ceffio-console AND NOT ceffio-admin (the legacy
// binding name): a RoleBinding's roleRef is IMMUTABLE in Kubernetes.
// Re-applying the old bindings with a Role reference instead of the old
// ClusterRole reference would be rejected on every existing installation.
// Fresh names apply cleanly; removeLegacyRBAC deletes the old objects.
func AdminRolesManifest(rights []NamespaceRights) string {
	docs := make([]string, 0, 2*len(rights))
	for _, r := range rights {
		var role strings.Builder
		role.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: ceffio-console\n  namespace: " + r.Namespace + "\nrules:\n")
		for _, rule := range r.Rules {
			fmt.Fprintf(&role, "- apiGroups: [%s]\n  resources: [%s]\n  verbs: [%s]\n",
				quoteJoin(rule.APIGroups), quoteJoin(rule.Resources), quoteJoin(rule.Verbs))
		}
		docs = append(docs, role.String())
		docs = append(docs, fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ceffio-console
  namespace: %s
subjects:
- kind: ServiceAccount
  name: ceffio-admin
  namespace: %s
roleRef:
  kind: Role
  name: ceffio-console
  apiGroup: rbac.authorization.k8s.io
`, r.Namespace, deployNS))
	}
	return strings.Join(docs, "---\n")
}

// quoteJoin renders a YAML flow sequence with every element quoted: the
// wildcard resource "*" is not valid bare, and quoting uniformly keeps the
// output deterministic without per-element rules.
func quoteJoin(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = `"` + s + `"`
	}
	return strings.Join(quoted, ", ")
}

// removeLegacyRBAC deletes the pre-registry namespace grant: the ClusterRole
// ceffio-admin-namespaces and the RoleBindings ceffio-admin that referenced
// it in every platform namespace.
//
// WHY DELETE RATHER THAN LEAVE: the stale objects grant exactly the rights
// the generated Roles now grant, so leaving them would not break anything —
// but the cluster would carry two overlapping grants, and the day the
// registry NARROWS a right, the stale ClusterRole would silently keep it
// alive. Deleting it is what makes the registry the single source of the
// console's namespace-scoped rights.
//
// BEST-EFFORT, deliberately: on a fresh installation the objects do not
// exist (--ignore-not-found), and a cleanup failure must not turn a
// successful deployment into a failure. Deleting the ClusterRole alone
// neutralizes every stale binding — a RoleBinding referencing a nonexistent
// role grants nothing — including in namespaces the registry no longer
// covers.
func removeLegacyRBAC(ctx context.Context, rights []NamespaceRights) {
	deleteQuietly := func(args ...string) {
		cmd := k8s.Command(ctx, "kubectl", append([]string{"delete", "--ignore-not-found"}, args...)...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run()
	}
	deleteQuietly("clusterrole", "ceffio-admin-namespaces")
	for _, r := range rights {
		deleteQuietly("rolebinding", "ceffio-admin", "--namespace", r.Namespace)
	}
}

func waitConsoleReady(ctx context.Context) error {
	fmt.Println("∙ waiting for console pod Ready...")
	return k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/ceffio-admin", "-n", deployNS, "--timeout=600s").Run()
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
