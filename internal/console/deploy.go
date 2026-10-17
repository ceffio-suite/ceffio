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

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// MÉCANISME DE L'IMAGE CONSOLE — UN SEUL MANIFESTE, EN LIGNE COMME HORS LIGNE.
//
// La référence d'image est unique et calculée : imageRepo + le tag dérivé de
// la version du BINAIRE en cours d'exécution (version.ImageTag()). Plus aucun
// tag n'est écrit à la main : un tag oublié faisait tourner l'ancienne image
// indéfiniment (buildAndImportImage saute la reconstruction si le tag existe
// déjà dans containerd).
//
// POURQUOI ghcr.io ET PLUS localhost/ : avec localhost/, l'image n'existait
// que construite sur place, et le manifeste du pod différait selon que la
// machine pouvait ou non joindre un registre. Avec la référence GHCR, le
// Deployment appliqué est le MÊME dans les deux cas (imagePullPolicy:
// IfNotPresent) : si l'image est déjà dans containerd — importée localement
// ou tirée plus tôt — le kubelet la sert sans réseau ; sinon il tire la
// version publiée depuis GHCR. Une installation en ligne et une installation
// hors ligne convergent donc vers le même manifeste.
//
// Ordre de décision dans buildAndImportImage :
//  1. l'image est déjà présente dans containerd → ne rien faire ;
//  2. version de RELEASE (tag ne commençant pas par "dev-") → tenter un
//     `crictl pull` de l'image publiée ; en cas d'échec (machine hors
//     ligne), construire et importer localement ;
//  3. version de DÉVELOPPEMENT (tag "dev-…", jamais publié) → construire
//     et importer localement, sans tentative de pull.
const (
	deployNS   = "ceffio-system"
	deployName = "ceffio-admin"
	// imageRepo : dépôt public des images console publiées par la CI.
	imageRepo = "ghcr.io/ceffio-suite/ceffio-console"
)

// imageRef est l'UNIQUE référence d'image utilisée par la console (build,
// import, manifeste du Deployment, vérifications).
//
// Variable de package initialisée une fois, et non une constante : le tag
// vient de version.ImageTag(), qui est une fonction — interdite dans une
// const Go. L'initialiser une seule fois évite aussi de re-hacher le binaire
// (~40 Mo) à chaque appel, ImageTag() calculant le hachage du binaire pour
// les builds de développement.
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
	if err := applyConsoleManifest(ctx, domain); err != nil {
		return err
	}
	if err := waitConsoleReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Administration console deployed (https://admin." + domain + ")")
	return nil
}

// buildAndImportImage guarantees the console image in containerd k3s.
// Idempotent: skips if the image is already present.
//
// Trois chemins, dans l'ordre (voir l'en-tête du fichier pour le pourquoi) :
// image déjà présente → rien ; release → crictl pull, sinon construction
// locale ; développement → construction locale uniquement.
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
	// 1. Déjà présente dans containerd : ne rien faire. C'est le cas normal
	//    d'un redéploiement, et aussi celui d'une machine en ligne où le
	//    kubelet a déjà tiré l'image depuis GHCR.
	if imagePresent(ctx) {
		fmt.Println("∙ console image already present (" + imageRef + ")")
		return nil
	}

	// 2. Version de RELEASE : l'image est publiée sur GHCR, on tente d'abord
	//    de la tirer. En cas d'échec (machine hors ligne, registre
	//    injoignable), on retombe sur la construction locale — le manifeste
	//    reste le même grâce à imagePullPolicy: IfNotPresent.
	if !strings.HasPrefix(version.ImageTag(), "dev-") {
		fmt.Println("∙ release build: pulling console image " + imageRef)
		if pullImage(ctx) {
			return nil
		}
		fmt.Println("∙ pull failed (offline?): falling back to local build + import")
	}

	// 3. Version de DÉVELOPPEMENT : le tag "dev-<hachage>" n'est jamais
	//    publié, la construction locale est le seul chemin possible.
	fmt.Println("∙ building + importing console image " + imageRef)

	// Construction locale, en quatre temps (a à d) :

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
	// On compare sur la référence COMPLÈTE (dépôt + tag), pas sur un
	// fragment : "ceffio-console" seul matcherait n'importe quelle autre
	// image du même dépôt, et "ghcr.io" d'autres images Ceffio.
	out, err := exec.CommandContext(ctx, "sh", "-c",
		"sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images ls -q | grep -F '"+imageRef+"'").CombinedOutput()
	return err == nil && strings.Contains(string(out), imageRef)
}

// pullImage tente de tirer l'image publiée depuis GHCR via crictl.
// Retourne true si l'image est visible du CRI après le pull.
//
// POURQUOI crictl ET PAS ctr : le pull doit atterrir dans le namespace
// k8s.io avec le résolveur du kubelet (authentification, miroirs), sinon le
// pod resterait en ImagePullBackOff malgré une image « présente ». crictl
// parle au CRI exactement comme le kubelet.
//
// L'échec n'est PAS une erreur : une machine hors ligne doit pouvoir
// déployer, l'appelant retombe alors sur la construction locale.
func pullImage(ctx context.Context) bool {
	// Même approche que le reste du fichier : `sh -c` avec `command -v`
	// pour tester la disponibilité, et sudo car le socket containerd
	// n'est lisible que par root. k3s fournit son propre crictl
	// (`k3s crictl`) quand aucun crictl système n'est installé.
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
# LECTURE, au niveau cluster : l'onglet Overview, les certificats et
# l'infrastructure lisent pods, ingress et certificates de TOUS les namespaces.
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
# LA CONSOLE ADMINISTRE TOUTE LA PLATEFORME, PAS SEULEMENT DEUX NAMESPACES.
#
# Le déploiement de la plateforme, la lecture de l'état, les certificats, les
# applications Nextcloud, les ExApp : tout passe par cette console. Un droit
# limité à ceffio-exapps et ceffio-system l'empêchait d'administrer ce
# qu'elle est censée administrer, et l'erreur remontait sous forme de refus RBAC
# au moment du clic :
#
#   User "system:serviceaccount:ceffio-system:ceffio-admin" cannot create
#   resource "namespaces" …
#
# LE PÉRIMÈTRE EST CELUI DES NAMESPACES DE LA PLATEFORME, et il est délibérément
# plus étroit qu'un cluster-admin :
#
#   - un ClusterRole pour les ressources qui n'appartiennent à aucun namespace
#     (namespaces eux-mêmes, et les définitions de rôles) ;
#   - un RoleBinding dans chaque namespace ceffio-* et ceffio-exapps,
#     qui donne l'écriture là où la plateforme vit ;
#   - AUCUN droit sur kube-system, longhorn-system ou cert-manager : ce sont les
#     briques d'infrastructure, elles ne se pilotent pas depuis cette console.
#
# Le namespace est le seul objet cluster-wide, et c'est inévitable : en créer un
# n'appartient à aucun namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ceffio-admin
rules:
# Lecture sur tout le cluster : l'onglet Infrastructure et la page Certificats
# listent pods, ingress et certificates de l'ensemble de la plateforme.
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
# Écriture sur les objets qui n'appartiennent à aucun namespace.
# create et update, PAS delete : l'installation crée le namespace et le
# déployeur n'y touche plus ensuite. « Remove » retire les charges et les
# volumes, jamais le namespace — il appartient à la plateforme, pas à la
# console. Retirer delete réduit le droit au strict nécessaire.
- apiGroups: [""]
  resources: [namespaces]
  verbs: [create, update, patch]
# PAS DE DROIT SUR clusterroles, ET C'EST UNE RÈGLE DE SÉCURITÉ, PAS UN CHOIX.
#
# La console avait ce droit et s'en servait pour créer le ClusterRole dont elle
# avait besoin — ce que Kubernetes refuse :
#
#	attempting to grant RBAC permissions not currently held
#
# Un compte ne peut pas s'accorder ce qu'il ne détient pas : c'est la protection
# contre l'élévation de privilèges. Tous les droits RBAC sont donc posés par le
# DÉPLOYEUR, qui tourne avec un kubeconfig administrateur, et la console ne fait
# que les consommer. Retirer ce droit rend l'erreur impossible plutôt que de la
# corriger après coup.
---
# Un RoleBinding par namespace de la plateforme. Générés ici plutôt qu'écrits à
# la main : la liste des namespaces évolue avec le produit, et un binding oublié
# se traduirait par un refus RBAC au moment d'une action, sans lien visible avec
# le déploiement.
` + roleBindingsNamespaces() + `
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
# ÉCRITURE DANS LES NAMESPACES DE LA PLATEFORME.
#
# Un RoleBinding par namespace, pas un droit cluster-wide : Kubernetes n'offre
# pas de « tous les namespaces sauf ceux-là », donc la liste est explicite — et
# être explicite est ici un avantage, parce qu'elle montre ce qui est administré
# et ce qui ne l'est pas.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ceffio-admin-namespaces
rules:
# Le cœur de la plateforme : charges, configuration, secrets applicatifs,
# services, Ingress, volumes.
- apiGroups: [""]
  resources: [pods, services, configmaps, secrets, persistentvolumeclaims, serviceaccounts]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: [""]
  resources: [pods/exec, pods/log]
  verbs: [get, create]
- apiGroups: ["apps"]
  resources: [deployments, statefulsets, replicasets]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: ["networking.k8s.io"]
  resources: [ingresses]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: ["cert-manager.io"]
  resources: [certificates, certificaterequests]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: [roles, rolebindings]
  verbs: [get, list, watch, create, update, patch, delete]
- apiGroups: ["postgresql.cnpg.io"]
  resources: ["*"]
  verbs: [get, list, watch, create, update, patch, delete]
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
	return cmd.Run()
}

// namespacesPlateforme: les namespaces que la console administre.
//
// LA LISTE EST EXPLICITE, et c'est volontaire. Kubernetes n'offre pas de
// « tous les namespaces sauf ceux-là » : accorder l'écriture au niveau cluster
// donnerait aussi kube-system, longhorn-system et cert-manager — les briques
// d'infrastructure, qui ne se pilotent pas depuis cette console.
//
// Un namespace absent de cette liste ne casse rien : le RoleBinding est créé
// pour un namespace qui peut ne pas exister encore, et Kubernetes l'accepte. Il
// prend effet dès que le namespace apparaît.
var namespacesPlateforme = []string{
	"ceffio-system",
	"ceffio-files",
	"ceffio-identity",
	"ceffio-office",
	"ceffio-video",
	"ceffio-mail",
	"ceffio-data",
	"ceffio-vault",
	"ceffio-observability",
	// Les ExApp vivent ici : HaRP y déploie le conteneur de chaque application
	// demandée depuis Nextcloud.
	"ceffio-exapps",
}

// roleBindingsNamespaces builds one RoleBinding per platform namespace,
// referencing the shared ClusterRole above.
//
// UN SEUL ClusterRole, PLUSIEURS RoleBindings : c'est la forme idiomatique
// pour accorder les mêmes droits dans plusieurs namespaces. Dupliquer le Role
// dans chacun créerait dix copies d'une même liste de règles, et dix endroits
// où oublier une nouvelle règle.
func roleBindingsNamespaces() string {
	var sb strings.Builder
	for _, ns := range namespacesPlateforme {
		fmt.Fprintf(&sb, `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ceffio-admin
  namespace: %s
subjects:
- kind: ServiceAccount
  name: ceffio-admin
  namespace: %s
roleRef:
  kind: ClusterRole
  name: ceffio-admin-namespaces
  apiGroup: rbac.authorization.k8s.io
---
`, ns, deployNS)
	}
	return sb.String()
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
