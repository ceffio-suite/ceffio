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
	// Bump OBLIGATOIRE à chaque changement de la page ou du code console :
	// buildAndImportImage saute la reconstruction si le tag existe déjà dans
	// containerd. Sans bump, l'ancienne image continue de servir.
	imageTag = "1.32.2"
	imageRef = imageName + ":" + imageTag
)

// Deploy installe la console d'administration DANS le cluster (Phase 11) :
//   - image OCI locale (binaire + page web embarquée) importée dans containerd
//   - Deployment ceffio-admin + ServiceAccount + Role (lecture pods/ingress/certs)
//   - Secret ceffio-console-key (clé admin persistée) + env KC_ADMIN
//   - Service ClusterIP + Ingress admin.<domain> + certificat
//
// Remplace l'ancien modèle (systemd + Endpoints→nœud).
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDéploiement de la console d'administration (Phase 11)...")

	if err := buildAndImportImage(ctx); err != nil {
		return err
	}
	if err := ensureConsoleKey(ctx); err != nil {
		return err
	}
	// Les identifiants Keycloak vivent dans ceffio-identity ; la console tourne
	// dans ceffio-system et un secretKeyRef ne traverse PAS les namespaces. On
	// copie donc le secret chez la console : sans cette copie les variables
	// seraient vides et la console repondrait « credentials absents ».
	if err := copierSecret(ctx, "ceffio-identity", "keycloak-admin", deployNS); err != nil {
		return err
	}
	if err := applyConsoleManifest(ctx, domain); err != nil {
		return err
	}
	if err := waitConsoleReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Console d'administration déployée (https://admin." + domain + ")")
	return nil
}

// buildAndImportImage construit l'image OCI de la console et l'importe dans
// containerd k3s. Idempotent : saute si l'image est déjà présente.
//
// Contraintes de conception (apprises en from-scratch) — la machine cible est un
// serveur de PRODUCTION, pas un poste de dev :
//   - pas de toolchain Go : on ne compile PAS sur place. On réutilise le binaire
//     en cours d'exécution (os.Executable), qui est par construction un binaire
//     Ceffio pour la bonne plateforme. Exiger `go` faisait échouer la Phase 11
//     sur toute machine vierge (« exec: "go": executable file not found").
//   - pas de démon Docker : l'image est assemblée directement en OCI (tar) puis
//     importée dans le containerd de k3s via ctr. Exiger `docker build`/`save`
//     est injustifiable sur un hôte K3s.
func buildAndImportImage(ctx context.Context) error {
	if imagePresent(ctx) {
		fmt.Println("∙ image console déjà présente (" + imageRef + ")")
		return nil
	}
	fmt.Println("∙ construction + import de l'image console " + imageRef)

	// 1. Binaire à embarquer : celui qui tourne (déjà un exécutable Ceffio).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("binaire courant introuvable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if fi, err := os.Stat(self); err != nil || fi.Size() == 0 {
		return fmt.Errorf("binaire courant illisible (%s): %v", self, err)
	}

	// 2. Assemblage OCI minimal (Dockerfile FROM scratch équivalent), SANS Docker :
	//    config + layer tar.gz contenant /usr/local/bin/ceffio et les CA.
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

	// 3. Import dans containerd k3s. Deux mécanismes, dans l'ordre :
	//    a) `k3s ctr images import` (voie supportée : gère l'index OCI complet
	//       et enregistre la référence dans le namespace k8s.io) ;
	//    b) repli sur l'import brut containerd.
	//    On passe par `k3s ctr` quand disponible : c'est le client aligné sur le
	//    runtime du cluster, qui résout le namespace correctement.
	imp := k8s.Command(ctx, "sh", "-c", strings.Join([]string{
		"(command -v k3s >/dev/null && sudo k3s ctr images import " + ociTar + ") ||",
		"(command -v ctr >/dev/null && sudo ctr -n k8s.io -a /run/k3s/containerd/containerd.sock images import " + ociTar + ") ||",
		"(sudo crictl -r unix:///run/k3s/containerd/containerd.sock --image-endpoint unix:///run/k3s/containerd/containerd.sock load " + ociTar + ")",
	}, " "))
	imp.Stdout = os.Stdout
	imp.Stderr = os.Stderr
	if err := imp.Run(); err != nil {
		return fmt.Errorf("import containerd: %w", err)
	}

	// 4. Vérification : l'image doit être VISIBLE par le CRI, sinon le pod
	//    restera en ImagePullBackOff (le bug « resolver » historique).
	if !imagePresent(ctx) {
		return fmt.Errorf("image %s importée mais non résolue par le CRI — "+
			"le pod resterait en ImagePullBackOff (référence non trouvée dans le namespace k8s.io)", imageRef)
	}
	return nil
}

// buildLayerFromBinary crée la couche tar.gz minimale : le binaire + les CA.
// Retourne (chemin de la couche compressée, diffID = sha256 du tar décompressé).
//
// Attention : pour une couche `tar+gzip`, `rootfs.diff_ids` doit contenir le
// SHA256 du tar NON compressé (identifiant de la couche décompressée), tandis
// que le manifest référence le digest du .tar.gz. Confondre les deux fait
// échouer l'import containerd.
//
// Le tar brut est monté en mémoire (binaire ~40 Mo : acceptable, et cela évite
// une seconde passe de lecture), puis compressé vers le fichier final.
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

	// diff_id = sha256 du tar décompressé.
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
		return fmt.Errorf("lecture %s: %w", src, err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// buildOCIImage assemble un tar OCI (oci-layout + index) importable par ctr.
//
// layerPath : la couche .tar.gz ; diffID : sha256 du tar DÉCOMPRESSÉ
// (rootfs.diff_ids). Le manifest, lui, référence le digest du .tar.gz.
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
	// La couche est copiée telle quelle (streaming, pas de chargement en RAM).
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

// ensureConsoleKey garantit la clé d'administration DANS LE COFFRE, et nulle part ailleurs.
//
// ELLE EST REPRISE SI ELLE EXISTE : c'est elle qui authentifie les appels à l'API de
// la console. En régénérer une couperait l'accès sans prévenir, et le symptôme
// serait un 401 sur une clé qui « a l'air » valide.
func ensureConsoleKey(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "console", "api")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("coffre illisible pour console/api : %w", err)
	}
	if entree["key"] != "" {
		return nil
	}
	key, err := genSecret(32)
	if err != nil {
		return err
	}
	entree["key"] = key
	fmt.Println("∙ clé d'administration de la console générée (absente du coffre)")
	return secrets.EcrireDansCoffre(ctx, coffre, "console", "api", entree)
}

// applyConsoleManifest applique RBAC + Deployment + Service + Ingress.
// NOTE sur les identifiants Keycloak : ils sont lus LOCALEMENT (secret copié
// dans ce namespace avant ce manifeste). Un secretKeyRef ne peut pas traverser
// les namespaces, et le secret vit dans ceffio-identity alors que la console
// tourne dans ceffio-system — les variables restaient donc vides, et le
// `optional: true` masquait l'echec : le pod démarrait puis répondait
// « credentials absents » à chaque requête. On ne met PAS optional : un secret
// absent doit faire échouer le pod, pas produire une console inutilisable.
func applyConsoleManifest(ctx context.Context, domain string) error {
	// LES SECRETS VIENNENT DU COFFRE, à travers le fichier que l'injecteur rend.
	//
	// TROIS SOURCES : la clé de la console, le compte d'administration Keycloak, et
	// le compte de service Nextcloud. L'image de la console ne contient AUCUN shell :
	// elle ne peut pas « sourcer » ce fichier comme les autres composants, elle le
	// lit elle-même au démarrage, dans le même format.
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
# Droit d exécuter occ dans le pod Nextcloud, LIMITÉ à ce namespace.
#
# POURQUOI ICI ET PAS DANS LE ClusterRole : un ClusterRole s'applique à tous les
# namespaces. On veut au contraire restreindre ce droit à ceffio-files et à lui
# seul — la console peut exécuter dans Nextcloud, jamais ailleurs. C'est un
# Role + RoleBinding locaux qui l'expriment.
#
# Ce droit sert aux reglages SYSTEME de Nextcloud (mail_smtp*, qui ne passent
# pas par l'API OCS). La gestion des applications, elle, n en a pas besoin.
#
# Le droit sur les Secrets est limité à UN SEUL (resourceNames) : la console
# relit le mot de passe SMTP pour tester une configuration sans le ressaisir,
# mais ne peut PAS lire les autres Secrets du namespace (base de données,
# clés de chiffrement…).
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
        # PLUS AUCUNE VALEUR SECRÈTE ICI : elles arrivent par le fichier que
        # l'injecteur rend, et que la console lit elle-même au démarrage — son
        # image ne contient pas de shell, donc elle ne peut pas le « sourcer »
        # comme les autres composants.
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
	fmt.Println("∙ attente du pod console Ready...")
	return k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/ceffio-admin", "-n", deployNS, "--timeout=180s").Run()
}

// genSecret est réutilisé (même convention que les autres couches).
func secretExists(ctx context.Context, name string) bool {
	return k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", deployNS).Run() == nil
}

// copierSecret recopie un secret d'un namespace a un autre.
//
// Pourquoi ce detour : Kubernetes ne permet PAS a un secretKeyRef de traverser
// les namespaces. Le secret keycloak-admin vit dans ceffio-identity, la console
// tourne dans ceffio-system — la reference restait donc introuvable et les
// variables d'environnement étaient vides, en silence (d'autant plus que la
// reference portait `optional: true`).
//
// La copie est idempotente : on lit la source et on (re)applique la copie.
// Aucune valeur n'est affichee ni journalisee.
func copierSecret(ctx context.Context, nsSource, nom, nsCible string) error {
	if nsSource == nsCible {
		return nil
	}
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", nsSource,
		"-o", "json").Output()
	if err != nil {
		return fmt.Errorf("lecture du secret %s/%s : %w", nsSource, nom, err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		return fmt.Errorf("secret illisible : %w", err)
	}
	// On nettoie les metadonnees propres a la source : les garder ferait porter
	// a la copie l'uid, les timestamps et la resourceVersion d'origine, que
	// l'API refuse a la creation.
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
		return fmt.Errorf("copie du secret vers %s : %w : %s", nsCible, err, oneLine(string(out)))
	}
	fmt.Printf("✓ Secret %s copié dans %s (les références ne traversent pas les namespaces)\n", nom, nsCible)
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
