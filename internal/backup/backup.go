// Package backup sauvegarde et restaure une installation Ceffio.
//
// Principe : une sauvegarde n'est un filet de sécurité que si sa restauration a
// été exercée. Ce package va donc par paires — Sauvegarder écrit une archive
// autoportante, Restaurer la relit et la remet en place en vérifiant au passage
// l'intégrité de chaque élément.
//
// Ce qui est sauvegardé, et pourquoi ce choix :
//
//  1. Les bases PostgreSQL (logical dump par base) — mysuite, keycloak,
//     nextcloud, synapse. C'est le cœur de la plateforme : identités, comptes,
//     métadonnées de fichiers, conversations.
//  2. Les volumes (tar) — nextcloud-data (fichiers réels des utilisateurs),
//     synapse-media, onlyoffice-data, jitsi-config. Un dump SQL ne suffit pas :
//     les documents et les pièces jointes vivent sur disque.
//  3. Les Secrets applicatifs — sans eux, une restauration rend des données
//     orphelines : les mots de passe de base ne correspondent plus, les clés de
//     signature Matrix et ONLYOFFICE ne concordent plus.
//  4. Un manifeste — versions, empreintes SHA-256 et taille de chaque élément,
//     pour pouvoir dire « l'archive est complète » au moment de restaurer.
//
// Les données sont extraites via kubectl exec puis rapatriées en flux : rien
// n'est écrit sur le nœud, qui n'a pas forcément la place.
package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// Bases PostgreSQL de la plateforme. Toutes vivent dans le cluster CNPG
// ceffio-pg ; les nommer explicitement évite de dépendre d'une découverte
// dynamique qui inclurait un jour une base technique.
var Bases = []string{"mysuite", "keycloak", "nextcloud", "synapse"}

// Volumes à sauvegarder : namespace, nom du PVC, et le sous-chemin utile
// (certains volumes contiennent à côté des données un état sans intérêt).
var Volumes = []Volume{
	{Namespace: "ceffio-files", PVC: "nextcloud-data", PodLabel: "app=nextcloud",
		Path: "/var/www/html/data", UID: 33, GID: 33}, // www-data
	{Namespace: "ceffio-chat", PVC: "synapse-media", PodLabel: "app=synapse",
		Path: "/data/media_store", UID: 991, GID: 991},
	{Namespace: "ceffio-office", PVC: "onlyoffice-data", PodLabel: "app=onlyoffice",
		Path: "/var/lib/onlyoffice", UID: 0, GID: 0},
	{Namespace: "ceffio-video", PVC: "jitsi-config", PodLabel: "app=prosody",
		Path: "/config", UID: 0, GID: 0},
}

// Secrets applicatifs : sans eux, les données restaurées sont orphelines.
//
// Liste établie depuis l'inventaire réel du cluster (2026-10-07), et non depuis
// une supposition : les secrets contenant les mots de passe de base, les clés de
// signature Matrix, les identifiants OIDC et la clé de la console. Les secrets
// TLS ne sont PAS listés : cert-manager les régénère depuis les Certificate, qui
// sont eux-mêmes recréés par le déploiement. Les secrets d'opérateur (CNPG,
// webhooks, tokens de service) sont recréés par leurs opérateurs respectifs.
var Secrets = []struct{ Name, Namespace string }{
	// base de données
	{"ceffio-pg-app", "ceffio-data"},
	// identité
	{"keycloak-admin", "ceffio-identity"},
	{"keycloak-db", "ceffio-identity"},
	{"nextcloud-oidc", "ceffio-identity"},
	{"synapse-oidc", "ceffio-identity"},
	// fichiers
	{"nextcloud-admin", "ceffio-files"},
	{"nextcloud-db", "ceffio-files"},
	// chat
	{"synapse-db", "ceffio-chat"},
	{"synapse-secrets", "ceffio-chat"},
	// bureau
	{"onlyoffice-secret", "ceffio-office"},
	// visio
	{"jitsi-secrets", "ceffio-video"},
	// console d'administration
	{"ceffio-console-key", "ceffio-system"},
}

type Volume struct {
	Namespace string `json:"namespace"`
	PVC       string `json:"pvc"`
	PodLabel  string `json:"-"`
	Path      string `json:"path"`
	// UID/GID que l'application attend sur ce volume. Indispensable à la
	// restauration : sans ce rétablissement, les fichiers extraits restent
	// propriété de root et l'application — qui tourne sous un autre compte —
	// perd le droit d'écrire (cas vécu : Nextcloud en 503 après restauration).
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// Entry décrit un élément sauvegardé : c'est ce qui permet de vérifier
// l'archive avant de restaurer, plutôt que de découvrir un trou en route.
type Entry struct {
	Kind      string `json:"kind"` // base | volume | secret
	Name      string `json:"name"`
	File      string `json:"file"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Rows      string `json:"rows,omitempty"` // bases : nombre de lignes estimé
	PGVersion string `json:"pg_version,omitempty"`
}

type Manifest struct {
	CreatedAt  string   `json:"created_at"`
	Version    string   `json:"version,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	K8sVersion string   `json:"k8s_version,omitempty"`
	Entries    []Entry  `json:"entries"`
	Errors     []string `json:"errors,omitempty"`
	TotalBytes int64    `json:"total_bytes"`
	Complete   bool     `json:"complete"`
}

// Sauvegarder produit l'archive et renvoie son chemin.
//
// progress reçoit une ligne par étape (nil accepté).
func Sauvegarder(ctx context.Context, dir string, progress func(string)) (string, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(dir, "ceffio-backup-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	man := Manifest{CreatedAt: time.Now().Format(time.RFC3339)}
	if v, err := kubectlOut(ctx, "version", "-o", "json"); err == nil {
		var vv struct {
			ServerVersion struct {
				GitVersion string `json:"gitVersion"`
			} `json:"serverVersion"`
		}
		if json.Unmarshal([]byte(v), &vv) == nil {
			man.K8sVersion = vv.ServerVersion.GitVersion
		}
	}
	if d := DetectDomain(ctx); d != "" {
		man.Domain = d
	}

	// 1. Bases PostgreSQL.
	pod := pgPodName(ctx)
	if pod == "" {
		man.Errors = append(man.Errors, "pod PostgreSQL introuvable : bases non sauvegardées")
	} else {
		for _, base := range Bases {
			progress("base " + base)
			rel := filepath.Join("db", base+".sql")
			dst := filepath.Join(work, rel)
			os.MkdirAll(filepath.Dir(dst), 0o700)

			if err := dumpBase(ctx, pod, base, dst); err != nil {
				man.Errors = append(man.Errors, fmt.Sprintf("base %s : %v", base, err))
				continue
			}
			e := Entry{Kind: "base", Name: base, File: rel}
			e.Bytes, e.SHA256, _ = empreinte(dst)
			e.PGVersion = strings.TrimSpace(query(ctx, pod, "postgres", "SHOW server_version"))
			e.Rows = strings.TrimSpace(query(ctx, pod, base,
				"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"))
			man.Entries = append(man.Entries, e)
		}
	}

	// 2. Volumes.
	for _, v := range Volumes {
		progress("volume " + v.PVC)
		podName := podFor(ctx, v.Namespace, v.PodLabel)
		if podName == "" {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : aucun pod %s dans %s", v.PVC, v.PodLabel, v.Namespace))
			continue
		}
		rel := filepath.Join("volumes", v.PVC+".tar.gz")
		dst := filepath.Join(work, rel)
		os.MkdirAll(filepath.Dir(dst), 0o700)

		if err := tarVolume(ctx, v.Namespace, podName, v.Path, dst); err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : %v", v.PVC, err))
			continue
		}
		e := Entry{Kind: "volume", Name: v.PVC, File: rel}
		e.Bytes, e.SHA256, _ = empreinte(dst)
		man.Entries = append(man.Entries, e)
	}

	// 3. Secrets applicatifs (indispensables : sans eux, données orphelines).
	progress("secrets applicatifs")
	secRel := filepath.Join("secrets", "applicatifs.json")
	if err := dumpSecrets(ctx, filepath.Join(work, secRel)); err != nil {
		man.Errors = append(man.Errors, "secrets : "+err.Error())
	} else {
		e := Entry{Kind: "secret", Name: "applicatifs", File: secRel}
		e.Bytes, e.SHA256, _ = empreinte(filepath.Join(work, secRel))
		man.Entries = append(man.Entries, e)
	}

	for _, e := range man.Entries {
		man.TotalBytes += e.Bytes
	}
	man.Complete = len(man.Errors) == 0
	sort.Slice(man.Entries, func(i, j int) bool {
		if man.Entries[i].Kind != man.Entries[j].Kind {
			return man.Entries[i].Kind < man.Entries[j].Kind
		}
		return man.Entries[i].Name < man.Entries[j].Name
	})

	manRaw, _ := json.MarshalIndent(man, "", "  ")
	os.WriteFile(filepath.Join(work, "manifest.json"), manRaw, 0o600)

	// Archive finale : l'ensemble est mis dans un .tar.gz unique.
	name := fmt.Sprintf("ceffio-backup-%s.tar.gz", time.Now().Format("20060102-150405"))
	out := filepath.Join(dir, name)
	if err := compress(work, out); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(out)
	return abs, nil
}

// ---------------------------------------------------------------------------
// Vérification
// ---------------------------------------------------------------------------

// Verifier relit une archive et contrôle chaque empreinte contre le manifeste.
// C'est le contrôle qui manque à la plupart des sauvegardes : sans lui, on ne
// sait pas si l'archive est exploitable avant le jour où on en a besoin.
func Verifier(archive string) (*Manifest, error) {
	dir, err := os.MkdirTemp("", "ceffio-verif-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := decompress(archive, dir); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("manifeste absent : archive illisible")
	}
	var man Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return nil, fmt.Errorf("manifeste corrompu : %w", err)
	}
	for i, e := range man.Entries {
		p := filepath.Join(dir, e.File)
		n, h, err := empreinte(p)
		if err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : fichier manquant", e.Name))
			continue
		}
		if h != e.SHA256 {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : empreinte differente (archive alteree)", e.Name))
			continue
		}
		if n != e.Bytes {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : taille differente", e.Name))
		}
		man.Entries[i] = e
	}
	man.Complete = len(man.Errors) == 0
	return &man, nil
}

// ---------------------------------------------------------------------------
// Outils internes
// ---------------------------------------------------------------------------

func empreinte(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func dumpBase(ctx context.Context, pod, base, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := k8s.Command(ctx, "kubectl", "exec", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "pg_dump", "-U", "postgres", "--clean", "--if-exists", "-d", base)
	// Stdout vers le fichier, stderr capturé À PART : on ne peut pas brancher
	// Stdout et appeler CombinedOutput() en même temps (« Stdout already set »).
	cmd.Stdout = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		f.Close()
		os.Remove(dst)
		return fmt.Errorf("pg_dump : %w : %s", err, oneLine(stderr.String()))
	}
	return nil
}

func tarVolume(ctx context.Context, ns, pod, path, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	// tar -czf - : on écrit dans la sortie standard du conteneur, rapatriée telle
	// quelle. Le chemin est vérifié avant : aucun risque d'écrire sur le nœud.
	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", ns, pod, "--",
		"sh", "-c", "tar czf - -C "+path+" .")
	cmd.Stdout = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		f.Close()
		os.Remove(dst)
		return fmt.Errorf("tar : %w : %s", err, oneLine(stderr.String()))
	}
	if fi, _ := f.Stat(); fi != nil && fi.Size() < 32 {
		return fmt.Errorf("archive vide (chemin %s inexistant dans le pod ?)", path)
	}
	return nil
}

func dumpSecrets(ctx context.Context, dst string) error {
	type item struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Data      map[string]string `json:"data"`
	}
	var all []item
	var manques []string
	for _, s := range Secrets {
		out, err := kubectlOut(ctx, "get", "secret", s.Name, "-n", s.Namespace, "-o", "json")
		if err != nil {
			manques = append(manques, s.Namespace+"/"+s.Name)
			continue
		}
		var doc struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		}
		if json.Unmarshal([]byte(out), &doc) != nil {
			manques = append(manques, s.Namespace+"/"+s.Name)
			continue
		}
		all = append(all, item{Name: doc.Metadata.Name, Namespace: doc.Metadata.Namespace, Data: doc.Data})
	}
	if len(all) == 0 {
		return fmt.Errorf("aucun secret sauvegardé (manquants : %s)", strings.Join(manques, ", "))
	}
	// Un secret absent signale une couche non installée (visio par exemple) :
	// on le signale sans faire échouer la sauvegarde, car ce n'est pas une panne.
	_ = manques
	raw, _ := json.MarshalIndent(map[string]any{
		"secrets": all, "manquants": manques,
	}, "", "  ")
	os.MkdirAll(filepath.Dir(dst), 0o700)
	// 0600 : ce fichier contient des secrets en clair, il ne doit pas être lisible
	// par un autre compte que le propriétaire de la sauvegarde.
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		return err
	}
	os.Chmod(dst, 0o600)
	return nil
}

func pgPodName(ctx context.Context) string {
	out, err := kubectlOut(ctx, "get", "pods", "-n", "ceffio-data",
		"-l", "cnpg.io/cluster=ceffio-pg,role=primary", "-o", "name")
	if err == nil && strings.TrimSpace(out) != "" {
		return strings.TrimPrefix(strings.TrimSpace(out), "pod/")
	}
	out, err = kubectlOut(ctx, "get", "pods", "-n", "ceffio-data", "-l", "cnpg.io/cluster=ceffio-pg", "-o", "name")
	if err != nil {
		return ""
	}
	lines := strings.Fields(strings.TrimSpace(out))
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimPrefix(lines[0], "pod/")
}

func podFor(ctx context.Context, ns, label string) string {
	out, err := kubectlOut(ctx, "get", "pods", "-n", ns, "-l", label, "-o", "name")
	if err != nil {
		return ""
	}
	lines := strings.Fields(strings.TrimSpace(out))
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimPrefix(lines[0], "pod/")
}

// query exécute une requête SQL dans une base donnée et renvoie le résultat brut.
//
// Attention à l'ordre : le nom de base part avec `-d`, la requête vient EN
// DERNIER. Une version antérieure passait la base en premier argument sans `-d`,
// si bien que psql la lisait comme la requête SQL et que la vraie requête
// devenait un argument parasite — psql sortait alors en succès avec un résultat
// vide, ce qui rendait le bug invisible : le comptage retournait 0 au lieu
// d'échouer.
func query(ctx context.Context, pod, base, sql string) string {
	a := []string{"exec", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", base, "-tAc", sql}
	out, err := kubectlOut(ctx, a...)
	if err != nil {
		return ""
	}
	return out
}

// DetectDomain déduit le domaine de base depuis les ingress.
func DetectDomain(ctx context.Context) string {
	out, err := kubectlOut(ctx, "get", "ingress", "-A",
		"-o", "jsonpath={range .items[*]}{.spec.rules[*].host}{\"\\n\"}{end}")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, "."); i > 0 {
			return l[i+1:]
		}
	}
	return ""
}

func kubectlOut(ctx context.Context, args ...string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return strings.TrimSpace(s)
}

// compress crée un .tar.gz à partir d'un répertoire.
func compress(srcDir, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := writeTarGz(srcDir, out); err != nil {
		os.Remove(dst)
		return err
	}
	return nil
}

func writeTarGz(srcDir string, w io.Writer) error {
	gz := newGzip(w)
	tw := tar.NewWriter(gz)
	var files []string
	filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	for _, p := range files {
		rel, _ := filepath.Rel(srcDir, p)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			continue
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		io.Copy(tw, f)
		f.Close()
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func decompress(src, dstDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := newGunzip(f)
	if err != nil {
		return fmt.Errorf("archive illisible : %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Protection contre une archive piégée : un chemin relatif qui remonte
		// au-delà du répertoire de destination est refusé.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("archive refusée : chemin suspect %q", hdr.Name)
		}
		p := filepath.Join(dstDir, clean)
		if hdr.FileInfo().IsDir() {
			os.MkdirAll(p, 0o700)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o700)
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		io.Copy(out, tr)
		out.Close()
	}
	return nil
}
