// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package backup backs up and restores a Ceffio installation.
//
// Principle: a backup is only a safety net if its restore has been
// exercised. This package therefore works in pairs — Sauvegarder writes a
// self-contained archive, Restaurer re-reads it and puts it back in place,
// verifying the integrity of each item along the way.
//
// What gets backed up, and why this choice:
//
//  1. The PostgreSQL databases (logical dump per database) — mysuite,
//     keycloak, nextcloud. This is the heart of the platform: identities,
//     accounts, file metadata, conversations.
//  2. The volumes (tar) — nextcloud-data (users' actual files),
//     onlyoffice-data. A SQL dump is not enough:
//     documents and attachments live on disk.
//  3. The application Secrets — without them, a restore leaves orphaned
//     data: the database passwords no longer match, the Matrix and
//     ONLYOFFICE signing keys no longer agree.
//  4. A manifest — versions, SHA-256 fingerprints and size of each item,
//     so we can say "the archive is complete" at restore time.
//
// Data is extracted via kubectl exec then streamed back: nothing is written
// to the node, which may not have the space.
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

// PostgreSQL databases of the platform. They all live in the CNPG cluster
// ceffio-pg; naming them explicitly avoids depending on a dynamic discovery
// that might one day include a technical database.
var Bases = []string{"mysuite", "keycloak", "nextcloud"}

// Volumes to back up: namespace, PVC name, and the useful subpath (some
// volumes hold, alongside the data, state of no interest).
var Volumes = []Volume{
	{Namespace: "ceffio-files", PVC: "nextcloud-data", PodLabel: "app=nextcloud",
		Path: "/var/www/html/data", UID: 33, GID: 33}, // www-data
	{Namespace: "ceffio-office", PVC: "onlyoffice-data", PodLabel: "app=onlyoffice",
		Path: "/var/lib/onlyoffice", UID: 0, GID: 0},
}

// Application Secrets: without them, the restored data is orphaned.
//
// List established from the cluster's real inventory (2026-10-07), and not
// from a guess: the database passwords, the OIDC credentials and the console
// key. TLS secrets are NOT listed: cert-manager regenerates them from the
// Certificates, which are themselves recreated by the deployment. Operator
// secrets (CNPG, webhooks, service tokens) are recreated by their respective
// operators.
var Secrets = []struct{ Name, Namespace string }{
	// database
	{"ceffio-pg-app", "ceffio-data"},
	// identity
	{"keycloak-admin", "ceffio-identity"},
	{"keycloak-db", "ceffio-identity"},
	// files
	{"nextcloud-admin", "ceffio-files"},
	{"nextcloud-db", "ceffio-files"},
	// office
	{"onlyoffice-secret", "ceffio-office"},
	// admin console
	{"ceffio-console-key", "ceffio-system"},
}

type Volume struct {
	Namespace string `json:"namespace"`
	PVC       string `json:"pvc"`
	PodLabel  string `json:"-"`
	Path      string `json:"path"`
	// UID/GID the application expects on this volume. Essential for
	// restore: without this restoration, the extracted files remain owned
	// by root and the application — which runs under another account —
	// loses write access (real case: Nextcloud 503ing after a restore).
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// Entry describes one backed-up item: this is what lets us verify the
// archive before restoring, rather than discovering a hole along the way.
type Entry struct {
	Kind      string `json:"kind"` // base | volume | secret
	Name      string `json:"name"`
	File      string `json:"file"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Rows      string `json:"rows,omitempty"` // databases: estimated row count
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

// Sauvegarder produces the archive and returns its path.
//
// progress receives one line per step (nil accepted).
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

	// 1. PostgreSQL databases.
	pod := pgPodName(ctx)
	if pod == "" {
		man.Errors = append(man.Errors, "PostgreSQL pod not found: databases not backed up")
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
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : no pod %s in %s", v.PVC, v.PodLabel, v.Namespace))
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

	// 3. Application secrets (essential: without them, orphaned data).
	progress("application secrets")
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

	// Final archive: everything is put into a single .tar.gz.
	name := fmt.Sprintf("ceffio-backup-%s.tar.gz", time.Now().Format("20060102-150405"))
	out := filepath.Join(dir, name)
	if err := compress(work, out); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(out)
	return abs, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verifier re-reads an archive and checks every fingerprint against the
// manifest. This is the check most backups lack: without it, we do not know
// whether the archive is usable until the day we need it.
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
		return nil, fmt.Errorf("manifest missing: unreadable archive")
	}
	var man Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return nil, fmt.Errorf("corrupt manifest: %w", err)
	}
	for i, e := range man.Entries {
		p := filepath.Join(dir, e.File)
		n, h, err := empreinte(p)
		if err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : missing file", e.Name))
			continue
		}
		if h != e.SHA256 {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : fingerprint differs (tampered archive)", e.Name))
			continue
		}
		if n != e.Bytes {
			man.Errors = append(man.Errors, fmt.Sprintf("%s : size differs", e.Name))
		}
		man.Entries[i] = e
	}
	man.Complete = len(man.Errors) == 0
	return &man, nil
}

// ---------------------------------------------------------------------------
// Internal tools
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
	// Stdout to the file, stderr captured SEPARATELY: you cannot wire
	// Stdout and call CombinedOutput() at the same time ("Stdout already
	// set").
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
	// tar -czf -: we write to the container's standard output, streamed back
	// as-is. The path is checked beforehand: no risk of writing to the node.
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
		return fmt.Errorf("empty archive (path %s missing in the pod?)", path)
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
		return fmt.Errorf("no secret backed up (missing: %s)", strings.Join(manques, ", "))
	}
	// A missing secret signals an uninstalled layer (video, for example): we
	// report it without failing the backup, since it is not an outage.
	_ = manques
	raw, _ := json.MarshalIndent(map[string]any{
		"secrets": all, "manquants": manques,
	}, "", "  ")
	os.MkdirAll(filepath.Dir(dst), 0o700)
	// 0600: this file contains secrets in cleartext, it must not be readable
	// by any account other than the backup's owner.
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

// query runs a SQL query against a given database and returns the raw
// result.
//
// Mind the order: the database name goes with `-d`, the query comes LAST.
// An earlier version passed the database as the first argument without `-d`,
// so psql read it as the SQL query and the real query became a stray
// argument — psql then exited successfully with an empty result, which made
// the bug invisible: the count returned 0 instead of failing.
func query(ctx context.Context, pod, base, sql string) string {
	a := []string{"exec", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", base, "-tAc", sql}
	out, err := kubectlOut(ctx, a...)
	if err != nil {
		return ""
	}
	return out
}

// DetectDomain infers the base domain from the ingresses.
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

// compress creates a .tar.gz from a directory.
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
		return fmt.Errorf("unreadable archive: %w", err)
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
		// Protection against a booby-trapped archive: a relative path that
		// escapes above the destination directory is refused.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf("archive refused: suspicious path %q", hdr.Name)
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
