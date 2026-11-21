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
//     keycloak, nextcloud, openproject. This is the heart of the platform:
//     identities, accounts, file metadata, conversations, projects. Some of
//     them belong to OPTIONAL modules: a database that does not exist on the
//     installation is skipped, not reported as a failure (see Bases).
//  2. The volumes (tar) — nextcloud-data (users' actual files),
//     onlyoffice-data, stalwart-data (the mail server's RocksDB store and
//     blobs), openproject-assets (projects' attachments, which no SQL dump
//     carries). A SQL dump is not enough: documents, attachments and
//     messages live on disk.
//  3. The application Secrets — without them, a restore leaves orphaned
//     data: the database passwords no longer match, the Matrix and
//     ONLYOFFICE signing keys no longer agree.
//  4. The vault's key-value tree — the platform's non-regenerable
//     credentials (OIDC secrets, relay credentials, DKIM keys). Backing up
//     workloads without it restores an installation that starts and whose
//     integrations fail, with no error naming the vault.
//  5. A manifest — versions, SHA-256 fingerprints and size of each item,
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
	"errors"
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
//
// THE LIST IS A CONSTANT, THE INSTALLATION DECIDES. nextcloud belongs to the
// optional `files` chain and openproject to the optional `openproject` module:
// on an installation without them, `pg_dump` would fail with "database does
// not exist" and EVERY backup would be marked incomplete — which makes the
// safety net look broken, and a restore refuse an archive that is in fact
// fine. The presence of each database is therefore checked on the cluster
// before dumping (see basesPresentes); a database that exists but cannot be
// read stays an error.
var Bases = []string{"mysuite", "keycloak", "nextcloud", "openproject"}

// Volumes to back up: namespace, PVC name, and the useful subpath (some
// volumes hold, alongside the data, state of no interest).
//
// A VOLUME WHOSE MODULE IS NOT INSTALLED IS SKIPPED, not failed: mail and
// openproject are optional, so their volumes do not exist on every
// installation. The distinction we keep is between "no PVC: nothing to save"
// and "a PVC with no pod: data we cannot read" — the second is a real error,
// because a backup that silently drops a volume existing on the cluster is
// exactly the one discovered at restore time. See sauvegarderVolume.
//
// WHY stalwart-data DECLARES StopWorkload AND THE OTHERS DO NOT. Nextcloud and
// ONLYOFFICE keep file trees: copying them while the application runs is
// imperfect but the result is a coherent-enough archive, and stopping the
// application would be a bigger risk than the one it removes. Stalwart keeps a
// RocksDB store and a local blob store: a copy taken while it runs is not a
// backup, it is a file of unknown validity — tar exits 0 and the store does not
// open. Measured in POC K of docs/plan-mail.md, hence the stop/copy/restart
// sequence implemented in arret.go.
var Volumes = []Volume{
	{Namespace: "ceffio-files", PVC: "nextcloud-data", PodLabel: "app=nextcloud",
		Path: "/var/www/html/data", UID: 33, GID: 33}, // www-data
	{Namespace: "ceffio-office", PVC: "onlyoffice-data", PodLabel: "app=onlyoffice",
		Path: "/var/lib/onlyoffice", UID: 0, GID: 0},
	{Namespace: "ceffio-mail", PVC: "stalwart-data", PodLabel: "app=stalwart",
		Path: "/var/lib/stalwart", UID: 2000, GID: 2000, StopWorkload: "stalwart"},
	// OpenProject keeps its attachments outside the database: a dump alone
	// restores projects whose work packages point at documents that are no
	// longer there. A LIVE COPY IS ACCEPTED, like Nextcloud and ONLYOFFICE:
	// each attachment is a whole file written once under its own name, so a
	// copy taken while the application runs misses at worst the attachment
	// being uploaded at that instant — stopping the application would cost
	// more than it protects.
	//
	// The service account and the pod run as UID 1000 (fsGroup included): the
	// restore chowns to that account, without which Puma and the worker lose
	// write access to their own attachments.
	{Namespace: "ceffio-system", PVC: "openproject-assets", PodLabel: "app=openproject",
		Path: "/var/openproject/assets", UID: 1000, GID: 1000},
}

// Application Secrets: without them, the restored data is orphaned.
//
// List established from the cluster's real inventory (2026-10-07), and not
// from a guess: the database passwords, the OIDC credentials and the console
// key. TLS secrets are NOT listed: cert-manager regenerates them from the
// Certificates, which are themselves recreated by the deployment. Operator
// secrets (CNPG, webhooks, service tokens) are recreated by their respective
// operators.
//
// MODULE SETTINGS ARE INCLUDED, because nothing recreates them: they are what
// an OPERATOR typed — a relay host, a DNS credential, a challenge choice. A
// restore that brings back the workloads without them leaves an installation
// that looks whole and behaves differently, and the operator has no way of
// knowing which values are missing. See internal/settings for where they live.
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
	// vault: the token that re-reads the backed-up tree after a restore, and
	// the unseal key the vault needs to start. Both are SECRETS ALREADY ON THE
	// MACHINE — what stays excluded is the recovery keys, which are not on the
	// machine and are the only way back in if the vault is lost (docs/secrets.md).
	{"openbao-token", "ceffio-vault"},
	{"openbao-unseal-key", "ceffio-vault"},
	// module settings, when no vault is configured: one Secret per module
	// (`ceffio-settings-<module>`), holding the groups with secret fields.
	// Enumerated at backup time rather than listed here — the modules are a
	// registry, and a list written by hand would go stale the day one is added.
}

// configMapsCeffio lists the ConfigMaps carrying operator settings.
//
// WHY THEY ARE NOT IN Secrets: they hold no credential, but they hold choices —
// and a restore that loses them silently changes the behaviour of a module that
// is otherwise installed correctly.
var ConfigMapsCeffio = []struct{ Name, Namespace string }{
	{"ceffio-settings", "ceffio-system"},
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
	// Deployment to stop while this volume is copied, empty when a live copy
	// is acceptable. See the comment on Volumes for why the mail server needs
	// it and the others do not.
	StopWorkload string `json:"-"`
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
		// WHICH DATABASES THIS INSTALLATION HAS comes from the cluster, not
		// from the list: an optional module that is not installed leaves no
		// database behind, and dumping it would fail — which would mark every
		// backup incomplete and make a restore refuse a sound archive. If the
		// cluster cannot answer, every database of the list is still
		// attempted: the error is reported here, and the dumps that fail say
		// so too.
		presentes, errListe := basesPresentes(ctx, pod)
		if errListe != nil {
			man.Errors = append(man.Errors, "bases : "+errListe.Error())
		}
		gardees, absentes := filtrerBases(presentes)
		for _, base := range absentes {
			progress("base " + base + " : absente, rien à sauvegarder")
		}
		for _, base := range gardees {
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
		rel := filepath.Join("volumes", v.PVC+".tar.gz")
		dst := filepath.Join(work, rel)
		os.MkdirAll(filepath.Dir(dst), 0o700)

		if err := sauvegarderVolume(ctx, v, dst, progress); err != nil {
			// No PVC means the module is not installed: nothing to save, and
			// calling it a failure would make the archive unrestorable. A
			// volume that exists but has no pod stays an error (see
			// sauvegarderVolume).
			if errors.Is(err, errVolumeAbsent) {
				progress("volume " + v.PVC + " : absent, rien à sauvegarder")
				continue
			}
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

	// 4. Operator settings ConfigMaps.
	//
	// They hold no credential but they hold CHOICES: a challenge type, a DNS
	// zone, a feature's mode. A restore that brings back the workloads without
	// them leaves an installation that looks whole and behaves differently —
	// and nothing tells the operator which values are missing.
	progress("module settings")
	settingsRel := filepath.Join("configmaps", "ceffio-settings.json")
	if err := dumpConfigMaps(ctx, filepath.Join(work, settingsRel)); err != nil {
		// An installation with no settings has none of these objects, which is
		// a normal state, not a failure: the file is simply absent.
		if !strings.Contains(err.Error(), "no configmap") {
			man.Errors = append(man.Errors, "configmaps : "+err.Error())
		}
	} else {
		e := Entry{Kind: "configmap", Name: "ceffio-settings", File: settingsRel}
		e.Bytes, e.SHA256, _ = empreinte(filepath.Join(work, settingsRel))
		man.Entries = append(man.Entries, e)
	}

	// 5. The vault's key-value tree.
	//
	// A vault that is not deployed is not a failure: an installation may not
	// have one. A vault that IS deployed but does not answer is a failure, and
	// it is reported as such — the operator asked for a complete backup.
	progress("vault entries")
	vaultRel := filepath.Join("vault", "kv-ceffio.json")
	if err := dumpCoffre(ctx, filepath.Join(work, vaultRel)); err != nil {
		if !errors.Is(err, errCoffreAbsent) {
			man.Errors = append(man.Errors, "vault : "+err.Error())
		}
	} else {
		e := Entry{Kind: "vault", Name: "kv-ceffio", File: vaultRel}
		e.Bytes, e.SHA256, _ = empreinte(filepath.Join(work, vaultRel))
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
	//
	// The command goes through executerKubectl (the package's seam) rather than
	// k8s.Command directly: the same function then serves the live volumes and
	// the stopped mail volume, and the mail path is testable without a cluster.
	if err := executerKubectl(ctx, nil, f, "exec", "-n", ns, pod, "--",
		"sh", "-c", "tar czf - -C "+path+" ."); err != nil {
		f.Close()
		os.Remove(dst)
		return fmt.Errorf("tar : %w", err)
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

	// The list, PLUS the module settings Secrets discovered on the cluster.
	//
	// WHY DYNAMICALLY: `ceffio-settings-<module>` exists once a module with
	// settings has saved one, and the modules come from a registry. A list
	// written by hand here would go stale the day one is added — and the
	// failure is silent: the backup reports success and the operator discovers
	// the loss only when a restore comes up with settings they never chose.
	cibles := append([]struct{ Name, Namespace string }{}, Secrets...)
	sortie, err := kubectlOut(ctx, "get", "secrets", "-n", "ceffio-system",
		"-l", "app.kubernetes.io/part-of=ceffio", "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}")
	if err == nil {
		for _, nom := range strings.Split(strings.TrimSpace(sortie), "\n") {
			nom = strings.TrimSpace(nom)
			if strings.HasPrefix(nom, "ceffio-settings-") {
				cibles = append(cibles, struct{ Name, Namespace string }{nom, "ceffio-system"})
			}
		}
	}

	for _, s := range cibles {
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

// dumpConfigMaps backs up the ConfigMaps holding operator settings.
//
// They hold no credential, so the file is written 0644 rather than 0600 — but
// they are backed up for the same reason as the secrets: nothing recreates them,
// and losing them silently changes how an installation behaves.
func dumpConfigMaps(ctx context.Context, dst string) error {
	type item struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Data      map[string]string `json:"data"`
	}
	var all []item
	for _, c := range ConfigMapsCeffio {
		out, err := kubectlOut(ctx, "get", "configmap", c.Name, "-n", c.Namespace, "-o", "json")
		if err != nil {
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
			continue
		}
		all = append(all, item{Name: doc.Metadata.Name, Namespace: doc.Metadata.Namespace, Data: doc.Data})
	}
	if len(all) == 0 {
		return fmt.Errorf("no configmap backed up")
	}
	raw, _ := json.MarshalIndent(map[string]any{"configmaps": all}, "", "  ")
	os.MkdirAll(filepath.Dir(dst), 0o700)
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		return err
	}
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

// basesPresentes lists the databases the cluster actually holds.
//
// ONE psql call, not one per database: asking "does this database exist?"
// separately would make a failing connection indistinguishable from an
// absence, and the wrong answer here silently drops data from the archive.
func basesPresentes(ctx context.Context, pod string) (map[string]bool, error) {
	out, err := sortieKubectl(ctx, "exec", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", "postgres", "-tAc", "SELECT datname FROM pg_database")
	if err != nil {
		return nil, fmt.Errorf("listing the databases: %w", err)
	}
	presentes := map[string]bool{}
	for _, ligne := range strings.Split(out, "\n") {
		if nom := strings.TrimSpace(ligne); nom != "" {
			presentes[nom] = true
		}
	}
	return presentes, nil
}

// filtrerBases splits the constant list into the databases to dump and the
// ones to skip.
//
// A nil map means the listing failed: every database of the list is then
// attempted rather than silently dropped, and the caller reports the failure.
func filtrerBases(presentes map[string]bool) (gardees, absentes []string) {
	if presentes == nil {
		return Bases, nil
	}
	for _, base := range Bases {
		if presentes[base] {
			gardees = append(gardees, base)
		} else {
			absentes = append(absentes, base)
		}
	}
	return gardees, absentes
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
