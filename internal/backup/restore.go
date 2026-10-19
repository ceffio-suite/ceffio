// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// Restaurer puts a backup back in place.
//
// Order imposed by dependencies, not by convenience:
//  1. Secrets first — restored databases are useless if the application
//     passwords no longer match;
//  2. databases next — identities, accounts, metadata;
//  3. volumes last — the documents, which reference the metadata.
//
// Restoring the databases is DESTRUCTIVE (pg_restore --clean): the caller
// must have confirmed. The CLI handles that; this function does not do it in
// its place — but it says so in its report.
func Restaurer(ctx context.Context, archive string, progress func(string)) (*Manifest, error) {
	if progress == nil {
		progress = func(string) {}
	}

	// Verification first: restoring an incomplete archive would only add an
	// outage to the outage.
	man, err := Verifier(archive)
	if err != nil {
		return nil, err
	}
	if len(man.Errors) > 0 {
		return man, fmt.Errorf("incomplete or tampered archive: %s", strings.Join(man.Errors, " ; "))
	}

	work, err := os.MkdirTemp("", "ceffio-restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	if err := decompress(archive, work); err != nil {
		return nil, err
	}

	pod := pgPodName(ctx)
	if pod == "" {
		return man, fmt.Errorf("PostgreSQL pod not found: cannot restore the databases")
	}

	// 1. Secrets.
	progress("application secrets")
	if err := restoreSecrets(ctx, filepath.Join(work, "secrets/applicatifs.json"), &man.Errors); err != nil {
		man.Errors = append(man.Errors, "secrets : "+err.Error())
	}

	// 2. Databases.
	for _, e := range man.Entries {
		if e.Kind != "base" {
			continue
		}
		progress("base " + e.Name)
		if err := restoreBase(ctx, pod, e.Name, filepath.Join(work, e.File)); err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("base %s : %v", e.Name, err))
		}
	}

	// 3. Volumes.
	for _, e := range man.Entries {
		if e.Kind != "volume" {
			continue
		}
		v, ok := volumeByName(e.Name)
		if !ok {
			man.Errors = append(man.Errors, "unknown volume: "+e.Name)
			continue
		}
		progress("volume " + e.Name)
		podName := podFor(ctx, v.Namespace, v.PodLabel)
		if podName == "" {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : no pod %s", e.Name, v.PodLabel))
			continue
		}
		if err := restoreVolume(ctx, v, podName, filepath.Join(work, e.File)); err != nil {
			man.Errors = append(man.Errors, fmt.Sprintf("volume %s : %v", e.Name, err))
		}
	}

	man.Complete = len(man.Errors) == 0
	return man, nil
}

func volumeByName(name string) (Volume, bool) {
	for _, v := range Volumes {
		if v.PVC == name {
			return v, true
		}
	}
	return Volume{}, false
}

// restoreSecrets re-applies the Secrets, creating the missing namespaces.
//
// It ALSO restores the settings ConfigMap, because it is the same kind of object
// at the same level of importance — operator settings that nothing recreates.
// A separate step would be a second place to call from the restore sequence, and
// one of them would eventually be forgotten.
func restoreSecrets(ctx context.Context, path string, errs *[]string) error {
	// The archive keeps it one level up, under configmaps/.
	cmPath := filepath.Join(filepath.Dir(filepath.Dir(path)), "configmaps", "ceffio-settings.json")
	if err := restoreConfigMaps(ctx, cmPath, errs); err != nil {
		*errs = append(*errs, err.Error())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("secrets file missing from the archive")
	}
	var doc struct {
		Secrets []struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Data      map[string]string `json:"data"`
		} `json:"secrets"`
		Manquants []string `json:"manquants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	// Secrets absent from the backup correspond to layers not installed at
	// backup time (e.g. video without --video). This is not a restore
	// error: we report it without blocking.
	if len(doc.Manquants) > 0 {
		fmt.Printf("  (secrets not present in the backup: %s)\n", strings.Join(doc.Manquants, ", "))
	}
	for _, s := range doc.Secrets {
		// The namespace may not exist on a freshly rebuilt machine.
		kubectlOut(ctx, "create", "namespace", s.Namespace)

		// Straight replacement rather than `kubectl apply`: apply refuses an
		// object created imperatively (missing last-applied-configuration
		// annotation). And that is precisely the case here — the Secrets
		// were created by `kubectl create secret` at install time. We delete
		// then recreate, which restores EXACTLY the saved state.
		kubectlOut(ctx, "delete", "secret", s.Name, "-n", s.Namespace, "--ignore-not-found")

		obj := map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata":   map[string]any{"name": s.Name, "namespace": s.Namespace},
			"type":       "Opaque",
			"data":       s.Data,
		}
		b, _ := json.Marshal(obj)
		cmd := k8s.Command(ctx, "kubectl", "create", "-f", "-")
		cmd.Stdin = strings.NewReader(string(b))
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := oneLine(stderr.String())
			// "AlreadyExists" can no longer happen after the delete, but we
			// tolerate any partially successful message.
			if !strings.Contains(msg, "AlreadyExists") {
				*errs = append(*errs, fmt.Sprintf("secret %s/%s : %s", s.Namespace, s.Name, msg))
			}
		}
	}
	return nil
}

// restoreConfigMaps re-applies the settings ConfigMaps.
//
// A missing file is NOT an error: an installation where no module has saved a
// setting yet has no such object, and a restore on a fresh machine must not fail
// because of it. That is the difference with the Secrets file, whose absence
// means the archive itself is incomplete.
func restoreConfigMaps(ctx context.Context, path string, errs *[]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading the settings configmap: %w", err)
	}
	var doc struct {
		ConfigMaps []struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Data      map[string]string `json:"data"`
		} `json:"configmaps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("the settings configmap file is not valid: %w", err)
	}

	for _, c := range doc.ConfigMaps {
		kubectlOut(ctx, "create", "namespace", c.Namespace)
		// Replaced, not applied: the object was created imperatively and
		// carries no last-applied-configuration for apply to compare against.
		// Deleting first restores EXACTLY the saved state.
		kubectlOut(ctx, "delete", "configmap", c.Name, "-n", c.Namespace, "--ignore-not-found")

		obj := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": c.Name, "namespace": c.Namespace},
			"data":       c.Data,
		}
		b, _ := json.Marshal(obj)
		cmd := k8s.Command(ctx, "kubectl", "create", "-f", "-")
		cmd.Stdin = strings.NewReader(string(b))
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := oneLine(stderr.String())
			if !strings.Contains(msg, "AlreadyExists") {
				*errs = append(*errs, fmt.Sprintf("configmap %s/%s : %s", c.Namespace, c.Name, msg))
			}
		}
	}
	return nil
}

// restoreBase reloads a dump into its database.
//
// The target database is recreated: pg_dump was taken with --clean
// --if-exists, so the dump drops then recreates the objects. We do NOT do
// DROP DATABASE: a missing database is created if needed, otherwise its
// content is replaced object by object — a gentler approach that leaves the
// database in place if the restore fails midway.
func restoreBase(ctx context.Context, pod, base, dumpPath string) error {
	f, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// The database must exist to receive the dump.
	if strings.TrimSpace(query(ctx, pod, "postgres",
		"SELECT 1 FROM pg_database WHERE datname='"+base+"'")) != "1" {
		if err := execSQL(ctx, pod, "postgres", "CREATE DATABASE "+quoteIdent(base)); err != nil {
			return fmt.Errorf("creating the database: %w", err)
		}
	}

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", base, "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reload: %w : %s", err, oneLine(stderr.String()))
	}
	return nil
}

func execSQL(ctx context.Context, pod, db, sql string) error {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres", "-n", "ceffio-data", pod,
		"--", "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w : %s", err, oneLine(string(out)))
	}
	return nil
}

// itoa converts an integer to a string (avoids importing strconv for so
// little).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// quoteIdent protects a SQL identifier name (database names are fixed in
// this program, but the function is reusable without pitfalls).
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// restoreVolume re-injects a tar into the corresponding pod.
//
// Two real problems encountered in testing, and their solution:
//
//  1. The tar was taken as root, extraction happens as the container's user
//     → `--no-same-owner` stops it from trying to restore ownership.
//  2. Extracting directly into the mount point makes tar fail on "."
//     (utime/mode forbidden on the root directory of the mounted volume)
//     and tar exits with code 2 — even though the files themselves are
//     written correctly.
//
// Solution: extract into a temporary subdirectory OF THE SAME volume, then
// copy the contents into place. We stay within the volume (so no space
// concerns), and the mount point is never touched directly.
func restoreVolume(ctx context.Context, v Volume, pod, tarPath string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// --no-same-owner: the tar was taken as root, extraction happens as the
	// container's user; without this option tar tries to restore ownership
	// and fails on the mount point.
	// Then ownership is explicitly RESTORED to the UID/GID expected by the
	// application: without this chown, everything belongs to root and the
	// application (www-data for Nextcloud) loses write access — a silent
	// outage observed in testing (Nextcloud 503 after restore).
	// cp -R without --preserve: preserving the target's timestamps fails on
	// a mount point.
	const staging = ".ceffio-restore"
	script := "set -e; " +
		"rm -rf " + v.Path + "/" + staging + "; " +
		"mkdir -p " + v.Path + "/" + staging + "; " +
		"tar xzf - --no-same-owner -C " + v.Path + "/" + staging + "; " +
		"cp -R " + v.Path + "/" + staging + "/. " + v.Path + "/; " +
		"chown -R " + itoa(v.UID) + ":" + itoa(v.GID) + " " + v.Path + " 2>/dev/null || true; " +
		"rm -rf " + v.Path + "/" + staging

	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", v.Namespace, pod, "--", "sh", "-c", script)
	cmd.Stdin = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extraction: %w : %s", err, oneLine(stderr.String()))
	}
	return nil
}
