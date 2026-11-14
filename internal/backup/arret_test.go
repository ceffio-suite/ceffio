// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WHY THESE TESTS EXIST.
//
// Backing up the mail volume is the one operation of this package that STOPS a
// production service. The three ways it can go wrong are all silent:
//
//  1. The stop is not compensated — the backup fails and the mail server stays
//     down. Nobody notices until someone's mail is refused.
//  2. The helper pod is not removed before the restart — the PVC is
//     ReadWriteOnce, so the restart stays Pending, and the error names a pod
//     start, not the leftover pod that causes it.
//  3. The volume table loses the StopWorkload marker — tar exits 0 on a live
//     RocksDB store and the resulting archive does not open. That is the
//     failure mode we measured in POC K.
//
// None of these can be rehearsed on a real installation without taking the
// maintainer's mail down, so they are asserted here against the seam.

// volumeMessagerie returns the mail entry of the volume table, failing the test
// if it is absent — an absent entry means the archive silently stops covering
// the mail server.
func volumeMessagerie(t *testing.T) Volume {
	t.Helper()
	v, ok := volumeByName("stalwart-data")
	if !ok {
		t.Fatalf("the volume table no longer contains stalwart-data: the archive no longer covers the mail server")
	}
	return v
}

func TestLesVolumesCouvrentLaMessagerie(t *testing.T) {
	v := volumeMessagerie(t)

	if v.Namespace != "ceffio-mail" {
		t.Errorf("namespace = %q, want ceffio-mail", v.Namespace)
	}
	if v.Path != "/var/lib/stalwart" {
		t.Errorf("path = %q, want /var/lib/stalwart (the store and the blob directory of Stalwart 1.0)", v.Path)
	}
	if v.UID != 2000 || v.GID != 2000 {
		t.Errorf("uid/gid = %d/%d, want 2000/2000: any other owner and the restored store is unreadable by the server",
			v.UID, v.GID)
	}
	if v.StopWorkload != "stalwart" {
		t.Errorf("StopWorkload = %q, want stalwart: without the stop, tar exits 0 on a live RocksDB store and the archive does not open",
			v.StopWorkload)
	}
	if _, ok := volumeByName("nextcloud-data"); !ok {
		t.Errorf("nextcloud-data disappeared from the volume table")
	}
}

// fauxVolume returns a fake whose only noteworthy answer is the copy itself:
// every kubectl command succeeds, the copy fails with errCopie.
func fauxVolume(errCopie error) *kubectlFactice {
	return &kubectlFactice{repondre: func(args []string, entree string) (string, error) {
		if len(args) == 0 {
			return "", fmt.Errorf("kubectl called without arguments")
		}
		switch args[0] {
		case "scale", "wait", "delete", "rollout":
			return "", nil
		case "get":
			if len(args) > 1 && args[1] == "deployment" {
				return "example.com/mail:test", nil
			}
			// The pods of the stopped workload: empty, so the wait for the
			// volume to be free ends on the first poll.
			return "", nil
		case "apply":
			return "", nil
		case "exec":
			// The copy streams a tar: the fake returns just enough bytes for
			// tarVolume's "empty archive" guard not to reject it.
			if strings.Contains(entree, "tar czf") || (len(args) > 0 && strings.Contains(argsEnTexte(args), "tar czf")) {
				return strings.Repeat("x", 64), errCopie
			}
			return "", errCopie
		}
		return "", fmt.Errorf("unexpected kubectl command: %s", argsEnTexte(args))
	}}
}

func TestLeVolumeDeMessagerieEstArretePuisRedemarre(t *testing.T) {
	v := volumeMessagerie(t)
	f := fauxVolume(nil)
	installerFauxKubectl(t, f)

	dst := filepath.Join(t.TempDir(), "stalwart-data.tar.gz")
	if err := sauvegarderVolume(context.Background(), v, dst, nil); err != nil {
		t.Fatalf("sauvegarderVolume: %v", err)
	}

	arrets := f.commandes("scale", "deployment", "stalwart")
	if len(arrets) != 2 {
		t.Fatalf("scale called %d time(s), want 2 (once to stop, once to restart): %v", len(arrets), arrets)
	}
	if !strings.Contains(argsEnTexte(arrets[0]), "--replicas=0") {
		t.Errorf("first scale = %q, want --replicas=0: the copy happens on a stopped server", argsEnTexte(arrets[0]))
	}
	if !strings.Contains(argsEnTexte(arrets[1]), "--replicas=1") {
		t.Errorf("second scale = %q, want --replicas=1: the restart must be the last word", argsEnTexte(arrets[1]))
	}
	if !f.aFait("rollout", "status", "deployment/stalwart") {
		t.Errorf("`rollout status` was not called: scaling back is not the same as being back")
	}

	// The helper pod must mount the volume it copies, under the PVC's name.
	var manifeste string
	for _, a := range f.appels {
		if a.Args[0] == "apply" {
			manifeste = a.Entree
		}
	}
	if manifeste == "" {
		t.Fatalf("no manifest was applied: the copy has no pod to run in")
	}
	for _, attendu := range []string{"claimName: stalwart-data", "mountPath: /var/lib/stalwart", "runAsUser: 2000", "fsGroup: 2000"} {
		if !strings.Contains(manifeste, attendu) {
			t.Errorf("the temporary pod does not declare %q:\n%s", attendu, manifeste)
		}
	}
	if !f.aFait("delete", "pod") {
		t.Errorf("the temporary pod was not deleted: it holds the ReadWriteOnce volume, so the restart would stay Pending")
	}
}

func TestLeVolumeDeMessagerieEstRedemarreQuandLaCopieEchoue(t *testing.T) {
	v := volumeMessagerie(t)
	f := fauxVolume(fmt.Errorf("disk full"))
	installerFauxKubectl(t, f)

	dst := filepath.Join(t.TempDir(), "stalwart-data.tar.gz")
	err := sauvegarderVolume(context.Background(), v, dst, nil)
	if err == nil {
		t.Fatalf("sauvegarderVolume returned nil although the copy failed")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("error = %q, want the copy's own error", err.Error())
	}

	arrets := f.commandes("scale", "deployment", "stalwart")
	if len(arrets) != 2 || !strings.Contains(argsEnTexte(arrets[1]), "--replicas=1") {
		t.Fatalf("the workload was not restarted after the failed copy (scale calls: %v): a failed backup became an outage", arrets)
	}
	if !f.aFait("delete", "pod") {
		t.Errorf("the temporary pod was left behind after the failed copy")
	}
}

func TestUnPodTemporaireQuiNeDemarrePasEstSupprimeEtLaChargeRedemarree(t *testing.T) {
	v := volumeMessagerie(t)
	f := fauxVolume(nil)
	// Only the readiness wait fails: this is the case where the volume is still
	// held (Multi-Attach) or the image cannot be pulled.
	f.repondre = func(args []string, entree string) (string, error) {
		if len(args) > 0 && args[0] == "wait" {
			return "", fmt.Errorf("timed out waiting for the condition")
		}
		if len(args) > 0 && args[0] == "get" && len(args) > 1 && args[1] == "deployment" {
			return "example.com/mail:test", nil
		}
		if len(args) > 0 && args[0] == "exec" {
			return "", fmt.Errorf("exec must not run: the pod was never ready")
		}
		if len(args) > 0 {
			switch args[0] {
			case "scale", "delete", "apply", "rollout", "get":
				return "", nil
			}
		}
		return "", fmt.Errorf("unexpected kubectl command: %s", argsEnTexte(args))
	}
	installerFauxKubectl(t, f)

	dst := filepath.Join(t.TempDir(), "stalwart-data.tar.gz")
	if err := sauvegarderVolume(context.Background(), v, dst, nil); err == nil {
		t.Fatalf("sauvegarderVolume returned nil although the temporary pod never became ready")
	}
	if !f.aFait("delete", "pod") {
		t.Errorf("the temporary pod was not deleted after a failed start: it would keep the volume busy")
	}
	arrets := f.commandes("scale", "deployment", "stalwart")
	if len(arrets) != 2 || !strings.Contains(argsEnTexte(arrets[1]), "--replicas=1") {
		t.Fatalf("the workload was not restarted after the failed start (scale calls: %v)", arrets)
	}
}

func TestLeVolumeDeMessagerieEstRestaureApresArret(t *testing.T) {
	v := volumeMessagerie(t)
	f := fauxVolume(nil)
	installerFauxKubectl(t, f)

	// A tar with one byte of content: restoreVolume only streams it, the
	// extraction itself happens in the pod.
	tarPath := filepath.Join(t.TempDir(), "stalwart-data.tar.gz")
	if err := os.WriteFile(tarPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := restaurerVolume(context.Background(), v, tarPath, nil); err != nil {
		t.Fatalf("restaurerVolume: %v", err)
	}

	arrets := f.commandes("scale", "deployment", "stalwart")
	if len(arrets) != 2 {
		t.Fatalf("scale called %d time(s), want 2 (stop, restart): %v", len(arrets), arrets)
	}
	if !strings.Contains(argsEnTexte(arrets[0]), "--replicas=0") {
		t.Errorf("the workload was not stopped before the restore: %q", argsEnTexte(arrets[0]))
	}
	if !strings.Contains(argsEnTexte(arrets[1]), "--replicas=1") {
		t.Errorf("the workload was not restarted after the restore: %q", argsEnTexte(arrets[1]))
	}
	var restauration string
	for _, a := range f.appels {
		if len(a.Args) > 0 && a.Args[0] == "exec" {
			restauration = argsEnTexte(a.Args)
		}
	}
	if !strings.Contains(restauration, "tar xzf -") {
		t.Errorf("the extraction command does not read the archive from stdin: %q", restauration)
	}
	if strings.Contains(restauration, "/var/lib/stalwart/.ceffio-restore") == false {
		t.Errorf("the extraction does not go through the staging subdirectory of the volume: %q", restauration)
	}
}
