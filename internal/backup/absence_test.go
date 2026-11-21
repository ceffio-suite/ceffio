// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// WHY THESE TESTS EXIST.
//
// openproject and mail are OPTIONAL modules: an installation may not have them,
// and then the volume and the database they own simply do not exist. The
// backup must tell that absence from a failure, because the difference decides
// whether the archive is usable:
//
//   - an absence skipped is a complete archive for that installation;
//   - an absence reported as an error sets man.Complete = false, and Restaurer
//     then refuses the archive ("incomplete or tampered") — the safety net
//     stops working for everyone who did not install the optional module.
//
// The other half matters just as much: a volume that EXISTS but whose workload
// is gone holds data, and skipping it would drop that data without a word. The
// two cases are therefore tested together, so that a future "fix" of one cannot
// silently break the other.

// volumeOpenProject returns the OpenProject entry of the volume table, failing
// the test when it is absent: the module's attachments live on disk, and no SQL
// dump carries them.
func volumeOpenProject(t *testing.T) Volume {
	t.Helper()
	v, ok := volumeByName("openproject-assets")
	if !ok {
		t.Fatalf("the volume table no longer contains openproject-assets: project attachments would be lost")
	}
	return v
}

func TestLesVolumesCouvrentOpenProject(t *testing.T) {
	v := volumeOpenProject(t)

	if v.Namespace != "ceffio-system" {
		t.Errorf("namespace = %q, want ceffio-system (where the openproject module lives)", v.Namespace)
	}
	if v.PodLabel != "app=openproject" {
		t.Errorf("PodLabel = %q, want app=openproject: it is the selector of the application pods", v.PodLabel)
	}
	if v.Path != "/var/openproject/assets" {
		t.Errorf("path = %q, want /var/openproject/assets (cheminAssets of the module)", v.Path)
	}
	if v.UID != 1000 || v.GID != 1000 {
		t.Errorf("uid/gid = %d/%d, want 1000/1000: the service account runs with that id, and any other owner "+
			"leaves the restored attachments unreadable", v.UID, v.GID)
	}
	if v.StopWorkload != "" {
		t.Errorf("StopWorkload = %q: an attachment is a whole file written once under its own name, so a live "+
			"copy loses at worst the one being uploaded; stopping the application is not warranted", v.StopWorkload)
	}
}

func TestLesBasesCouvrentOpenProject(t *testing.T) {
	if !contient(Bases, "openproject") {
		t.Fatalf("openproject disappeared from the database list (%v): its projects, work packages and users "+
			"would be lost", Bases)
	}
}

// absente returns a fake whose every answer is a NotFound, which is what
// kubectl says about the PVC and the deployment of an uninstalled module.
func absente() *kubectlFactice {
	return &kubectlFactice{repondre: func(args []string, _ string) (string, error) {
		return "", fmt.Errorf("Error from server (NotFound): %s not found", argsEnTexte(args))
	}}
}

func TestUnVolumeAbsentNEstPasUneErreurDeSauvegarde(t *testing.T) {
	v := volumeOpenProject(t)
	f := absente()
	installerFauxKubectl(t, f)

	dst := filepath.Join(t.TempDir(), "openproject-assets.tar.gz")
	err := sauvegarderVolume(context.Background(), v, dst, nil)

	if !errors.Is(err, errVolumeAbsent) {
		t.Fatalf("error = %v, want errVolumeAbsent: the module is not installed, nothing was lost", err)
	}
	// Nothing else may be attempted: no temporary pod, no tar, and above all no
	// scale of a deployment that does not exist.
	for _, a := range f.appels {
		if len(a.Args) == 0 || a.Args[0] != "get" {
			t.Errorf("a %q command was run for an absent volume: %v", a.Args[0], a.Args)
		}
	}
}

func TestUnVolumeExistantSansPodResteUneErreur(t *testing.T) {
	v := volumeOpenProject(t)
	f := &kubectlFactice{repondre: func(args []string, _ string) (string, error) {
		if len(args) > 1 && args[1] == "pvc" {
			// The PVC is there: the attachments exist.
			return "persistentvolumeclaim/openproject-assets", nil
		}
		// ...but no pod matches the selector.
		return "", nil
	}}
	installerFauxKubectl(t, f)

	dst := filepath.Join(t.TempDir(), "openproject-assets.tar.gz")
	err := sauvegarderVolume(context.Background(), v, dst, nil)

	if err == nil {
		t.Fatalf("no error: the volume exists and was silently skipped")
	}
	if errors.Is(err, errVolumeAbsent) {
		t.Fatalf("error = %v: a volume that exists must never be reported as absent", err)
	}
	if !strings.Contains(err.Error(), v.PVC) {
		t.Errorf("error = %q, does not name the volume whose data would be lost", err)
	}
}

func TestRestaurerUnVolumeAbsentNommeLeModule(t *testing.T) {
	v := volumeOpenProject(t)
	installerFauxKubectl(t, absente())

	err := restaurerVolume(context.Background(), v, filepath.Join(t.TempDir(), "x.tar.gz"), nil)
	if err == nil {
		t.Fatalf("no error: the archive cannot be restored into a volume that does not exist")
	}
	if !strings.Contains(err.Error(), v.PVC) || !strings.Contains(err.Error(), "install the module") {
		t.Errorf("error = %q, want the volume name and the action that fixes it (install the module)", err)
	}
}

func TestUneBaseAbsenteNEstPasUnEchec(t *testing.T) {
	// An installation with files but without openproject: three databases
	// exist, the fourth does not.
	gardees, absentes := filtrerBases(map[string]bool{
		"mysuite": true, "keycloak": true, "nextcloud": true,
		"postgres": true, "template0": true, "template1": true,
	})

	if contient(gardees, "openproject") {
		t.Errorf("openproject was kept although the cluster does not have it: pg_dump would fail and mark the "+
			"backup incomplete (kept: %v)", gardees)
	}
	if !contient(absentes, "openproject") {
		t.Errorf("openproject was not reported as absent (absent: %v)", absentes)
	}
	for _, base := range []string{"mysuite", "keycloak", "nextcloud"} {
		if !contient(gardees, base) {
			t.Errorf("%s was dropped from the backup (kept: %v)", base, gardees)
		}
	}

	// A failed listing is not an absence: every database of the list is then
	// attempted, so that a network glitch cannot empty the archive.
	g, a := filtrerBases(nil)
	if len(a) != 0 || len(g) != len(Bases) {
		t.Errorf("filtrerBases(nil) = %v / %v, want every database of %v attempted and none skipped", g, a, Bases)
	}
}

func TestLesBasesPresentesViennentDuCluster(t *testing.T) {
	f := &kubectlFactice{repondre: func(args []string, _ string) (string, error) {
		if !contient(args, "psql") {
			return "", fmt.Errorf("unexpected command: %s", argsEnTexte(args))
		}
		return "mysuite\nkeycloak\nnextcloud\nopenproject\n", nil
	}}
	installerFauxKubectl(t, f)

	presentes, err := basesPresentes(context.Background(), "ceffio-pg-1")
	if err != nil {
		t.Fatalf("basesPresentes: %v", err)
	}
	for _, base := range Bases {
		if !presentes[base] {
			t.Errorf("%s missing from the listed databases: %v", base, presentes)
		}
	}

	// A failing psql must be an error, never an empty set: treating it as an
	// absence would silently drop every database from the archive.
	f.repondre = func([]string, string) (string, error) { return "", fmt.Errorf("connection refused") }
	presentes, err = basesPresentes(context.Background(), "ceffio-pg-1")
	if err == nil || presentes != nil {
		t.Fatalf("a failing listing returned %v / %v, want nil and an error", presentes, err)
	}
}

// contient says whether list holds name.
func contient(list []string, name string) bool {
	for _, l := range list {
		if l == name {
			return true
		}
	}
	return false
}
