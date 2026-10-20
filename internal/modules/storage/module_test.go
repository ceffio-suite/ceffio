// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// TestLeStockageEstUnModuleCore : the layer exists in the registry, and the layer it
// describes is the one that is actually installed.
func TestLeStockageEstUnModuleCore(t *testing.T) {
	m := &storageModule{}
	i := m.Info()

	if i.ID != "storage" {
		t.Errorf("ID = %q, expected storage", i.ID)
	}
	if i.Kind != module.Core {
		t.Errorf("Kind = %v, expected Core: the storage is installed by every deployment, "+
			"not by choice — nothing stateful works without it", i.Kind)
	}
	if !i.Default {
		t.Error("Default = false: the install sequence always lays the storage down")
	}
	if len(i.Namespaces) != 1 || i.Namespaces[0] != "longhorn-system" {
		t.Errorf("Namespaces = %v, expected [longhorn-system]: Longhorn installs itself "+
			"there through Helm and cannot be moved", i.Namespaces)
	}
}

// TestLeStockageNeDonneAucunDroitALaConsole : no Permission.
//
// The plan expected a read-only grant. The console's RBAC reference freezes
// longhorn-system as OUT OF REACH and refused it, listing every verb it would have
// added — and that reference is right on the merits: a volume here carries PostgreSQL,
// Nextcloud's files and the mail store.
func TestLeStockageNeDonneAucunDroitALaConsole(t *testing.T) {
	i := (&storageModule{}).Info()
	if len(i.Permissions) != 0 {
		t.Errorf("the module grants %d permission(s) on %v: the console's reference keeps "+
			"longhorn-system out of reach, and a volume here is the platform's data",
			len(i.Permissions), i.Namespaces)
	}
}

// TestLeStockageNExposeAucunService : the Longhorn UI has no authentication of its own.
// Exposing it by default is how a volume gets deleted; the optional longhorn-ui module
// is what puts a sign-in in front of it.
func TestLeStockageNExposeAucunService(t *testing.T) {
	if s := (&storageModule{}).Info().Services; len(s) != 0 {
		t.Errorf("the module exposes %d service(s): the Longhorn interface has no "+
			"authentication, and exposing it directly lets anyone who reaches it delete "+
			"a volume", len(s))
	}
}

// TestLUninstallRefuse : removing the storage removes every volume.
func TestLUninstallRefuse(t *testing.T) {
	if err := (&storageModule{}).Uninstall(context.Background(), module.Env{}); err == nil {
		t.Fatal("Uninstall succeeded: removing the storage removes every volume, which " +
			"is every piece of data the platform holds")
	}
}

// TestLEtatSansClientDitInconnu : no Kubernetes client is not "absent" — the difference
// matters, because absent reads as "the operator did not install it" and sends them to
// install a layer that is already there.
func TestLEtatSansClientDitInconnu(t *testing.T) {
	etat := (&storageModule{}).State(context.Background(), module.Env{})
	if etat.Status != module.Unknown {
		t.Errorf("State without a client = %q, expected unknown", etat.Status)
	}
	if etat.Detail == "" {
		t.Error("no detail: the operator is left guessing why the state is unknown")
	}
}

// TestLesTroisWorkloadsSontAttendus : Longhorn 1.13 split the manager, and the UI is a
// Deployment of its own. A State that read one of them would report Installed while the
// interface is down — the exact failure the installer was fixed for.
func TestLesTroisWorkloadsSontAttendus(t *testing.T) {
	if len(deployementsAttendus) != 3 {
		t.Fatalf("%d workload(s) expected, got %v", len(deployementsAttendus), deployementsAttendus)
	}
	for _, nom := range deployementsAttendus {
		if !strings.HasPrefix(nom, "longhorn-") {
			t.Errorf("workload %q does not look like a Longhorn deployment", nom)
		}
	}
	// longhorn-manager WAS RENAMED: keeping the old name would make the state report
	// "missing" on a healthy 1.13 installation.
	for _, nom := range deployementsAttendus {
		if nom == "longhorn-manager" {
			t.Error("longhorn-manager no longer exists in 1.13: it is longhorn-global-manager")
		}
	}
	_ = socle.EtatDesDeploiements
}
