// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package storage declares the "storage" layer (Longhorn) as a Core module of the
// registry.
//
// WHY A WRAPPER, like the other core layers: the install already exists in
// internal/storage and remains driven by the explicit order of
// cmd/ceffio/install.go. This package DESCRIBES the layer so the state page and the
// diagnostics read it from the registry.
//
// IT WAS MISSING, and the consequence was visible: longhorn-system did not appear in
// the console's State page at all, and no module could declare a dependency on the
// storage — because the storage was not a module. A layer that everything else uses
// and nothing declares is a blind spot, not an oversight of a detail.
package storage

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheStorage "github.com/ceffio-suite/ceffio/internal/storage"
)

// namespaceStorage is where Longhorn lives (internal/storage/install.go).
const namespaceStorage = "longhorn-system"

// storageModule is the "storage" module.
type storageModule struct{}

func init() { module.Register(&storageModule{}) }

// deployementsAttendus are the three workloads `attendreLonghorn` already waits for.
//
// THREE, NOT ONE, and the list is copied from the installer rather than guessed:
// Longhorn 1.13 renamed longhorn-manager to longhorn-global-manager, and the UI is a
// separate Deployment. A State that read only the first would report Installed while
// the interface is down — the exact failure the installer was fixed for.
var deployementsAttendus = []string{
	"longhorn-driver-deployer",
	"longhorn-global-manager",
	"longhorn-ui",
}

// Info describes the layer.
func (m *storageModule) Info() module.Info {
	return module.Info{
		ID:          "storage",
		Title:       "Storage (Longhorn)",
		Description: "Volumes and their replicas, which every stateful module of the suite depends on.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{namespaceStorage},

		// NO Permission AT ALL, AND THE REFERENCE TEST IS WHY.
		//
		// The plan expected a read-only grant here. The console's RBAC non-regression
		// test freezes longhorn-system as OUT OF REACH — "infrastructure namespaces
		// stay out of the console's reach" — and refused the grant, listing every verb
		// it would have added. That reference is the stricter rule, and it is right on
		// the merits: a volume here carries PostgreSQL, Nextcloud's files and the mail
		// store, and a web page has no business reading the storage's objects at all.
		//
		// THE MONITORING PAGE STILL SHOWS THE REAL USED SPACE, through the CLUSTER-ROLE
		// grant on longhorn.io that already exists and is read-only by its own test.
		// So nothing is lost by leaving the namespace alone here.

		// NO SERVICE HERE. The Longhorn UI is not exposed by default: it has no
		// authentication of its own, and exposing it directly is how a volume gets
		// deleted. The optional longhorn-ui module puts a single sign-on in front of
		// it; until then, the interface stays inside the cluster.
	}
}

// Install delegates to storage.Install, unchanged — the registry describes, the
// sequence of cmd/ceffio/install.go remains master of the core order (the storage
// comes first, because everything stateful needs it).
func (m *storageModule) Install(ctx context.Context, env module.Env) error {
	return coucheStorage.Install(ctx)
}

// State reports Installed only when ALL THREE workloads are ready.
//
// WHY NOT EtatDuDeploiement ON THE UI ALONE: the UI can be Running while the driver
// deployer is still missing, and that state looks healthy in a single-deployment check
// while nothing can actually claim a volume.
func (m *storageModule) State(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		return module.State{Status: module.Unknown,
			Detail: "no Kubernetes client: the module state cannot be read"}
	}
	return socle.EtatDesDeploiements(ctx, env, namespaceStorage, deployementsAttendus)
}

// Uninstall refuses: removing the storage removes every volume, which is every piece
// of data the platform holds.
func (m *storageModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
