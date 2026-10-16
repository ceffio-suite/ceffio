// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package storage resolves the StorageClass the suite writes its persistent
// volumes to.
//
// WHY THIS IS NOT A CONSTANT. Every module used to write `local-path` in its
// own manifest, four copies of the same string. That was correct while the
// suite was deployed on k3s alone, and wrong the moment the operator wants
// something else: switching to Longhorn meant editing four files, and the
// choice could not be made at deployment time at all.
//
// The two provisioners are not equivalent, and the difference is not only
// performance:
//
//	local-path  volumes live in a directory of the node. No expansion
//	            (allowVolumeExpansion is unset), no snapshot, no backup.
//	            Growing a volume means deleting and recreating the PVC, so
//	            losing the data.
//	longhorn    a CSI driver: online expansion, copy-on-write snapshots and
//	            backup to an object store. What makes the storage manageable
//	            brick by brick, which is a requirement of the product.
//
// So the class is read from CEFFIO_STORAGE_CLASS, with `longhorn` as the
// default: a deployment that follows the documentation today gets the
// manageable storage, and one that wants the simpler provisioner says so.
package storage

import (
	"os"
	"strings"
)

// NomParDefaut is the StorageClass used when nothing is configured.
//
// `longhorn`, not `local-path`: the suite's storage has to be expandable and
// backupable, and local-path offers neither. An installation that genuinely
// wants local-path opts out explicitly.
const NomParDefaut = "longhorn"

// Variable is the environment variable that overrides the class.
const Variable = "CEFFIO_STORAGE_CLASS"

// Classe returns the StorageClass to write into the manifests.
//
// The value is taken as given, without validation against what the cluster
// offers: a name that does not exist makes the PVC stay Pending, with an
// event naming it, which is a clearer failure than a silent fallback to
// something the operator did not ask for.
func Classe() string {
	c := strings.TrimSpace(os.Getenv(Variable))
	if c == "" {
		return NomParDefaut
	}
	return c
}
