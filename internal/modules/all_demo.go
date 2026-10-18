//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// WHY A SEPARATE FILE AND NOT ONE MORE LINE IN all.go: build constraints
// apply per FILE, and all.go must stay untagged — tagging it would drop the
// thirteen production modules from the default build, and adding an UNTAXED
// import of demo here would break every production build instead (demo's
// files are all excluded without the tag, so the import resolves to
// nothing). The only clean shape is therefore a second file in the same
// package, carrying the tag and exactly one blank import.
//
// This single line is the ENTIRE wiring cost of adding a feature to Ceffio
// — no installer change, no CLI change, no console change. That claim is
// what internal/modules/demo exists to prove, and what its integration test
// checks end to end.
package modules

import (
	_ "github.com/ceffio-suite/ceffio/internal/modules/demo"
)
