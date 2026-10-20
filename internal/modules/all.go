// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package modules hosts no logic: it exists only so that Go runs the init()
// of each module.
//
// WHY THIS FILE EXISTS: each module registers itself into the global
// registry from a func init() in its own package. But Go only runs the init()
// of packages actually imported by the binary — a module nobody imports would
// NEVER register, and its absence would be completely silent (no error, just
// a module that cannot be found). These blank imports ("_") force the init()
// to run without referencing any symbol; both frontends (CLI, console) then
// only have to import this single package to see the whole catalog.
//
// The all_test.go test is the guardrail: it verifies that every package
// calling module.Register is listed here.
package modules

import (
	_ "github.com/ceffio-suite/ceffio/internal/modules/console"
	_ "github.com/ceffio-suite/ceffio/internal/modules/data"
	_ "github.com/ceffio-suite/ceffio/internal/modules/exappsdaemon"
	_ "github.com/ceffio-suite/ceffio/internal/modules/files"
	_ "github.com/ceffio-suite/ceffio/internal/modules/identity"
	_ "github.com/ceffio-suite/ceffio/internal/modules/ingress"
	_ "github.com/ceffio-suite/ceffio/internal/modules/mail"
	_ "github.com/ceffio-suite/ceffio/internal/modules/office"
	_ "github.com/ceffio-suite/ceffio/internal/modules/platform"
	_ "github.com/ceffio-suite/ceffio/internal/modules/recording"
	_ "github.com/ceffio-suite/ceffio/internal/modules/storage"
	_ "github.com/ceffio-suite/ceffio/internal/modules/talk"
	_ "github.com/ceffio-suite/ceffio/internal/modules/transcription"
	_ "github.com/ceffio-suite/ceffio/internal/modules/vault"
)
