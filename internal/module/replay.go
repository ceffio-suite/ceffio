// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"fmt"
)

// RejouerInstalles redeploys every OPTIONAL module whose state says installed
// or merely degraded.
//
// WHY THIS EXISTS: `ceffio upgrade` replays the core layers, and nothing else.
// A module installed later — the Talk relay, the capture, the transcription —
// keeps the image of the day it was installed, and `module install` answers
// "already installed" instead of replaying. The installation then runs two
// versions of the same binary at once, which is exactly what `ceffio sbom
// --cluster` reports as a divergence. It found one: a relay three releases
// behind.
//
// WHY THE INSTALL IS SAFE TO REPLAY: the Module contract requires Install to be
// idempotent — it is already called by the CLI, by the console, and again after
// any interruption. Replaying is not a new operation; it is the ordinary one.
//
// DEGRADED IS REPLAYED TOO, and that is deliberate: a mail server whose DNS
// records are not published yet reports Degraded while its Deployment is
// perfectly ready. Skipping it would freeze its image at the version of the
// day it was installed — the exact drift this function exists to remove — for
// a defect an upgrade has no way to fix. A module that is ABSENT, INSTALLING
// or UNKNOWN is still not replayed: an upgrade is not an installation, and an
// unknown state is not a green light.
//
// CORE MODULES ARE NOT HANDLED HERE: they belong to the install sequence, which
// Redeployer already replays.
func RejouerInstalles(ctx context.Context, modules []Module, env Env, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	for _, m := range modules {
		info := m.Info()
		if info.Kind != Optional {
			continue
		}
		if st := m.State(ctx, env); !estRejouable(st) {
			continue
		}
		progress(fmt.Sprintf("%s: replaying the installed module", info.ID))
		// SETTINGS AND SECRETS ARE STORED UNDER THE MODULE'S ID: a replay that
		// carried the wrong one would read somebody else's configuration.
		env.ModuleID = info.ID
		if err := m.Install(ctx, env); err != nil {
			return fmt.Errorf("%s: %w", info.ID, err)
		}
	}
	return nil
}

// estRejouable says whether a state means "the module is there and must follow
// the binary".
//
// WHY A NAMED PREDICATE: the rule is easy to get subtly wrong (Degraded is not
// Absent, and Installing is not a green light), and naming it makes the test
// table below read as the rule itself.
func estRejouable(st State) bool {
	return st.Status == Installed || st.Status == Degraded
}
