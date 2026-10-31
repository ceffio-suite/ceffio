// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"fmt"
)

// RejouerInstalles redeploys every OPTIONAL module whose state says installed.
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
		if st := m.State(ctx, env); st.Status != Installed {
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
