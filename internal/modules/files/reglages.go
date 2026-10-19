// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package files

import (
	"context"
	"os/exec"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// The settings CONTRACT on the files module.
//
// WHY THESE FOUR METHODS ARE SEPARATE FROM reglages_smtp.go: that file holds
// the SMTP group and its logic; these are the contract's entry points. Keeping
// them apart means a second group added to this module — there is no reason
// there could not be one — is added to Settings without touching the SMTP
// specifics.

// Settings declares the groups this module exposes.
func (m *filesModule) Settings() []module.Group {
	return m.SettingsOfSmtp()
}

// Current reads one group's values.
func (m *filesModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	return m.CurrentSmtp(ctx, env, groupe)
}

// Apply validates, stores and applies one group.
func (m *filesModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	return m.ApplySmtp(ctx, env, groupe, v)
}

// Test checks one group without storing anything.
func (m *filesModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	return m.TestSmtp(ctx, env, groupe, v)
}

// k8sCommand is k8s.Command under a local name, so the settings file reads
// without importing the package a second time.
func k8sCommand(ctx context.Context, args ...string) *exec.Cmd {
	return k8s.Command(ctx, "kubectl", args...)
}
