// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package k8s centralizes the execution of the Kubernetes tools (kubectl, helm)
// with an explicit environment.
//
// Why this package exists — reproducibility bug discovered by the from-scratch
// test of 2026-09-25:
//
// The K3s install script exposes `kubectl` as a SYMLINK to the `k3s` binary
// (/usr/local/bin/kubectl -> k3s). Invoked under the name "kubectl", this
// binary applies K3s's "bundled kubectl" logic: it reads
// /etc/rancher/k3s/k3s.yaml IN HARD, BEFORE any standard resolution. And this
// file is owned by root, mode 0600 → a CLI launched by a non-root user (or
// any call inherited from such an env) fails with:
//
//	error loading config file "/etc/rancher/k3s/k3s.yaml": permission denied
//
// …even when ~/.kube/config exists, is correct and readable. Consequence: the
// whole deployment fails (WaitReady never sees the node, every Deploy breaks),
// and the error displayed never mentions the kubeconfig, which makes the
// diagnosis very expensive.
//
// The countermeasure: never depend on the implicit kubeconfig resolution —
// always pass KUBECONFIG explicitly in the process environment.
package k8s

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

// Env returns the current process environment enriched with KUBECONFIG
// (and, for K3s, the useful K3S_* ones), so that kubectl and helm aim at the
// same kubeconfig deterministically.
//
// If KUBECONFIG is already set by the caller, it is respected: we do not
// overwrite it.
func Env() []string {
	env := os.Environ()
	if os.Getenv("KUBECONFIG") != "" {
		return env
	}
	if p := defaultKubeconfig(); p != "" {
		env = append(env, "KUBECONFIG="+p)
	}
	return env
}

// defaultKubeconfig resolves the user's default kubeconfig
// (~/.kube/config). Returns "" if HOME cannot be found.
func defaultKubeconfig() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// Command is an exec.CommandContext that applies Env() automatically.
// Use it for EVERY kubectl or helm call.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = Env()
	return cmd
}
