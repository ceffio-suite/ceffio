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
	"strings"
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

// AvecSecrets sources the secrets the OpenBao injector wrote into the pod,
// then runs the command given on the shell.
//
// USE IT FOR EVERY `kubectl exec` THAT READS A SECRET, and there are many:
// kcadm for Keycloak, curl for Stalwart, psql for a generated database
// password. Each of them failed for the same reason, and the failure was
// always the same shape — a credential error that looks like a wrong password
// but is really an empty variable.
//
// WHY THE VARIABLES ARE EMPTY. The injector writes /secrets/env, and each
// component's CONTAINER COMMAND sources it for its own process. A
// `kubectl exec` opens a NEW shell inside that container: it inherits the
// image's environment, NOT what the entrypoint exported. Without this prefix,
// `"$KC_BOOTSTRAP_ADMIN_PASSWORD"` is an empty string, kcadm reports "Invalid
// user credentials", and one goes looking for a password problem that is not
// there.
//
// `set -a` exports everything the file defines so later commands in the same
// shell see the values. The work happens INSIDE the pod: only the variable
// NAMES reach the process table, never the values.
//
// If /secrets/env is absent — an injector that never ran — the source fails
// silently (2>/dev/null) and the command runs without credentials, failing
// loudly on its own error rather than pretending to succeed.
func AvecSecrets(commande string) string {
	return `set -a; . /secrets/env 2>/dev/null; set +a; ` + commande
}

// ExecAvecSecrets runs command inside pod, with the injected secrets sourced
// first. It is the short form of the common case:
//
//	kubectl [-n ns] exec [-i] <cible> -c <conteneur> -- sh -c AvecSecrets(…)
//
// stdin is passed through when non-empty, which is what the JMAP calls need.
func ExecAvecSecrets(ctx context.Context, ns, cible, conteneur, commande string, stdin string) (string, error) {
	args := []string{}
	if ns != "" {
		args = append(args, "-n", ns)
	}
	args = append(args, "exec")
	if stdin != "" {
		args = append(args, "-i")
	}
	args = append(args, cible, "-c", conteneur, "--", "sh", "-c", AvecSecrets(commande))
	cmd := Command(ctx, "kubectl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
