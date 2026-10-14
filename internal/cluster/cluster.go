// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package cluster handles provisioning of the Kubernetes runtime (real K3s on
// Linux, k3d in dev environments) and cluster health.
package cluster

import (
	"context"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runtime identifies the provisioning mode.
type Runtime string

const (
	RuntimeK3s Runtime = "k3s" // Linux: real K3s (single-node / appliance)
	RuntimeDev Runtime = "dev" // dev environment: k3d (K3s in Docker)
)

// Cluster describes a provisioned cluster.
type Cluster struct {
	Runtime Runtime
	Name    string
}

// Provision creates (or reuses, idempotently) the requested cluster.
func Provision(ctx context.Context, rt Runtime, name string) (*Cluster, error) {
	c := &Cluster{Runtime: rt, Name: name}
	switch rt {
	case RuntimeK3s:
		if err := provisionK3s(ctx); err != nil {
			return nil, err
		}
	case RuntimeDev:
		if err := provisionK3d(ctx, name); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown cluster runtime %q", rt)
	}
	return c, nil
}

// k3sDejaOperationnel reports whether a k3s cluster is already running on
// this machine.
//
// We test the SERVICE and the API, not the presence of a file: a binary that
// exists alongside a stopped service must trigger the repair, while a missing
// file with an active service (system install) must not trigger anything.
//
// Two signals, cheapest first:
//  1. the kubeconfig exists and kubectl responds -> the cluster is alive;
//  2. the systemd service is active.
//
// If either holds, the cluster is considered in place. The risk of being
// wrong is low, and the symmetric mistake (reinstalling a healthy cluster) is
// far more costly: it breaks what was working.
func k3sDejaOperationnel(ctx context.Context) bool {
	// 1. Does kubectl respond? That is the most direct proof.
	if _, err := os.Stat("/etc/rancher/k3s/k3s.yaml"); err == nil {
		c := exec.CommandContext(ctx, "kubectl", "get", "nodes",
			"--request-timeout=5s", "-o", "name")
		if err := c.Run(); err == nil {
			return true
		}
	}
	// 2. Is the service running?
	c := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "k3s")
	return c.Run() == nil
}

func provisionK3d(ctx context.Context, name string) error {
	if k3dExists(ctx, name) {
		fmt.Printf("k3d cluster %q already exists, reusing\n", name)
		return nil
	}
	cmd := exec.CommandContext(ctx, "k3d", "cluster", "create", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func k3dExists(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "k3d", "cluster", "list", "--no-headers").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, name) {
			return true
		}
	}
	return false
}

// provisionK3s installs a real K3s cluster via the official script (Linux),
// plus helm (a stack prerequisite) and the user's default kubeconfig.
func provisionK3s(ctx context.Context) error {
	// FIRST AND FOREMOST: a live cluster must NOT be re-provisioned.
	//
	// WHY THIS CHECK EXISTS: without it, every `ceffio install` re-runs the
	// k3s installer, which queries update.k3s.io to learn the version
	// channel. On a network that filters that domain (proxy, DPI, lying DNS),
	// the request fails with a certificate error and the WHOLE deployment
	// stops — even though the cluster was running perfectly and there was
	// nothing to install. An idempotent install must not depend on a network
	// call it does not need.
	if k3sDejaOperationnel(ctx) {
		fmt.Println("∙ k3s cluster already operational, reusing (no re-install)")
		return nil
	}

	// TODO(phase-1): HA flags (--cluster-init), version pin, service-extra options.
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=false sh -")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("get.k3s.io: %w", err)
	}
	// helm: prerequisite (jetstack and umbrella charts). Auto-install if missing.
	if _, err := exec.LookPath("helm"); err != nil {
		fmt.Println("∙ helm missing → installing via get-helm-3")
		hcmd := exec.CommandContext(ctx, "sh", "-c",
			"curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sh")
		hcmd.Stdout = os.Stdout
		hcmd.Stderr = os.Stderr
		if err := hcmd.Run(); err != nil {
			return fmt.Errorf("install helm: %w", err)
		}
	}
	// Kubeconfig: the K3s script starts the service in the background and
	// writes /etc/rancher/k3s/k3s.yaml only a few seconds AFTER the script
	// returns (K3s generates its CA/certificates on first boot). We therefore
	// wait for it actively: an immediate read fails and, being non-blocking,
	// leaves the machine without a kubeconfig → kubectl/helm then fail with
	// "permission denied" on k3s.yaml, and the cluster looks not-Ready.
	// ALWAYS rewritten: a stale ~/.kube/config from a previous k3s (a
	// different CA) would make helm/kubectl fail with "x509: certificate
	// signed by unknown authority". Errors are NEVER swallowed.
	const k3sCfg = "/etc/rancher/k3s/k3s.yaml"
	// The CLI runs as root (installer.sh → sudo): direct read. In "sudo
	// without root" mode (e.g. a binary run by a user), we fall back to
	// sudo cat.
	readCfg := func() ([]byte, error) {
		if data, err := os.ReadFile(k3sCfg); err == nil {
			return data, nil
		}
		out, err := exec.CommandContext(ctx, "sudo", "cat", k3sCfg).Output()
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s is empty", k3sCfg)
		}
		return out, nil
	}
	var data []byte
	deadline := time.Now().Add(90 * time.Second)
	for {
		var err error
		if data, err = readCfg(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("kubeconfig %s unavailable after 90s: %w "+
				"(did k3s start? check: systemctl status k3s)", k3sCfg, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return fmt.Errorf("cannot find HOME to write ~/.kube/config: %w", err)
	}
	kc := filepath.Join(home, ".kube")
	if err := os.MkdirAll(kc, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", kc, err)
	}
	if err := os.WriteFile(filepath.Join(kc, "config"), data, 0o600); err != nil {
		return fmt.Errorf("writing ~/.kube/config: %w", err)
	}
	return nil
}

// Destroy tears down the provisioned cluster and cleans up Ceffio's local
// state. The consumer derivation mirrors Provision (same switch).
func Destroy(ctx context.Context, rt Runtime, name string) error {
	switch rt {
	case RuntimeK3s:
		// k3s-uninstall.sh stops the service and purges /etc/rancher,
		// /var/lib/rancher, the binaries and the systemd service (local-path
		// data/volumes included). Its trace (set -x) is redirected to a log:
		// nothing is printed on success.
		cmd := exec.CommandContext(ctx, "sh", "-c",
			"systemctl stop k3s 2>/dev/null; if [ -x /usr/local/bin/k3s-uninstall.sh ]; then /usr/local/bin/k3s-uninstall.sh >/tmp/ceffio-k3s-uninstall.log 2>&1; else echo 'k3s-uninstall.sh missing (k3s not installed via the official script)'; fi")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("k3s-uninstall: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		fmt.Println("✓ K3s removed (k3s-uninstall.sh)")
	case RuntimeDev:
		if !k3dExists(ctx, name) {
			fmt.Printf("k3d cluster %q absent, nothing to delete\n", name)
		} else {
			cmd := exec.CommandContext(ctx, "k3d", "cluster", "delete", name)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("k3d cluster delete: %w", err)
			}
			fmt.Printf("✓ k3d cluster %q deleted\n", name)
		}
	default:
		return fmt.Errorf("unknown cluster runtime %q", rt)
	}
	return cleanupLocal(ctx, rt, name)
}

// cleanupLocal removes Ceffio's local state. The kubeconfig (~/.kube/config)
// is left in place: it may contain other clusters; we do not touch it.
func cleanupLocal(ctx context.Context, rt Runtime, name string) error {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		ce := filepath.Join(home, ".ceffio")
		if _, err := os.Stat(ce); err == nil {
			_ = os.RemoveAll(ce)
			fmt.Println("✓ local state ~/.ceffio removed")
		}
	}
	return nil
}

// Health lists the nodes of the current cluster (via kubectl).
func Health(ctx context.Context) ([]string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "nodes", "-o", "name").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get nodes: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	var nodes []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			nodes = append(nodes, strings.TrimPrefix(l, "node/"))
		}
	}
	return nodes, nil
}

// WaitReady waits until all nodes are Ready, with a timeout.
func WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if allNodesReady(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("cluster not Ready after %s", timeout)
}

func allNodesReady(ctx context.Context) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "nodes", "-o",
		`jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{" "}{end}`).Output()
	if err != nil {
		return false
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if f != "True" {
			return false
		}
	}
	return true
}

// podsApplicatifsPrets reports whether all pods in the ceffio-* namespaces
// are ready. Finished pods (Succeeded) are ignored: they are completed jobs.
func podsApplicatifsPrets(ctx context.Context) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "pods", "-A", "--no-headers").Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasPrefix(f[0], "ceffio-") {
			continue
		}
		// columns: NAMESPACE NAME READY STATUS RESTARTS AGE
		statut := f[3]
		if statut == "Succeeded" || statut == "Completed" {
			continue
		}
		if !strings.Contains(f[2], "/") {
			continue
		}
		parts := strings.SplitN(f[2], "/", 2)
		if parts[0] != parts[1] {
			return false
		}
	}
	return true
}
