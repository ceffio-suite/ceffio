// Package cluster gère le provisionnement du runtime Kubernetes (K3s réel sur
// Linux, k3d en environnement de dev) et la santé du cluster.
package cluster

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Runtime identifie le mode de provisionnement.
type Runtime string

const (
	RuntimeK3s Runtime = "k3s" // Linux : vrai K3s (single-node / appliance)
	RuntimeDev Runtime = "dev" // environnement de dev : k3d (K3s dans Docker)
)

// Cluster décrit un cluster provisionné.
type Cluster struct {
	Runtime Runtime
	Name    string
}

// Provision crée (ou réutilise, de façon idempotente) le cluster demandé.
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
		return nil, fmt.Errorf("runtime de cluster inconnu %q", rt)
	}
	return c, nil
}

func provisionK3d(ctx context.Context, name string) error {
	if k3dExists(ctx, name) {
		fmt.Printf("cluster k3d %q existe déjà, réutilisation\n", name)
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

// provisionK3s installe un vrai cluster K3s via le script officiel (Linux).
func provisionK3s(ctx context.Context) error {
	// TODO(phase-1) : flags HA (--cluster-init), version pin, options servi-extra.
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=false sh -")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Health liste les nœuds du cluster courant (via kubectl).
func Health(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "name").CombinedOutput()
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

// WaitReady attend que tous les nœuds soient Ready, avec un timeout.
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
	return fmt.Errorf("cluster non Ready après %s", timeout)
}

func allNodesReady(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o",
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
