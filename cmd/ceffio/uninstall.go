// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/cluster"
)

func newUninstallCmd() *cobra.Command {
	var runtimeFlag string
	var force bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall Ceffio and destroy the Kubernetes cluster (K3s/k3d)",
		Long: `Destroys the Kubernetes cluster (real K3s on Linux, k3d in dev) and cleans
up Ceffio's local state. DESTRUCTIVE: the cluster and its data (volumes) are
deleted. Interactive confirmation, skipped with --force.

Examples:
  ceffio uninstall                # destroys the Linux K3s (cluster "ceffio-dev")
  ceffio uninstall --runtime dev  # destroys the k3d cluster "ceffio-dev"
  ceffio uninstall --force        # without confirmation`,
		RunE: func(c *cobra.Command, args []string) error {
			rt, err := resolveUninstallRuntime(runtimeFlag)
			if err != nil {
				return err
			}
			if !force {
				fmt.Printf("Warning: this deletes cluster %q (%s) and ALL its data.\n", devClusterName, rt)
				fmt.Print("Type 'yes' to confirm: ")
				reader := bufio.NewReader(os.Stdin)
				line, _ := reader.ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					fmt.Println("Aborted.")
					return nil
				}
			}
			return cluster.Destroy(c.Context(), rt, devClusterName)
		},
	}
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "k3s", "Runtime to tear down (k3s, dev)")
	cmd.Flags().BoolVar(&force, "force", false, "Skip the confirmation")
	return cmd
}

func resolveUninstallRuntime(spec string) (cluster.Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "k3s":
		return cluster.RuntimeK3s, nil
	case "dev", "k3d":
		return cluster.RuntimeDev, nil
	case "rke2":
		return "", fmt.Errorf("runtime rke2: not implemented yet")
	default:
		return "", fmt.Errorf("unknown runtime %q", spec)
	}
}
