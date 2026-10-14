// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/stack"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var asJSON bool
	var showPods bool

	c := &cobra.Command{
		Use:   "status",
		Short: "Show the state of the Ceffio deployment",
		Long: `Shows the real state of the Ceffio stack: nodes, application layers,
ingress, TLS certificates and exposed services.

Reads the state directly from the cluster (no inventory file to maintain):
if a layer is missing or broken, the command says so, which stays true even
after a manual modification of the cluster.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st := stack.Collect(cmd.Context())
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			printStatus(st, showPods)
			return nil
		},
	}

	c.Flags().BoolVar(&asJSON, "json", false, "JSON output (for scripts and monitoring)")
	c.Flags().BoolVar(&showPods, "pods", false, "Detail every pod (name, state, restarts)")

	return c
}

func printStatus(st *stack.State, showPods bool) {
	if !st.ClusterReachable {
		fmt.Println("Ceffio — deployment state")
		fmt.Println()
		fmt.Println("✗ Cluster unreachable")
		fmt.Printf("  %s\n", st.ClusterError)
		fmt.Println()
		fmt.Println("Common causes:")
		fmt.Println("  · Ceffio is not installed on this machine")
		fmt.Println("  · the k3s service is stopped        → systemctl status k3s")
		fmt.Println("  · the kubeconfig is missing or unreadable")
		os.Exit(1)
	}

	fmt.Println("Ceffio — deployment state")
	fmt.Println()

	// Cluster
	fmt.Printf("Cluster   %d/%d node(s) ready\n", st.NodesReady, len(st.Nodes))
	for _, n := range st.Nodes {
		mark := "✓"
		if !n.Ready {
			mark = "✗"
		}
		fmt.Printf("  %s %-24s %-12s %-16s %s\n", mark, n.Name, n.Roles, n.InternalIP, n.Version)
	}

	if st.Domain != "" {
		fmt.Printf("Domain    %s\n", st.Domain)
	}

	// Layers
	fmt.Println()
	fmt.Println("Layers")
	width := 0
	for _, l := range st.Layers {
		if len(l.Name) > width {
			width = len(l.Name)
		}
	}
	for _, l := range st.Layers {
		mark, note := "✓", ""
		switch {
		case l.Total == 0:
			mark = "·"
			note = "absent"
		case l.Ready < l.Total:
			mark = "✗"
			note = fmt.Sprintf("%d pod(s) not ready", l.Total-l.Ready)
		}
		line := fmt.Sprintf("  %s %-*s  %2d/%-2d", mark, width, l.Name, l.Ready, l.Total)
		if l.Restarts > 0 {
			line += fmt.Sprintf("   restarts: %d", l.Restarts)
		}
		if note != "" {
			line += "   " + note
		}
		fmt.Println(line)

		if showPods {
			for _, p := range l.Pods {
				pm := "✓"
				if !p.Ready {
					pm = "✗"
				}
				extra := ""
				if p.Restarts > 0 {
					extra = fmt.Sprintf("  (%d restart(s))", p.Restarts)
				}
				if p.Phase != "Running" && p.Phase != "" {
					extra += "  [" + p.Phase + "]"
				}
				fmt.Printf("      %s %s%s\n", pm, p.Name, extra)
			}
		}
	}

	// Ingress
	if len(st.Ingresses) > 0 {
		fmt.Println()
		fmt.Println("Access (ingress)")
		for _, i := range st.Ingresses {
			fmt.Printf("  https://%s\n", i.Host)
		}
	}

	// Certificates
	if len(st.Certificates) > 0 {
		ready := 0
		for _, c := range st.Certificates {
			if c.Ready {
				ready++
			}
		}
		fmt.Println()
		fmt.Printf("TLS certificates   %d/%d ready\n", ready, len(st.Certificates))
		for _, c := range st.Certificates {
			mark := "✓"
			if !c.Ready {
				mark = "✗"
			}
			line := fmt.Sprintf("  %s %-22s %s", mark, c.Name, c.NS)
			if !c.Ready && c.Condition != "" && c.Condition != "False" {
				line += "   " + c.Condition
			}
			fmt.Println(line)
		}
	}

	// Exposed services
	lb := filterServices(st.Services)
	if len(lb) > 0 {
		fmt.Println()
		fmt.Println("Exposed services")
		for _, s := range lb {
			addr := s.IP
			if addr == "" {
				addr = s.Status
			}
			fmt.Printf("  %-18s %-10s %-16s port %s\n", s.Name, s.Type, addr, s.Port)
		}
	}

	// Verdict
	fmt.Println()
	fmt.Printf("Pods: %d/%d ready", st.ReadyPods, st.TotalPods)
	if st.TotalRestarts > 0 {
		fmt.Printf(" · %d cumulative restart(s)", st.TotalRestarts)
	}
	fmt.Println()
	if st.ReadyPods == st.TotalPods && st.TotalPods > 0 && st.NodesReady == len(st.Nodes) {
		fmt.Println("✓ Platform operational")
	} else {
		fmt.Println("✗ Degraded state — run `ceffio doctor` for the detailed diagnostic")
		os.Exit(1)
	}
}

// filterServices keeps only the services through which we enter the platform.
func filterServices(all []stack.Service) []stack.Service {
	out := []stack.Service{}
	for _, s := range all {
		if s.Type == "LoadBalancer" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
