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
		Short: "Afficher l'état du déploiement Ceffio",
		Long: `Affiche l'état réel de la pile Ceffio : nœuds, couches applicatives,
ingress, certificats TLS et services exposés.

Lit l'état directement dans le cluster (aucun fichier d'inventaire à maintenir) :
si une couche est absente ou cassée, la commande le dit, ce qui reste vrai même
après une modification manuelle du cluster.`,
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

	c.Flags().BoolVar(&asJSON, "json", false, "Sortie JSON (pour scripts et supervision)")
	c.Flags().BoolVar(&showPods, "pods", false, "Détailler chaque pod (nom, état, redémarrages)")

	return c
}

func printStatus(st *stack.State, showPods bool) {
	if !st.ClusterReachable {
		fmt.Println("Ceffio — état du déploiement")
		fmt.Println()
		fmt.Println("✗ Cluster injoignable")
		fmt.Printf("  %s\n", st.ClusterError)
		fmt.Println()
		fmt.Println("Causes fréquentes :")
		fmt.Println("  · Ceffio n'est pas installé sur cette machine")
		fmt.Println("  · le service k3s est arrêté          → systemctl status k3s")
		fmt.Println("  · le kubeconfig est absent ou illisible")
		os.Exit(1)
	}

	fmt.Println("Ceffio — état du déploiement")
	fmt.Println()

	// Cluster
	fmt.Printf("Cluster   %d/%d nœud(s) prêt(s)\n", st.NodesReady, len(st.Nodes))
	for _, n := range st.Nodes {
		mark := "✓"
		if !n.Ready {
			mark = "✗"
		}
		fmt.Printf("  %s %-24s %-12s %-16s %s\n", mark, n.Name, n.Roles, n.InternalIP, n.Version)
	}

	if st.Domain != "" {
		fmt.Printf("Domaine   %s\n", st.Domain)
	}

	// Couches
	fmt.Println()
	fmt.Println("Couches")
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
			note = fmt.Sprintf("%d pod(s) non prêt(s)", l.Total-l.Ready)
		}
		line := fmt.Sprintf("  %s %-*s  %2d/%-2d", mark, width, l.Name, l.Ready, l.Total)
		if l.Restarts > 0 {
			line += fmt.Sprintf("   redémarrages : %d", l.Restarts)
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
					extra = fmt.Sprintf("  (%d redémarrage(s))", p.Restarts)
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
		fmt.Println("Accès (ingress)")
		for _, i := range st.Ingresses {
			fmt.Printf("  https://%s\n", i.Host)
		}
	}

	// Certificats
	if len(st.Certificates) > 0 {
		ready := 0
		for _, c := range st.Certificates {
			if c.Ready {
				ready++
			}
		}
		fmt.Println()
		fmt.Printf("Certificats TLS   %d/%d prêt(s)\n", ready, len(st.Certificates))
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

	// Services exposés
	lb := filterServices(st.Services)
	if len(lb) > 0 {
		fmt.Println()
		fmt.Println("Services exposés")
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
	fmt.Printf("Pods : %d/%d prêts", st.ReadyPods, st.TotalPods)
	if st.TotalRestarts > 0 {
		fmt.Printf(" · %d redémarrage(s) cumulé(s)", st.TotalRestarts)
	}
	fmt.Println()
	if st.ReadyPods == st.TotalPods && st.TotalPods > 0 && st.NodesReady == len(st.Nodes) {
		fmt.Println("✓ Plateforme opérationnelle")
	} else {
		fmt.Println("✗ État dégradé — lancez `ceffio doctor` pour le diagnostic détaillé")
		os.Exit(1)
	}
}

// filterServices ne garde que ce par quoi on entre dans la plateforme.
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
