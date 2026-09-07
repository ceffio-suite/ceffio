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
		Short: "Désinstaller Ceffio et détruire le cluster Kubernetes (K3s/k3d)",
		Long: `Détruit le cluster Kubernetes (K3s réel sur Linux, k3d en dev) et nettoie l'état
local de Ceffio. DESTRUCTIF : le cluster et ses données (volumes) sont supprimés.
Confirmation interactive, sautée avec --force.

Exemples :
  ceffio uninstall              # détruit le K3s Linux (cluster "ceffio-dev")
  ceffio uninstall --runtime dev  # détruit le cluster k3d "ceffio-dev"
  ceffio uninstall --force      # sans confirmation`,
		RunE: func(c *cobra.Command, args []string) error {
			rt, err := resolveUninstallRuntime(runtimeFlag)
			if err != nil {
				return err
			}
			if !force {
				fmt.Printf("Attention : ceci supprime le cluster %q (%s) et TOUTES ses données.\n", devClusterName, rt)
				fmt.Print("Taper 'oui' pour confirmer : ")
				reader := bufio.NewReader(os.Stdin)
				line, _ := reader.ReadString('\n')
				if strings.TrimSpace(line) != "oui" {
					fmt.Println("Abandon.")
					return nil
				}
			}
			return cluster.Destroy(c.Context(), rt, devClusterName)
		},
	}
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "k3s", "Runtime à démonter (k3s, dev)")
	cmd.Flags().BoolVar(&force, "force", false, "Sauter la confirmation")
	return cmd
}

func resolveUninstallRuntime(spec string) (cluster.Runtime, error) {
	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "k3s":
		return cluster.RuntimeK3s, nil
	case "dev", "k3d":
		return cluster.RuntimeDev, nil
	case "rke2":
		return "", fmt.Errorf("runtime rke2 : pas encore implémenté")
	default:
		return "", fmt.Errorf("runtime inconnu %q", spec)
	}
}
