// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/cluster"
	"github.com/ceffio-suite/ceffio/internal/upgrade"
	versionreg "github.com/ceffio-suite/ceffio/internal/version"
	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	var oui bool
	var planSeul bool
	var dir string
	var domaine string

	c := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade Ceffio (compatibility + preflight + backup)",
		Long: `Upgrades a Ceffio installation to the pinned versions of the registry.

The sequence is imposed, in this order:

  1. preflight   — healthy cluster? stable pods? versions compared to what is
                   actually RUNNING (read from Kubernetes, not from files);
  2. display     — what would change, before any action;
  3. backup      — mandatory, then VERIFIED: an archive that is not re-read
                   protects against nothing;
  4. application — idempotent deployment of the target versions;
  5. re-reading  — did the versions really change?

If a preflight fails, nothing is touched. If the backup fails, the upgrade is
canceled — and not pursued without a safety net.

--plan shows what would change without modifying anything.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			fmt.Println("Ceffio — upgrade")
			fmt.Println()
			fmt.Println("Preflight...")

			plan := upgrade.Preparer(ctx, versionreg.Registry)
			fmt.Println()

			if !plan.ClusterOK {
				for _, b := range plan.Blocages {
					fmt.Printf("  ✗ %s\n", b)
				}
				fmt.Println()
				fmt.Println("✗ Preflight refused — nothing was modified.")
				os.Exit(1)
			}

			fmt.Printf("Cluster: %d/%d node(s) ready\n", plan.NoeudsPrets, plan.NoeudsTotal)
			fmt.Println()
			fmt.Println("Versions")
			largeur := 0
			for _, e := range plan.Etats {
				if len(e.Nom) > largeur {
					largeur = len(e.Nom)
				}
			}
			for _, e := range plan.Etats {
				marque := "="
				detail := e.Installee
				if e.Installee == "" {
					marque, detail = "·", "not deployed"
				} else if e.Ecart {
					marque = "→"
					detail = e.Installee + "  →  " + e.Cible
				}
				fmt.Printf("  %s %-*s  %s\n", marque, largeur, e.Nom, detail)
			}

			if len(plan.Alertes) > 0 {
				fmt.Println()
				for _, a := range plan.Alertes {
					fmt.Printf("  · %s\n", a)
				}
			}
			if len(plan.Blocages) > 0 {
				fmt.Println()
				fmt.Println("Blockers:")
				for _, b := range plan.Blocages {
					fmt.Printf("  ✗ %s\n", b)
				}
			}

			if len(plan.Changements) == 0 {
				fmt.Println()
				fmt.Println("✓ No version drift: nothing to upgrade.")
				return nil
			}

			fmt.Println()
			fmt.Printf("%d component(s) to upgrade.\n", len(plan.Changements))
			for _, c := range plan.Changements {
				fmt.Printf("  %s : %s → %s\n", c.Nom, c.Installee, c.Cible)
			}

			if planSeul {
				fmt.Println()
				fmt.Println("--plan: no change applied.")
				return nil
			}

			if !plan.Pret {
				fmt.Println()
				fmt.Println("✗ Preflight refused — fix the blockers before upgrading.")
				os.Exit(1)
			}

			if !oui {
				fmt.Println()
				fmt.Println("A complete backup will be taken before any change.")
				fmt.Print("Confirm the upgrade (type \"yes\"): ")
				rep, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(rep)) != "yes" {
					fmt.Println("Canceled.")
					return nil
				}
			}

			fmt.Println()
			fmt.Println("Upgrading...")

			// THE BINARY ITSELF IS PART OF WHAT IS UPGRADED. The console, the
			// public-IP reporter and the Talk relay all run this image; leaving
			// it out of the target means the plan compares every component
			// except the one the operator just replaced, and answers "nothing
			// to do" while old pods keep running.
			cible := append([]versionreg.Composant{}, versionreg.Registry...)
			if binaire, ok := versionreg.ComposantBinaire(); ok {
				cible = append(cible, binaire)
			}

			res, err := upgrade.Executer(ctx, cible, upgrade.Options{
				Domain:    domaine,
				BackupDir: dir,
				Progress: func(e string) {
					fmt.Printf("  · %s\n", e)
				},
				// The application consists in replaying the deployment: each
				// module targets the pinned registry version and is idempotent.
				Appliquer: func(ctx context.Context) error {
					return cluster.Redeployer(ctx, domaine)
				},
			})
			if res != nil && res.Sauvegarde != "" {
				fmt.Println()
				fmt.Printf("Backup: %s\n", res.Sauvegarde)
			}
			if err != nil {
				fmt.Println()
				for _, e := range res.Erreurs {
					fmt.Printf("  ✗ %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Upgrade failed")
				fmt.Println()
				fmt.Println(upgrade.ConsigneRetourArriere(res))
				os.Exit(1)
			}

			fmt.Println()
			if len(res.Erreurs) > 0 {
				fmt.Println("Persistent drifts after upgrade:")
				for _, e := range res.Erreurs {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("Rollback if needed:")
				fmt.Println("  " + res.Rollback)
				os.Exit(1)
			}
			fmt.Println("✓ Upgrade complete")
			fmt.Println()
			fmt.Println("Check the state with: ceffio status")
			return nil
		},
	}

	c.Flags().BoolVar(&oui, "yes", false, "Do not ask for confirmation")
	c.Flags().BoolVar(&planSeul, "plan", false, "Show what would change, without modifying anything")
	c.Flags().StringVar(&dir, "dir", ".", "Directory for the preliminary backup")
	c.Flags().StringVar(&domaine, "domain", "", "Base domain (deduced when absent)")

	return c
}
