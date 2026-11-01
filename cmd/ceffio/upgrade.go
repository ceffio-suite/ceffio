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
	"github.com/ceffio-suite/ceffio/internal/module"
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

			cible := cibleUpgrade()

			plan := upgrade.Preparer(ctx, cible)
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
				if planSeul {
					fmt.Println("✓ No version drift: nothing to upgrade.")
					return nil
				}
				// PAS DE DÉRIVE DE VERSION, MAIS UNE CONVERGENCE À FAIRE : les
				// modules optionnels installés ne sont pas des composants du
				// registre, le plan ne les voit pas, et ils suivent le binaire
				// au moment du rejeu — pas avant.
				fmt.Println("· No version drift in the registry: replaying the installation, " +
					"so the installed modules follow the binary.")
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

			res, err := upgrade.Executer(ctx, cibleUpgrade(), upgrade.Options{
				Domain:    domaine,
				BackupDir: dir,
				Progress: func(e string) {
					fmt.Printf("  · %s\n", e)
				},
				// The application consists in replaying the deployment: each
				// module targets the pinned registry version and is idempotent.
				//
				// AND THE INSTALLED OPTIONAL MODULES ARE REPLAYED TOO: they are
				// not part of the core layers, and without this a module
				// installed once keeps the image of that day — a relay three
				// releases behind, two versions of the binary running at once.
				// Une convergence : même sans dérive de version, les modules
				// optionnels installés sont rejoués (ils suivent le binaire).
				ToujoursRejouer: true,
				Appliquer: func(ctx context.Context) error {
					if err := cluster.Redeployer(ctx, domaine); err != nil {
						return err
					}
					return module.RejouerInstalles(ctx, module.All(), moduleEnv(domaine),
						func(e string) { fmt.Printf("  · %s\n", e) })
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

// cibleUpgrade is what an upgrade moves: the version registry, AND the binary
// itself.
//
// THE BINARY IS PART OF THE TARGET. The console, the public-IP reporter and the
// Talk relay all run the same image; leaving it out of the plan means comparing
// every component except the one the operator just replaced — and answering
// "nothing to do" while those pods keep an older version. That is not
// hypothetical: it is how the reporter was found three releases behind.
func cibleUpgrade() []versionreg.Composant {
	cible := append([]versionreg.Composant{}, versionreg.Registry...)
	if binaire, ok := versionreg.ComposantBinaire(); ok {
		cible = append(cible, binaire)
	}
	return cible
}
