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
	var video bool

	c := &cobra.Command{
		Use:   "upgrade",
		Short: "Mettre à niveau Ceffio (compatibilité + préflight + backup)",
		Long: `Met à niveau une installation Ceffio vers les versions épinglées du registre.

Le déroulé est imposé, dans cet ordre :

  1. préflight   — cluster sain ? pods stables ? versions comparées à ce qui
                   TOURNE réellement (lu dans Kubernetes, pas dans les fichiers) ;
  2. affichage   — ce qui changerait, avant toute action ;
  3. sauvegarde  — obligatoire, puis VÉRIFIÉE : une archive non relue ne
                   protège de rien ;
  4. application — déploiement idempotent des versions cibles ;
  5. relecture   — les versions ont-elles vraiment changé ?

Si un préflight échoue, rien n'est touché. Si la sauvegarde échoue, la mise à
niveau est annulée — et non poursuivie sans filet.

--plan affiche ce qui changerait sans rien modifier.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			fmt.Println("Ceffio — mise à niveau")
			fmt.Println()
			fmt.Println("Préflight...")

			plan := upgrade.Preparer(ctx, versionreg.Registry)
			fmt.Println()

			if !plan.ClusterOK {
				for _, b := range plan.Blocages {
					fmt.Printf("  ✗ %s\n", b)
				}
				fmt.Println()
				fmt.Println("✗ Préflight refusé — rien n'a été modifié.")
				os.Exit(1)
			}

			fmt.Printf("Cluster : %d/%d nœud(s) prêt(s)\n", plan.NœudsPrets, plan.NœudsTotal)
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
					marque, detail = "·", "non déployé"
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
				fmt.Println("Blocages :")
				for _, b := range plan.Blocages {
					fmt.Printf("  ✗ %s\n", b)
				}
			}

			if len(plan.Changements) == 0 {
				fmt.Println()
				fmt.Println("✓ Aucun écart de version : rien à mettre à niveau.")
				return nil
			}

			fmt.Println()
			fmt.Printf("%d composant(s) à mettre à niveau.\n", len(plan.Changements))
			for _, c := range plan.Changements {
				fmt.Printf("  %s : %s → %s\n", c.Nom, c.Installee, c.Cible)
			}

			if planSeul {
				fmt.Println()
				fmt.Println("--plan : aucune modification appliquée.")
				return nil
			}

			if !plan.Pret {
				fmt.Println()
				fmt.Println("✗ Préflight refusé — corriger les blocages avant de mettre à niveau.")
				os.Exit(1)
			}

			if !oui {
				fmt.Println()
				fmt.Println("Une sauvegarde complète sera prise avant toute modification.")
				fmt.Print("Confirmer la mise à niveau (tapez « oui ») : ")
				rep, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(rep)) != "oui" {
					fmt.Println("Annulé.")
					return nil
				}
			}

			fmt.Println()
			fmt.Println("Mise à niveau...")

			res, err := upgrade.Executer(ctx, versionreg.Registry, upgrade.Options{
				Domain:    domaine,
				BackupDir: dir,
				Video:     video,
				Progress: func(e string) {
					fmt.Printf("  · %s\n", e)
				},
				// L'application consiste à rejouer le déploiement : chaque module
				// vise la version épinglée du registre et est idempotent.
				Appliquer: func(ctx context.Context) error {
					return cluster.Redeployer(ctx, domaine, video)
				},
			})
			if res != nil && res.Sauvegarde != "" {
				fmt.Println()
				fmt.Printf("Sauvegarde : %s\n", res.Sauvegarde)
			}
			if err != nil {
				fmt.Println()
				for _, e := range res.Erreurs {
					fmt.Printf("  ✗ %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Échec de la mise à niveau")
				fmt.Println()
				fmt.Println(upgrade.ConsigneRetourArriere(res))
				os.Exit(1)
			}

			fmt.Println()
			if len(res.Erreurs) > 0 {
				fmt.Println("Écarts persistants après mise à niveau :")
				for _, e := range res.Erreurs {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("Retour arrière si nécessaire :")
				fmt.Println("  " + res.Rollback)
				os.Exit(1)
			}
			fmt.Println("✓ Mise à niveau terminée")
			fmt.Println()
			fmt.Println("Contrôlez l'état avec : ceffio status")
			return nil
		},
	}

	c.Flags().BoolVar(&oui, "yes", false, "Ne pas demander de confirmation")
	c.Flags().BoolVar(&planSeul, "plan", false, "Afficher ce qui changerait, sans rien modifier")
	c.Flags().StringVar(&dir, "dir", ".", "Répertoire de la sauvegarde préalable")
	c.Flags().StringVar(&domaine, "domain", "", "Domaine de base (déduit si absent)")
	c.Flags().BoolVar(&video, "video", false, "La visioconférence est installée (déployée aussi)")

	return c
}
