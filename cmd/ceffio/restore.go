package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/backup"
	"github.com/spf13/cobra"
)

func newRestoreCmd() *cobra.Command {
	var oui bool
	var seulementVerifier bool

	c := &cobra.Command{
		Use:   "restore <backup>",
		Short: "Restaurer un backup complet",
		Long: `Restaure une installation Ceffio depuis une archive produite par « ceffio backup ».

Ordre d'application, imposé par les dépendances :
  1. les Secrets       — sinon les mots de passe de base ne correspondent plus
  2. les bases         — identités, comptes, métadonnées
  3. les volumes       — les documents, qui référencent ces métadonnées

L'archive est VÉRIFIÉE avant toute écriture (empreintes du manifeste) : une
sauvegarde incomplète ou altérée est refusée plutôt que partiellement appliquée.

La restauration des bases remplace le contenu existant (le dump a été pris avec
--clean). Les fichiers présents sur les volumes mais absents de l'archive ne sont
PAS supprimés : une restauration ne doit pas détruire ce qu'elle ne sait pas
remplacer.

Cette opération est destructive : elle demande confirmation, sauf avec --yes.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := args[0]

			fmt.Println("Ceffio — restauration")
			fmt.Println()
			fmt.Printf("Archive : %s\n", archive)
			fmt.Println()

			// 1. Inspection et vérification AVANT toute écriture.
			fmt.Println("Vérification de l'archive...")
			man, err := backup.Verifier(archive)
			if err != nil {
				return err
			}
			if !man.Complete {
				for _, e := range man.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Archive REFUSÉE : restaurer une sauvegarde incomplète ajouterait")
				fmt.Println("  une panne à la panne. Vérifiez l'archive d'origine.")
				os.Exit(1)
			}
			fmt.Printf("✓ %d élément(s), empreintes conformes\n", len(man.Entries))
			fmt.Println()
			fmt.Println("Contenu :")
			printManifeste(man)

			if seulementVerifier {
				fmt.Println()
				fmt.Println("--verify-only : aucune modification appliquée.")
				return nil
			}

			// 2. Confirmation explicite.
			if !oui {
				fmt.Println()
				fmt.Println("Cette opération va REMPLACER le contenu des bases et des volumes")
				fmt.Println("de l'installation courante. Elle est irréversible.")
				fmt.Print("Confirmer (tapez « oui ») : ")
				rep, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(rep)) != "oui" {
					fmt.Println("Annulé.")
					return nil
				}
			}

			// 3. Restauration.
			fmt.Println()
			fmt.Println("Restauration...")
			res, err := backup.Restaurer(cmd.Context(), archive, func(etape string) {
				fmt.Printf("  · %s\n", etape)
			})
			if err != nil {
				return err
			}
			fmt.Println()

			if len(res.Errors) > 0 {
				fmt.Println("Erreurs pendant la restauration :")
				for _, e := range res.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Restauration incomplète")
				os.Exit(1)
			}

			fmt.Println("✓ Restauration terminée")

			// 4. Vérification post-restauration : les données sont-elles
			//    réellement là ? Compter ce qu'on vient de restaurer est la
			//    seule façon de ne pas se contenter de « la commande a réussi ».
			fmt.Println()
			fmt.Println("Contrôle des données restaurées...")
			for _, e := range res.Entries {
				if e.Kind != "base" {
					continue
				}
				n := backup.CompterTables(cmd.Context(), e.Name)
				status := "✓"
				if n < 0 {
					status = "✗"
					n = 0
				}
				fmt.Printf("  %s base %-12s %d table(s)\n", status, e.Name, n)
			}
			fmt.Println()
			fmt.Println("Relancez les applications pour qu'elles reprennent la main :")
			fmt.Println("  ceffio status   puis   kubectl rollout restart -n <ns> deploy")
			return nil
		},
	}

	c.Flags().BoolVar(&oui, "yes", false, "Ne pas demander de confirmation")
	c.Flags().BoolVar(&seulementVerifier, "verify-only", false, "Vérifier l'archive sans rien restaurer")

	return c
}
