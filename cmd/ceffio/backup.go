package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ceffio-suite/ceffio/internal/backup"
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	var dir string
	var verifier bool

	c := &cobra.Command{
		Use:   "backup",
		Short: "Sauvegarder les données (PostgreSQL, fichiers, media, config)",
		Long: `Sauvegarde une installation Ceffio dans une archive autoportante.

Contenu :
  · les bases PostgreSQL   mysuite, keycloak, nextcloud, synapse
  · les volumes            nextcloud-data, synapse-media, onlyoffice-data,
                           jitsi-config
  · les Secrets applicatifs — sans eux, les données restaurées seraient
                           orphelines (mots de passe de base, clés de
                           signature Matrix et ONLYOFFICE)
  · un manifeste           empreintes SHA-256 de chaque élément

L'archive est écrite dans le répertoire courant, ou dans --dir. Elle contient
des secrets : elle est créée en 0600 et ne doit pas être déposée en clair sur
un partage.

Avec --verify (par défaut), l'archive est relue et chaque empreinte
recontrôlée juste après sa création — c'est ce qui distingue une sauvegarde
d'un fichier de taille inconnue.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Ceffio — sauvegarde")
			fmt.Println()

			path, err := backup.Sauvegarder(cmd.Context(), dir, func(etape string) {
				fmt.Printf("  · %s\n", etape)
			})
			if err != nil {
				return err
			}

			man, err := backup.Verifier(path)
			if err == nil {
				fmt.Println()
				fmt.Printf("Archive  : %s\n", path)
				fmt.Printf("Taille   : %.1f Mo\n", float64(man.TotalBytes)/1024/1024)
				fmt.Printf("Éléments : %d\n", len(man.Entries))
				for _, e := range man.Entries {
					fmt.Printf("  %-8s %-20s %8.3f Mo  %s\n", e.Kind, e.Name,
						float64(e.Bytes)/1024/1024, e.SHA256[:12])
				}
			}

			if len(man.Errors) > 0 {
				fmt.Println()
				fmt.Println("Avertissements :")
				for _, e := range man.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Sauvegarde incomplète — voir les avertissements ci-dessus")
				os.Exit(1)
			}

			if verifier {
				fmt.Println()
				if err := verifierArchive(path); err != nil {
					return err
				}
			}

			fmt.Println()
			fmt.Println("✓ Sauvegarde complète")
			fmt.Println()
			fmt.Println("Pour restaurer : ceffio restore " + filepath.Base(path))
			return nil
		},
	}

	c.Flags().StringVar(&dir, "dir", ".", "Répertoire de destination de l'archive")
	c.Flags().BoolVar(&verifier, "verify", true, "Relire l'archive et contrôler les empreintes")

	return c
}

// printManifeste affiche le résumé d'une sauvegarde.
func printManifeste(man *backup.Manifest) {
	if man.CreatedAt != "" {
		fmt.Printf("  créée le   : %s\n", man.CreatedAt)
	}
	if man.Domain != "" {
		fmt.Printf("  domaine    : %s\n", man.Domain)
	}
	if man.K8sVersion != "" {
		fmt.Printf("  kubernetes : %s\n", man.K8sVersion)
	}
	fmt.Printf("  éléments   : %d (%.1f Mo)\n", len(man.Entries), float64(man.TotalBytes)/1024/1024)
	for _, e := range man.Entries {
		fmt.Printf("    %-8s %s\n", e.Kind, e.Name)
	}
}

// verifierArchive relit une archive et contrôle chaque empreinte.
// Extrait ici pour être partagé avec `ceffio restore`.
func verifierArchive(path string) error {
	man, err := backup.Verifier(path)
	if err != nil {
		return err
	}
	if !man.Complete {
		for _, e := range man.Errors {
			fmt.Printf("  ! %s\n", e)
		}
		return fmt.Errorf("archive incomplète ou altérée")
	}
	fmt.Printf("✓ Archive vérifiée : %d élément(s), empreintes conformes\n", len(man.Entries))
	return nil
}
