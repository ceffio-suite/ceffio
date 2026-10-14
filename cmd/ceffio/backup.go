// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

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
		Short: "Back up the data (PostgreSQL, files, media, config)",
		Long: `Backs up a Ceffio installation into a self-contained archive.

Contents:
  · the PostgreSQL databases   mysuite, keycloak, nextcloud
  · the volumes                nextcloud-data, onlyoffice-data
  · the application Secrets — without them, the restored data would be
                               orphaned (database passwords, signing
                               keys and ONLYOFFICE)
  · a manifest                 SHA-256 fingerprints of every item

The archive is written to the current directory, or into --dir. It contains
secrets: it is created 0600 and must not be left in clear text on a share.

With --verify (default), the archive is re-read and every fingerprint
rechecked right after its creation — that is what distinguishes a backup
from a file of unknown size.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Ceffio — backup")
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
				fmt.Printf("Size     : %.1f MB\n", float64(man.TotalBytes)/1024/1024)
				fmt.Printf("Items    : %d\n", len(man.Entries))
				for _, e := range man.Entries {
					fmt.Printf("  %-8s %-20s %8.3f MB  %s\n", e.Kind, e.Name,
						float64(e.Bytes)/1024/1024, e.SHA256[:12])
				}
			}

			if len(man.Errors) > 0 {
				fmt.Println()
				fmt.Println("Warnings:")
				for _, e := range man.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Incomplete backup — see the warnings above")
				os.Exit(1)
			}

			if verifier {
				fmt.Println()
				if err := verifierArchive(path); err != nil {
					return err
				}
			}

			fmt.Println()
			fmt.Println("✓ Backup complete")
			fmt.Println()
			fmt.Println("To restore: ceffio restore " + filepath.Base(path))
			return nil
		},
	}

	c.Flags().StringVar(&dir, "dir", ".", "Destination directory for the archive")
	c.Flags().BoolVar(&verifier, "verify", true, "Re-read the archive and check the fingerprints")

	return c
}

// printManifeste prints the summary of a backup.
func printManifeste(man *backup.Manifest) {
	if man.CreatedAt != "" {
		fmt.Printf("  created on : %s\n", man.CreatedAt)
	}
	if man.Domain != "" {
		fmt.Printf("  domain     : %s\n", man.Domain)
	}
	if man.K8sVersion != "" {
		fmt.Printf("  kubernetes : %s\n", man.K8sVersion)
	}
	fmt.Printf("  items      : %d (%.1f MB)\n", len(man.Entries), float64(man.TotalBytes)/1024/1024)
	for _, e := range man.Entries {
		fmt.Printf("    %-8s %s\n", e.Kind, e.Name)
	}
}

// verifierArchive re-reads an archive and checks every fingerprint.
// Extracted here to be shared with `ceffio restore`.
func verifierArchive(path string) error {
	man, err := backup.Verifier(path)
	if err != nil {
		return err
	}
	if !man.Complete {
		for _, e := range man.Errors {
			fmt.Printf("  ! %s\n", e)
		}
		return fmt.Errorf("incomplete or corrupted archive")
	}
	fmt.Printf("✓ Archive verified: %d item(s), fingerprints match\n", len(man.Entries))
	return nil
}
