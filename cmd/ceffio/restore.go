// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

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
		Short: "Restore a complete backup",
		Long: `Restores a Ceffio installation from an archive produced by "ceffio backup".

Order of application, imposed by the dependencies:
  1. the Secrets       — otherwise the database passwords no longer match
  2. the databases     — identities, accounts, metadata
  3. the volumes       — the documents, which reference that metadata

The archive is VERIFIED before any write (manifest fingerprints): an
incomplete or corrupted backup is refused rather than partially applied.

Restoring the databases replaces the existing content (the dump was taken
with --clean). Files present on the volumes but missing from the archive are
NOT deleted: a restore must not destroy what it does not know how to replace.

This operation is destructive: it asks for confirmation, except with --yes.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			archive := args[0]

			fmt.Println("Ceffio — restore")
			fmt.Println()
			fmt.Printf("Archive : %s\n", archive)
			fmt.Println()

			// 1. Inspection and verification BEFORE any write.
			fmt.Println("Verifying the archive...")
			man, err := backup.Verifier(archive)
			if err != nil {
				return err
			}
			if !man.Complete {
				for _, e := range man.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Archive REFUSED: restoring an incomplete backup would add")
				fmt.Println("  an outage on top of an outage. Check the original archive.")
				os.Exit(1)
			}
			fmt.Printf("✓ %d item(s), fingerprints match\n", len(man.Entries))
			fmt.Println()
			fmt.Println("Contents:")
			printManifeste(man)

			if seulementVerifier {
				fmt.Println()
				fmt.Println("--verify-only: no change applied.")
				return nil
			}

			// 2. Explicit confirmation.
			if !oui {
				fmt.Println()
				fmt.Println("This operation will REPLACE the contents of the databases and volumes")
				fmt.Println("of the current installation. It is irreversible.")
				fmt.Print("Confirm (type \"yes\"): ")
				rep, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(rep)) != "yes" {
					fmt.Println("Canceled.")
					return nil
				}
			}

			// 3. Restore.
			fmt.Println()
			fmt.Println("Restoring...")
			res, err := backup.Restaurer(cmd.Context(), archive, func(etape string) {
				fmt.Printf("  · %s\n", etape)
			})
			if err != nil {
				return err
			}
			fmt.Println()

			if len(res.Errors) > 0 {
				fmt.Println("Errors during the restore:")
				for _, e := range res.Errors {
					fmt.Printf("  ! %s\n", e)
				}
				fmt.Println()
				fmt.Println("✗ Incomplete restore")
				os.Exit(1)
			}

			fmt.Println("✓ Restore complete")

			// 4. Post-restore check: is the data actually there? Counting what
			//    was just restored is the only way not to settle for "the
			//    command succeeded".
			fmt.Println()
			fmt.Println("Checking the restored data...")
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
			fmt.Println("Restart the applications so they take over again:")
			fmt.Println("  ceffio status   then   kubectl rollout restart -n <ns> deploy")
			return nil
		},
	}

	c.Flags().BoolVar(&oui, "yes", false, "Do not ask for confirmation")
	c.Flags().BoolVar(&seulementVerifier, "verify-only", false, "Verify the archive without restoring anything")

	return c
}
