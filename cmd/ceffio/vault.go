// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newVaultCmd deploys the secrets vault ALONE.
//
// WHY A SEPARATE COMMAND, AND NOT JUST THE `install` BLOCK: two reasons, both
// drawn from reality.
//
// First, surgery. `install` replays the whole stack. On a platform in service,
// that is disproportionate when we only want the vault — and `install` still
// carries a known defect on an existing cluster (it attempts to recreate
// `ceffio-dev` and fails on `update.k3s.io`). Deploying the vault must not
// depend on the rest being repaired first.
//
// Then, day-to-day operations: a vault that cannot be redeployed alone is a
// vault we do not dare touch. After an OpenBao upgrade, a configuration change
// or a rotation of the unseal key, this is the command we want at hand.
//
// IT IS IDEMPOTENT, like the rest: running it again destroys nothing,
// regenerates no key, and does not reinitialize an already initialized vault.
// Reinitializing it would make the existing secrets unreadable.
func newVaultCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "vault",
		Short: "Deploy the secrets vault (OpenBao)",
		Long: `Deploys the suite's OpenBao secrets vault, and readies it for use.

The deployment is idempotent and happens in this order:

  1. the namespace and the unseal key (32 bytes, the "zero-secret");
  2. the configuration: raft storage, static seal, declared audit journal;
  3. the StatefulSet, its volume and its service;
  4. the initialization, only if the vault is not already initialized;
  5. the versioned KV engine, at path "kv";
  6. an administration policy, a derived token, and the REVOCATION of the root
     token — a master token that survives the setup is a defect;
  7. an end-to-end check: write, re-read, and prove that the vault REFUSES a
     path outside the policy's perimeter.

What this command does NOT do, and which must be known: it does not move any
existing secret to the vault. The Kubernetes Secrets stay in place, and the
components keep reading them. It is a deployment, not a migration.

The unseal key lives in a Kubernetes Secret, on the same machine as the vault:
whoever gets the machine gets the vault. That is the compromise of automatic
unsealing, accepted and written down here rather than discovered later.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			domaine, _ := cmd.Flags().GetString("domain")
			res := vault.Deploy(cmd.Context(), domaine)

			fmt.Println()
			if !res.Pret {
				// Error exit, but without drama: it is a statement of fact,
				// not a failure of the suite's deployment. The secrets stay in
				// Kubernetes and everything keeps working.
				return fmt.Errorf("the vault is not in service — secrets stay in Kubernetes")
			}

			fmt.Println("✓ Secrets vault in service")
			fmt.Printf("  address: %s\n", res.Adresse)
			fmt.Println("  token   : stored in the openbao-token Secret (not shown)")
			fmt.Println()
			fmt.Println("For the components to use it, export:")
			fmt.Printf("  BAO_ADDR=%s\n", res.Adresse)
			fmt.Println("  BAO_TOKEN=<read from the openbao-token Secret>")
			return nil
		},
	}
	// SAME DEFAULT AS `install`, AND FOR THE SAME REASON: the production
	// domain is *.ceffio.example.com until further notice. Overridable for
	// another environment.
	c.Flags().String("domain", "ceffio.example.com", "Base domain (e.g. company.fr)")
	return c
}
