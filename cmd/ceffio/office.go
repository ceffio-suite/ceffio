// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newOfficeCmd deploys the office layer ALONE.
//
// SAME REASON AS FOR MAIL AND THE CONSOLE: ONLYOFFICE was only deployable
// through `install`, which replays the whole stack. Yet it is precisely the
// component whose signing token is shared with Nextcloud — so the one we want
// to be able to redeploy alone after a rotation, without touching the rest.
func newOfficeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "office",
		Short: "Deploy the office layer (ONLYOFFICE) alone",
		Long: `Deploys the document server and (re)plugs its connector into Nextcloud.

THE SIGNING TOKEN IS READ FROM THE VAULT, with fallback to the Kubernetes
Secret. This same token must feed both sides — the server and the connector
configuration. Reading them from the same place is what makes a rotation
complete: otherwise the signature stops matching, and the symptom is an
authentication error on documents rather than a half-done rotation.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// We resolve vault access BEFORE everything else: without it, the
			// command would silently fall back on the Kubernetes Secrets and
			// would never read the vault — the fallback would give the
			// illusion that the switch happened.
			if client, err := k8sapi.Nouveau(); err == nil {
				if adresse, jeton, err := vault.Acces(c.Context(), client); err == nil {
					os.Setenv("BAO_ADDR", adresse)
					os.Setenv("BAO_TOKEN", jeton)
					os.Setenv("BAO_MOTEUR", "kv")
					fmt.Printf("  ∙ vault: %s (secrets come from it first)\n", adresse)
				} else {
					fmt.Printf("  ∙ vault unresolved (%v) — secrets will come from Kubernetes\n", err)
				}
			}
			return office.Deploy(c.Context())
		},
	}
	return c
}
