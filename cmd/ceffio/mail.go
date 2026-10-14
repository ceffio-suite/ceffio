// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// Default values of the outbound relay.
//
// WHY THIS DEFAULT, AND NOT AUTOMATIC DISCOVERY: outbound port 25 is blocked
// by Free (measured), so Stalwart cannot deliver to the outside by itself —
// one.com provides the reverse DNS and the deliverability. This is not a
// guess, it is the configuration of this installation.
const (
	relaisParDefaut     = "send.one.com"
	portRelaisParDefaut = 587
)

// newMailCmd deploys the mail layer ALONE.
//
// SAME REASON AS FOR `ceffio vault` AND FOR THE CONSOLE: a component that
// cannot be redeployed alone is a component we do not dare touch. Stalwart
// was only reachable through `install`, which replays the whole stack — and
// it is ABSENT from the upgrade sequence. In other words: a fix on mail had
// no path to be applied.
//
// THE RELAY CREDENTIALS ARE READ, NOT TYPED. They come from the vault, with
// fallback to the Kubernetes Secret. Passing them as options would invite
// writing them into the shell history, and they would have to be fixed at
// every rotation — that is exactly what we are trying to remove.
func newMailCmd() *cobra.Command {
	var domain string
	var hote string
	var port int

	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Deploy the mail layer (Stalwart) alone",
		Long: `Deploys the mail server, without replaying the whole stack.

The domain of the ADDRESSES is the platform domain, not the web host
"mail.<domain>": those are two distinct things, and confusing them produces
addresses that nobody can receive.

The outbound relay credentials are read from the vault, with fallback to the
Kubernetes Secret. No secret value is ever typed as an option.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain is required")
			}
			// WE RESOLVE VAULT ACCESS BEFORE EVERYTHING ELSE.
			//
			// Without this step, the command would silently fall back on the
			// Kubernetes Secrets: the secrets module reads BAO_ADDR/BAO_TOKEN
			// from the environment, and `install` sets them for its own
			// modules, in its own process. A command run alone has nobody to
			// do it — and a silent fallback gives the illusion that the switch
			// happened.
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
			coffre := secrets.DepuisEnvironnement()
			utilisateur, err := secrets.LireOuSecret(c.Context(), coffre, "smtp", "relais",
				"username", "ceffio-files/nextcloud-smtp", "username")
			if err != nil {
				return fmt.Errorf("outbound relay user not found: %w", err)
			}
			motdepasse, err := secrets.LireOuSecret(c.Context(), coffre, "smtp", "relais",
				"password", "ceffio-files/nextcloud-smtp", "password")
			if err != nil {
				return fmt.Errorf("outbound relay password not found: %w", err)
			}
			return mail.Deploy(c.Context(), domain, hote, port, utilisateur, motdepasse)
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "ceffio.example.com", "Base domain")
	cmd.Flags().StringVar(&hote, "relais", relaisParDefaut, "Outbound relay host")
	cmd.Flags().IntVar(&port, "relais-port", portRelaisParDefaut, "Outbound relay port")
	return cmd
}
