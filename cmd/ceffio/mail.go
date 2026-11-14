// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newMailCmd deploys the mail layer ALONE.
//
// SAME REASON AS FOR `ceffio vault` AND FOR THE CONSOLE: a component that
// cannot be redeployed alone is a component we do not dare touch. Stalwart
// was only reachable through `install`, which replays the whole stack — and
// it is ABSENT from the upgrade sequence. In other words: a fix on mail had
// no path to be applied.
//
// THE RELAY IS A SETTING NOW, not a parameter of this command. The deployment
// reads the mail module's settings — relay group included — so a command line
// that passed a host and a port on every run would be a second source for a
// value the page also edits, and the last writer would win silently. The two
// legacy flags are kept, and they WRITE THE SETTINGS through the module, so a
// script that passes them still works and still lands in one place.
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

The outbound relay comes from the mail module's settings (the relay group),
which this command reads and applies. --relais and --relais-port are kept for
scripts: when given they are WRITTEN TO THOSE SETTINGS first, then applied, so
there is still exactly one place where the relay is configured.

The relay password lives in the vault (kv/ceffio/mail/relay): it is never
typed as an option, and never written to a ConfigMap.

Once deployed, ceffio module check mail says whether the world can actually
reach it — MX, PTR, port 25, TLS, the DNS records — and docs/mail.md explains
each check and how to fix it.`,
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
			if err := mail.Deploy(c.Context(), domain); err != nil {
				return err
			}
			// The legacy flags are written AFTER the deployment, because they
			// end by re-applying the server configuration: on a cluster where
			// the mail layer does not exist yet, there would be nothing to
			// apply them to.
			if c.Flags().Changed("relais") || c.Flags().Changed("relais-port") {
				if err := enregistrerRelaisInitial(c.Context(), domain, hote, port, "", ""); err != nil {
					return err
				}
			}
			return nil
		},
	}

	// The sign-in check, on its own subcommand: it VERIFIES an effect rather
	// than deploying anything, and an operator looking for it will type
	// `ceffio mail sso` — see mail_sso.go for why the check reads the server's
	// answer instead of its configuration.
	cmd.AddCommand(newMailSSOCmd())

	cmd.Flags().StringVar(&domain, "domain", "ceffio.example.com", "Base domain")
	cmd.Flags().StringVar(&hote, "relais", "", "Outbound relay host, written to the mail settings")
	cmd.Flags().IntVar(&port, "relais-port", 587, "Outbound relay port, written to the mail settings")
	return cmd
}
