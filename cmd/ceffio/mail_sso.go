// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// `ceffio mail sso` — check that Stalwart's single sign-on is ACTIVE, not merely
// configured.
//
// WHY THIS COMMAND EXISTS, and what it would have saved: the configuration was
// correct, complete and stored, and the sign-in still fell back to Stalwart's own
// form. The reason is that Stalwart reads its directories ONCE, at startup, into
// an in-memory snapshot — so a pod that did not restart after the configuration
// was written keeps serving the OLD one. Measured on a live installation:
//
//	before a restart:  /api/discover → issuer "" — authorization_endpoint "/login"
//	after  a restart:  /api/discover → issuer "https://keycloak.…/realms/ceffio"
//
// The trap is not the restart, which the code does: it is that NOTHING NOTICES
// when it did not happen. Stalwart writes no log line at all, so the failure is
// completely silent, and the only way to see it is to ask the server what it
// would do with an account.
//
// THAT IS WHAT THIS COMMAND ASKS. It does not read the configuration back — a
// check of what is written would pass on the broken installation, which is
// exactly the defect it exists to catch. It calls `/api/discover/<account>` and
// looks at the answer: if the issuer is the platform's own identity provider,
// the SSO is live; if it is empty and the endpoints are relative, Stalwart is
// serving its internal directory and the sign-in will never leave the page.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/mail"
)

func newMailSSOCmd() *cobra.Command {
	var domaineAdmin string
	var domaineMessagerie string
	var compteAdmin string
	var reparer bool

	cmd := &cobra.Command{
		Use:   "sso",
		Short: "Check that the mail sign-in really goes through Keycloak",
		Long: `Checks that Stalwart delegates the sign-in to the identity provider.

The check is made on the ANSWER of the server, not on its configuration: a
configuration that is correct but not loaded gives exactly the same symptom as a
missing one — a sign-in that stays on Stalwart's own form — and reading the
configuration back would pass on both.

With --repair, the configuration is reapplied and Stalwart restarted, which is
what makes a pending change take effect.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()

			// The account the check runs with. The admin account of the
			// ADMIN domain: it is the one an operator signs in with, so it is
			// the one whose answer matters.
			if compteAdmin == "" {
				compteAdmin = "adminceffio"
			}
			if domaineAdmin == "" {
				domaineAdmin = "ceffio.local"
			}
			compte := compteAdmin + "@" + domaineAdmin

			if reparer {
				fmt.Println("∙ reapplying the single sign-on configuration")
				// The issuer and the client are read from what is already
				// configured, so a repair never invents a provider.
				issuer, clientID, err := mail.SSOExistant(ctx)
				if err != nil {
					return err
				}
				if issuer == "" {
					return fmt.Errorf("no OIDC directory is configured: run `ceffio install` first")
				}
				// THE MAIL DOMAIN AND THE WEB HOST ARE TWO DIFFERENT THINGS, and
				// confusing them creates a domain nobody asked for: measured, a
				// first version of this command passed "mail.ceffio.org" (the
				// host) where the ADDRESS domain was expected, and Stalwart
				// created a third mail domain that receives nothing.
				//
				// The domain comes from the ones the server already declares,
				// minus the admin domain: those are the addresses the platform
				// serves.
				if domaineMessagerie == "" {
					d, err := mail.DomaineMessagerieExistant(ctx, domaineAdmin)
					if err != nil {
						return err
					}
					domaineMessagerie = d
				}
				hote, err := mail.HoteStalwart(ctx)
				if err != nil {
					return err
				}
				fmt.Printf("  ∙ addresses domain: %s · web host: %s\n", domaineMessagerie, hote)
				if err := mail.ConfigurerSSO(ctx, domaineMessagerie, mail.SSO{
					Hote:         hote,
					Issuer:       issuer,
					ClientID:     clientID,
					DomaineAdmin: domaineAdmin,
					CompteAdmin:  compteAdmin,
				}); err != nil {
					return err
				}
				fmt.Println()
			}

			// --- THE CHECK ---------------------------------------------------
			reponse, err := mail.Decouvrir(ctx, compte)
			if err != nil {
				return fmt.Errorf("the server did not answer: %w", err)
			}

			issuer, _ := reponse["issuer"].(string)
			authEndpoint, _ := reponse["authorization_endpoint"].(string)

			// THE DISTINCTION THAT MATTERS, and it is a property of the ANSWER
			// rather than of the configuration: a relative endpoint means
			// Stalwart is serving its own directory. An absolute one pointing at
			// the identity provider means the delegation is live.
			if issuer == "" || !strings.HasPrefix(authEndpoint, "http") {
				fmt.Println("✗ the sign-in does NOT go through the identity provider")
				fmt.Printf("  /api/discover/%s answers:\n", compte)
				fmt.Printf("    issuer                 = %q\n", issuer)
				fmt.Printf("    authorization_endpoint = %q\n", authEndpoint)
				fmt.Println()
				fmt.Println("  A RELATIVE endpoint means Stalwart is serving its OWN directory.")
				fmt.Println("  The configuration may well be correct: Stalwart reads its")
				fmt.Println("  directories once, at startup, so a configuration written since")
				fmt.Println("  the last restart is not in effect. Nothing reports it.")
				fmt.Println()
				fmt.Println("  Fix it with:  ceffio mail sso --repair")
				return fmt.Errorf("single sign-on inactive")
			}

			fmt.Println("✓ the sign-in goes through the identity provider")
			fmt.Printf("  account                : %s\n", compte)
			fmt.Printf("  issuer                 : %s\n", issuer)
			fmt.Printf("  authorization_endpoint : %s\n", authEndpoint)
			return nil
		},
	}

	cmd.Flags().StringVar(&domaineAdmin, "domaine-admin", "ceffio.local",
		"Domain of the administrator accounts")
	cmd.Flags().StringVar(&compteAdmin, "compte", "adminceffio",
		"Name of the administrator account")
	cmd.Flags().StringVar(&domaineMessagerie, "domaine", "",
		"Domain of the mail ADDRESSES (default: the first domain declared by the server "+
			"other than the admin domain) — NOT the web host")
	cmd.Flags().BoolVar(&reparer, "repair", false,
		"Reapply the configuration and restart Stalwart, then check again")
	return cmd
}
