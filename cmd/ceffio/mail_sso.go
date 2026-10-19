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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/mail"
)

func newMailSSOCmd() *cobra.Command {
	var domaineAdmin string
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
				issuer, clientID, err := lireSSOExistant(ctx)
				if err != nil {
					return err
				}
				if issuer == "" {
					return fmt.Errorf("no OIDC directory is configured: run `ceffio install` first")
				}
				// The host is the mail host, which the server itself reports.
				hote, err := hoteStalwart(ctx)
				if err != nil {
					return err
				}
				if err := mail.ConfigurerSSO(ctx, hote, mail.SSO{
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
			reponse, err := discover(ctx, compte)
			if err != nil {
				return fmt.Errorf("the server did not answer: %w", err)
			}

			issuer := chaine(reponse["issuer"])
			authEndpoint := chaine(reponse["authorization_endpoint"])

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
	cmd.Flags().BoolVar(&reparer, "repair", false,
		"Reapply the configuration and restart Stalwart, then check again")
	return cmd
}

// discover calls /api/discover for an account and returns the parsed answer.
//
// THROUGH THE POD, not through the public address: the call stays on the
// internal network, works even when the ingress or the certificate is broken,
// and asks the server itself rather than a proxy in front of it.
func discover(ctx context.Context, compte string) (map[string]interface{}, error) {
	script := `curl -s --max-time 15 "http://localhost:8080/api/discover/` + compte + `"`
	out, err := k8s.Command(ctx, "kubectl", "-n", "ceffio-mail", "exec", "deploy/stalwart",
		"-c", "stalwart", "--", "sh", "-c", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, tronquer(string(out), 200))
	}
	var reponse map[string]interface{}
	if err := json.Unmarshal(out, &reponse); err != nil {
		return nil, fmt.Errorf("unreadable answer (%s): %w", tronquer(string(out), 200), err)
	}
	return reponse, nil
}

// lireSSOExistant returns the issuer and the client already configured.
//
// READ FROM THE SERVER rather than from an option: a repair must not be able to
// invent a provider. An operator who runs it on an installation pointed at
// Authentik would otherwise silently get Keycloak.
func lireSSOExistant(ctx context.Context) (string, string, error) {
	script := `. /secrets/env 2>/dev/null; ` +
		`curl -s --max-time 15 -u "$STALWART_RECOVERY_ADMIN" -H "Content-Type: application/json" ` +
		`-X POST http://localhost:8080/jmap -d '{"using":[],"methodCalls":[["x:Directory/get",` +
		`{"accountId":"d333333","properties":["@type","issuerUrl","requireAudience"]},"c1"]]}'`
	out, err := k8s.Command(ctx, "kubectl", "-n", "ceffio-mail", "exec", "deploy/stalwart",
		"-c", "stalwart", "--", "sh", "-c", script).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("reading the OIDC directory: %w: %s", err, tronquer(string(out), 200))
	}
	var reponse struct {
		MethodResponses []json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(out, &reponse); err != nil || len(reponse.MethodResponses) == 0 {
		return "", "", fmt.Errorf("unreadable directory answer: %s", tronquer(string(out), 200))
	}
	var couple []json.RawMessage
	if err := json.Unmarshal(reponse.MethodResponses[0], &couple); err != nil || len(couple) < 2 {
		return "", "", fmt.Errorf("unexpected answer: %s", tronquer(string(out), 200))
	}
	var corps struct {
		List []struct {
			Type     string `json:"@type"`
			Issuer   string `json:"issuerUrl"`
			Audience string `json:"requireAudience"`
		} `json:"list"`
	}
	if err := json.Unmarshal(couple[1], &corps); err != nil {
		return "", "", fmt.Errorf("unreadable directory body: %w", err)
	}
	for _, d := range corps.List {
		if d.Type == "Oidc" && d.Issuer != "" {
			return d.Issuer, d.Audience, nil
		}
	}
	return "", "", nil
}

// hoteStalwart returns the public host the server publishes.
//
// FROM ITS OWN DISCOVERY DOCUMENT: the host is what the server believes it is,
// and an operator who fronts it on another name would otherwise get a
// configuration pointing at the wrong address.
func hoteStalwart(ctx context.Context) (string, error) {
	script := `curl -s --max-time 15 http://localhost:8080/.well-known/openid-configuration`
	out, err := k8s.Command(ctx, "kubectl", "-n", "ceffio-mail", "exec", "deploy/stalwart",
		"-c", "stalwart", "--", "sh", "-c", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reading the server's own discovery: %w: %s", err, tronquer(string(out), 200))
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return "", fmt.Errorf("unreadable discovery (%s): %w", tronquer(string(out), 200), err)
	}
	hote := strings.TrimPrefix(strings.TrimPrefix(doc.Issuer, "https://"), "http://")
	if hote == "" {
		return "", fmt.Errorf("the server publishes no issuer: its public URL is not configured")
	}
	return hote, nil
}

// tronquer shortens an output for an error message.
//
// The console's helper is unexported and lives in another package; this command
// needs the same behaviour for its own error paths.
func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// chaine reads a string field, tolerating a null.
func chaine(v interface{}) string {
	s, _ := v.(string)
	return s
}
