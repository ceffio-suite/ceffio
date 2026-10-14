package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/files"
	"github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newFilesCmd deploys the files layer (Nextcloud) ALONE.
//
// WITH --domain, the command GOES ALL THE WAY TO THE SSO HOOKUP. Without this
// flag, it stops at the deployment — which left no recourse when only the SSO
// was broken: the hookup function was only called by the full installation,
// never by the command of the concerned component.
func newFilesCmd() *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "files",
		Short: "Deploy the files layer (Nextcloud) alone",
		Long: `Deploys Nextcloud and its storage.

ITS CREDENTIALS COME FROM THE VAULT, AND FROM NOWHERE ELSE: the database's, and
the administration account's. The pod only reads a file that the injector
composes from several entries — the database and the administration are two
distinct accounts, and the container does not need to know this split.

WITH --domain, also hooks Nextcloud to the Keycloak SSO (user_oidc app + provider).
The command then RE-READS what was recorded and fails if the provider lacks its
credentials: an empty provider leaves a login page at 404.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			resoudreCoffre(c)
			if err := files.Deploy(c.Context()); err != nil {
				return err
			}
			if domain == "" {
				return nil
			}
			return files.ConfigureOIDC(c.Context(), domain)
		},
	}
	cmd.Flags().StringVar(&domain, "domain", "",
		"Also hook up the SSO (e.g. ceffio.example.com); without this flag, deployment only")
	return cmd
}

// newIdentityCmd deploys the identity layer (Keycloak) ALONE.
func newIdentityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "identity",
		Short: "Deploy the identity layer (Keycloak) alone",
		Long: `Deploys Keycloak, which carries the authentication of the whole suite.

Same rules as for files: the database credentials and the administration
account come from the vault, and the pod reads them through the injector.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			resoudreCoffre(c)
			return identity.Deploy(c.Context())
		},
	}
}

// resoudreCoffre puts vault access into the environment, before any read.
//
// Without this resolution, the modules would fail at both reading and writing,
// and the error message would speak of an unreachable vault without saying why.
func resoudreCoffre(c *cobra.Command) {
	client, err := k8sapi.Nouveau()
	if err != nil {
		fmt.Printf("  ∙ Kubernetes client unavailable (%v)\n", err)
		return
	}
	adresse, jeton, err := vault.Acces(c.Context(), client)
	if err != nil {
		fmt.Printf("  ∙ vault unresolved (%v) — the command is going to fail: that is intended\n", err)
		return
	}
	os.Setenv("BAO_ADDR", adresse)
	os.Setenv("BAO_TOKEN", jeton)
	os.Setenv("BAO_MOTEUR", "kv")
	fmt.Printf("  ∙ vault: %s (single source of secrets)\n", adresse)
}
