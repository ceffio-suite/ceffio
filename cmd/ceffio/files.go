// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"os"
	"strings"

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
			// THE DOMAIN, before Deploy: it reapplies the suite's OIDC clients, and
			// their return addresses are built from it. Without it the clients are
			// left alone rather than pointed at a guessed host.
			if d := domaineDeLaPlateforme(c.Context()); d != "" {
				identity.PoserDomaine(d)
			}
			return identity.Deploy(c.Context())
		},
	}
}

// domaineDeLaPlateforme reads the installation's domain from the ingress layer's own
// configuration, so `ceffio identity` has no second --domain flag.
//
// AN EMPTY ANSWER IS NOT FATAL: Deploy then skips the OIDC clients rather than writing
// return addresses built from a guess. The rest of the identity layer — the realm, the
// theme, the administrator — needs no domain.
func domaineDeLaPlateforme(ctx context.Context) string {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return ""
	}
	// THE KEYCLOAK INGRESS IS THE DOMAIN'S OWN RECORD: its host is
	// keycloak.<domain>, written by the ingress layer and read back here. Reading the
	// running configuration rather than asking for a flag means no second source of
	// truth, and no --domain to forget on a command that never had one.
	obj, ok, err := cli.LireObjet(ctx,
		schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"},
		"keycloak")
	if err != nil || !ok {
		return ""
	}
	regles, found, err := unstructured.NestedSlice(obj.Object, "spec", "rules")
	if err != nil || !found {
		return ""
	}
	for _, r := range regles {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		hote, _ := m["host"].(string)
		if strings.HasPrefix(hote, "keycloak.") {
			return strings.TrimPrefix(hote, "keycloak.")
		}
	}
	return ""
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
