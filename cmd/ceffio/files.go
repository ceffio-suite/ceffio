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

// newFilesCmd déploie la couche fichiers (Nextcloud) SEULE.
func newFilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "files",
		Short: "Déployer la couche fichiers (Nextcloud) seule",
		Long: `Déploie Nextcloud et son stockage.

SES IDENTIFIANTS VIENNENT DU COFFRE, ET DE NULLE PART AILLEURS : ceux de la base, et
ceux du compte d'administration. Le pod ne fait que lire un fichier que l'injecteur
compose à partir de plusieurs entrées — la base et l'administration sont deux comptes
distincts, et le conteneur n'a pas à connaître cette répartition.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			resoudreCoffre(c)
			return files.Deploy(c.Context())
		},
	}
}

// newIdentityCmd déploie la couche identité (Keycloak) SEULE.
func newIdentityCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "identity",
		Short: "Déployer la couche identité (Keycloak) seule",
		Long: `Déploie Keycloak, qui porte l'authentification de toute la suite.

Mêmes règles que pour les fichiers : les identifiants de base et le compte
d'administration viennent du coffre, et le pod les lit par l'injecteur.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			resoudreCoffre(c)
			return identity.Deploy(c.Context())
		},
	}
}

// resoudreCoffre place l'accès au coffre dans l'environnement, avant toute lecture.
//
// Sans cette résolution, les modules échoueraient à lire comme à écrire, et le
// message d'erreur parlerait de coffre injoignable sans dire pourquoi.
func resoudreCoffre(c *cobra.Command) {
	client, err := k8sapi.Nouveau()
	if err != nil {
		fmt.Printf("  ∙ client Kubernetes indisponible (%v)\n", err)
		return
	}
	adresse, jeton, err := vault.Acces(c.Context(), client)
	if err != nil {
		fmt.Printf("  ∙ coffre non résolu (%v) — la commande va échouer : c'est voulu\n", err)
		return
	}
	os.Setenv("BAO_ADDR", adresse)
	os.Setenv("BAO_TOKEN", jeton)
	os.Setenv("BAO_MOTEUR", "kv")
	fmt.Printf("  ∙ coffre : %s (source unique des secrets)\n", adresse)
}
