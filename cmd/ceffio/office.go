package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/office"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newOfficeCmd déploie la couche bureautique SEULE.
//
// MÊME RAISON QUE POUR LA MESSAGERIE ET LA CONSOLE : ONLYOFFICE n'était
// déployable que par `install`, qui rejoue toute la pile. Or c'est précisément le
// composant dont le jeton de signature est partagé avec Nextcloud — donc celui
// qu'on veut pouvoir redéployer seul après une rotation, sans toucher au reste.
func newOfficeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "office",
		Short: "Déployer la couche bureautique (ONLYOFFICE) seule",
		Long: `Déploie le serveur de documents et (re)branche son connecteur dans Nextcloud.

LE JETON DE SIGNATURE EST LU DANS LE COFFRE, avec repli sur le Secret Kubernetes.
Ce même jeton doit alimenter les deux côtés — le serveur et la configuration du
connecteur. Les lire au même endroit est ce qui rend une rotation complète : sinon
la signature cesse de correspondre, et le symptôme est une erreur
d'authentification sur les documents plutôt qu'une rotation à moitié faite.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// On résout l'accès au coffre AVANT tout le reste : sans cela, la
			// commande se rabattrait silencieusement sur les Secrets Kubernetes
			// et ne lirait jamais le coffre — le repli donnerait l'illusion que
			// la bascule a eu lieu.
			if client, err := k8sapi.Nouveau(); err == nil {
				if adresse, jeton, err := vault.Acces(c.Context(), client); err == nil {
					os.Setenv("BAO_ADDR", adresse)
					os.Setenv("BAO_TOKEN", jeton)
					os.Setenv("BAO_MOTEUR", "kv")
					fmt.Printf("  ∙ coffre : %s (les secrets en viennent en priorité)\n", adresse)
				} else {
					fmt.Printf("  ∙ coffre non résolu (%v) — les secrets viendront de Kubernetes\n", err)
				}
			}
			return office.Deploy(c.Context())
		},
	}
	return c
}
