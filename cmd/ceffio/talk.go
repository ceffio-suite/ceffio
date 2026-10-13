package main

import (
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/talk"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newTalkCmd déploie la pile Talk (HPB) SEULE.
//
// MÊME RAISON QUE POUR LA MESSAGERIE, LA BUREAUTIQUE ET LA CONSOLE : Talk n'était
// déployable que par `install`, qui rejoue toute la pile. Or c'est le composant
// dont DEUX secrets sont partagés avec Nextcloud — donc celui qu'on veut pouvoir
// redéployer seul après une rotation, sans toucher au reste.
func newTalkCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "talk",
		Short: "Déployer la pile Talk (coturn, Janus, NATS, signaling) seule",
		Long: `Déploie le serveur de signalisation haute performance et son raccordement à Nextcloud.

LES SECRETS VIENNENT DU COFFRE, ET DE NULLE PART AILLEURS. Les deux charges qui les
consomment — coturn et le signaling — les lisent à leur démarrage par un agent, et
le raccordement Nextcloud lit la MÊME entrée. C'est ce qui garantit que le secret
partagé du signaling et celui des serveurs TURN restent identiques des deux côtés :
une rotation n'en touche jamais un sans l'autre.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// On résout l'accès au coffre AVANT tout le reste : sans cela, la
			// commande ne pourrait ni lire ni écrire les secrets, et le
			// raccordement Nextcloud échouerait sans dire pourquoi.
			if client, err := k8sapi.Nouveau(); err == nil {
				if adresse, jeton, err := vault.Acces(c.Context(), client); err == nil {
					os.Setenv("BAO_ADDR", adresse)
					os.Setenv("BAO_TOKEN", jeton)
					os.Setenv("BAO_MOTEUR", "kv")
					fmt.Printf("  ∙ coffre : %s (source unique des secrets)\n", adresse)
				} else {
					fmt.Printf("  ∙ coffre non résolu (%v) — le déploiement va échouer : c'est voulu\n", err)
				}
			}
			return talk.Deploy(c.Context())
		},
	}
	return c
}
