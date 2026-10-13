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

// Valeurs par défaut du relais d'expédition.
//
// POURQUOI CE DÉFAUT, ET PAS UNE DÉCOUVERTE AUTOMATIQUE : le port 25 sortant est
// bloqué chez Free (mesuré), donc Stalwart ne peut pas livrer lui-même vers
// l'extérieur — c'est one.com qui porte le reverse DNS et la délivrabilité. Ce
// n'est pas une supposition, c'est la configuration de cette installation.
const (
	relaisParDefaut     = "send.one.com"
	portRelaisParDefaut = 587
)

// newMailCmd déploie la couche messagerie SEULE.
//
// MÊME RAISON QUE POUR `ceffio vault` ET POUR LA CONSOLE : un composant qu'on ne
// peut pas redéployer seul est un composant qu'on n'ose pas toucher. Stalwart
// n'était atteignable que par `install`, qui rejoue toute la pile — et il est
// ABSENT de la séquence de remise à niveau. Autrement dit : un correctif sur la
// messagerie n'avait aucun chemin pour être appliqué.
//
// LES IDENTIFIANTS DU RELAIS SONT LUS, PAS SAISIS. Ils viennent du coffre, avec
// repli sur le Secret Kubernetes. Les passer en option inviterait à les écrire
// dans l'historique du shell, et il faudrait les corriger à chaque rotation —
// c'est exactement ce qu'on cherche à supprimer.
func newMailCmd() *cobra.Command {
	var domain string
	var hote string
	var port int

	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Déployer la couche messagerie (Stalwart) seule",
		Long: `Déploie le serveur de courrier, sans rejouer toute la pile.

Le domaine des ADRESSES est celui de la plateforme, pas l'hôte web « mail.<domaine> » :
ce sont deux choses distinctes, et les confondre produit des adresses que personne
ne peut recevoir.

Les identifiants du relais d'expédition sont lus dans le coffre, avec repli sur le
Secret Kubernetes. Aucune valeur secrète ne se saisit en option.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			if domain == "" {
				return fmt.Errorf("--domain est requis")
			}
			// ON RÉSOUT L'ACCÈS AU COFFRE AVANT TOUT LE RESTE.
			//
			// Sans cette étape, la commande se rabattrait silencieusement sur les
			// Secrets Kubernetes : le module de secrets lit BAO_ADDR/BAO_TOKEN
			// dans l'environnement, et `install` les pose pour ses propres
			// modules, dans son processus. Une commande lancée seule n'a personne
			// pour le faire — et un repli silencieux donne l'illusion que la
			// bascule a eu lieu.
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
			coffre := secrets.DepuisEnvironnement()
			utilisateur, err := secrets.LireOuSecret(c.Context(), coffre, "smtp", "relais",
				"username", "ceffio-files/nextcloud-smtp", "username")
			if err != nil {
				return fmt.Errorf("utilisateur du relais d'expédition introuvable : %w", err)
			}
			motdepasse, err := secrets.LireOuSecret(c.Context(), coffre, "smtp", "relais",
				"password", "ceffio-files/nextcloud-smtp", "password")
			if err != nil {
				return fmt.Errorf("mot de passe du relais d'expédition introuvable : %w", err)
			}
			return mail.Deploy(c.Context(), domain, hote, port, utilisateur, motdepasse)
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "ceffio.mandem-it.com", "Domaine de base")
	cmd.Flags().StringVar(&hote, "relais", relaisParDefaut, "Hôte du relais d'expédition")
	cmd.Flags().IntVar(&port, "relais-port", portRelaisParDefaut, "Port du relais d'expédition")
	return cmd
}
