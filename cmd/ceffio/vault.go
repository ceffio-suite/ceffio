package main

import (
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/spf13/cobra"
)

// newVaultCmd déploie le coffre de secrets SEUL.
//
// POURQUOI UNE COMMANDE SÉPARÉE, ET PAS SEULEMENT LE BLOC DE `install` : deux
// raisons, toutes deux tirées de la réalité.
//
// D'abord, la chirurgie. `install` rejoue toute la pile. Sur une plateforme en
// service, c'est disproportionné quand on ne veut que le coffre — et `install`
// porte encore un défaut connu sur un cluster existant (il tente de recréer
// `ceffio-dev` et échoue sur `update.k3s.io`). Déployer le coffre ne doit pas
// dépendre de la remise en état du reste.
//
// Ensuite, l'exploitation courante : un coffre qu'on ne peut pas redéployer seul
// est un coffre qu'on n'ose pas toucher. Après une mise à niveau d'OpenBao, un
// changement de configuration ou une rotation de la clé de descellement, c'est
// cette commande qu'on veut avoir sous la main.
//
// ELLE EST IDEMPOTENTE, comme le reste : la relancer ne détruit rien, ne
// régénère aucune clé, et ne réinitialise pas un coffre déjà initialisé. La
// réinitialiser rendrait les secrets existants illisibles.
func newVaultCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "vault",
		Short: "Déployer le coffre de secrets (OpenBao)",
		Long: `Déploie le coffre de secrets OpenBao de la suite, et le prépare à l'emploi.

Le déploiement est idempotent et se fait dans cet ordre :

  1. le namespace et la clé de descellement (32 octets, le « secret-zéro ») ;
  2. la configuration : stockage raft, sceau statique, journal d'audit déclaré ;
  3. le StatefulSet, son volume et son service ;
  4. l'initialisation, seulement si le coffre ne l'est pas déjà ;
  5. le moteur KV versionné, au chemin « kv » ;
  6. une politique d'administration, un jeton dérivé, et la RÉVOCATION du jeton
     racine — un jeton maître qui survit à la mise en place est un défaut ;
  7. une vérification de bout en bout : écrire, relire, et prouver que le coffre
     REFUSE un chemin hors du périmètre de la politique.

Ce que cette commande ne fait PAS, et qu'il faut savoir : elle ne bascule aucun
secret existant vers le coffre. Les Secrets Kubernetes restent en place, et les
composants continuent de les lire. C'est un déploiement, pas une migration.

La clé de descellement vit dans un Secret Kubernetes, sur la même machine que le
coffre : qui obtient la machine obtient le coffre. C'est le compromis du
descellement automatique, assumé et écrit ici plutôt que découvert plus tard.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			res := vault.Deploy(cmd.Context())

			fmt.Println()
			if !res.Pret {
				// Sortie en erreur, mais sans drame : c'est un constat, pas un
				// échec du déploiement de la suite. Les secrets restent dans
				// Kubernetes et tout continue de fonctionner.
				return fmt.Errorf("le coffre n'est pas en service — les secrets restent dans Kubernetes")
			}

			fmt.Println("✓ Coffre de secrets en service")
			fmt.Printf("  adresse : %s\n", res.Adresse)
			fmt.Println("  jeton   : rangé dans le Secret openbao-token (non affiché)")
			fmt.Println()
			fmt.Println("Pour que les composants s'en servent, exporter :")
			fmt.Printf("  BAO_ADDR=%s\n", res.Adresse)
			fmt.Println("  BAO_TOKEN=<lu depuis le Secret openbao-token>")
			return nil
		},
	}
	return c
}
