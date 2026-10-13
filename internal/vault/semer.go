package vault

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// semence décrit un secret qui vit aujourd'hui dans Kubernetes et doit se
// retrouver dans le coffre.
type semence struct {
	composant string   // arborescence du coffre : kv/ceffio/<composant>/<clé>
	ns        string   // namespace Kubernetes d'origine
	secret    string   // nom du Secret Kubernetes
	cles      []string // clés à reprendre
}

// semences liste ce qu'on remonte dans le coffre.
//
// L'ORDRE N'EST PAS INDIFFÉRENT : on commence par les FEUILLES — un composant
// dont peu de choses dépendent. Stalwart le premier : une seule valeur, un seul
// consommateur, aucune duplication. Talk et l'expédition SMTP viennent ensuite,
// et eux en portent — mais SEMER n'y touche pas : on se contente de recopier.
// Le jour où l'on basculera leur consommation, ces duplications devront être
// préservées, pas supprimées (voir l'inventaire, §3).
//
// Keycloak et Nextcloud ne sont PAS dans cette première liste. Ce sont les
// composants dont tout dépend : les migrer en premier, c'est prendre le risque
// maximal pour le bénéfice le plus faible, puisque rien ne les attend.
var semences = []semence{
	{composant: "stalwart", ns: "ceffio-mail", secret: "stalwart-admin",
		cles: []string{"username", "password", "storage"}},
	{composant: "onlyoffice", ns: "ceffio-office", secret: "onlyoffice-secret",
		cles: []string{"jwt"}},
	{composant: "talk", ns: "ceffio-video", secret: "talk-secrets",
		cles: []string{"hash-key", "block-key", "partage", "turn-secret"}},
	{composant: "console", ns: "ceffio-system", secret: "ceffio-console-key",
		cles: []string{"key"}},
	{composant: "smtp", ns: "ceffio-files", secret: "nextcloud-smtp",
		cles: []string{"username", "password"}},
}

// Semer remonte dans le coffre les secrets qui vivent DÉJÀ dans Kubernetes.
//
// ON LIT D'ABORD, SERVICE EN MARCHE, SANS RIEN BASCULER. À ce stade, aucun
// composant ne lit dans le coffre : on constitue la copie de référence, et on
// vérifie qu'elle se relit. Basculer la consommation est un autre travail, et il
// se fera un composant à la fois.
//
// DEUX RÈGLES, ET ELLES SONT TOUT LE SUJET :
//
//   - ON N'ÉCRASE JAMAIS. Un secret déjà présent au coffre n'est pas remplacé :
//     il peut être plus récent que la copie Kubernetes, ou en train de servir.
//     Écraser à chaque passage ferait de tout redéploiement une rotation
//     silencieuse — exactement ce qu'on cherche à éviter.
//   - ON NE RÉGÉNÈRE RIEN. Si la valeur n'existe nulle part, on ne l'invente
//     pas, on le DIT. Un secret inventé ne correspondrait à rien de vivant, et
//     casserait le service au moment précis où on le lui donnerait.
//
// Le résultat est idempotent : relancer ne change rien, et le compte rendu le
// montre au lieu de le laisser supposer.
func Semer(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	var poses, deja, absents int
	for _, s := range semences {
		for _, cle := range s.cles {
			valeur, err := cli.LireSecret(ctx, s.ns, s.secret, cle)
			if err != nil {
				return fmt.Errorf("lecture de %s/%s : %w", s.ns, s.secret, err)
			}
			if valeur == "" {
				fmt.Printf("  ∙ %s/%s : absent de Kubernetes — rien à semer (on n'invente pas)\n", s.composant, cle)
				absents++
				continue
			}
			chemin := "kv/ceffio/" + s.composant + "/" + cle
			if _, err := baoAvecJeton(ctx, cli, adm, "kv", "get", "-field="+cle, chemin); err == nil {
				deja++
				continue
			}
			if err := poserAuCoffre(ctx, cli, adm, chemin, cle, valeur); err != nil {
				return fmt.Errorf("écriture de %s : %w", chemin, err)
			}
			fmt.Printf("  + %s\n", chemin)
			poses++
		}
	}
	fmt.Printf("  ∙ semence : %d posé(s), %d déjà présent(s), %d absent(s)\n", poses, deja, absents)
	return nil
}

// poserAuCoffre écrit une valeur, en passant par un fichier de charge.
//
// POURQUOI PAS EN ARGUMENT : la valeur EST le secret. Sur une ligne de commande,
// elle serait lisible dans la liste des processus du conteneur — et le coffre
// existe précisément pour éviter ce genre de trace. C'est la même raison qui
// vaut pour le jeton d'administration, et la même solution.
func poserAuCoffre(ctx context.Context, cli *k8sapi.Client, jeton, chemin, cle, valeur string) error {
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/semence.json", map[string]string{cle: valeur}); err != nil {
		return err
	}
	_, err := baoAvecJeton(ctx, cli, jeton, "kv", "put", chemin, "@/tmp/semence.json")
	// La charge a porté la valeur : elle disparaît dès qu'elle a servi, quel que
	// soit le résultat.
	retirerPayloadCoffre(ctx, cli, "/tmp/semence.json")
	return err
}
