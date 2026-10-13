package vault

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// semence décrit une entrée du coffre, et d'où elle vient.
type semence struct {
	composant string   // arborescence : kv/ceffio/<composant>/<nom>
	nom       string   // nom de l'entrée — celui qu'on cherche dans le coffre
	ns        string   // namespace Kubernetes d'origine
	secret    string   // nom du Secret Kubernetes
	cles      []string // clés reprises, regroupées dans une SEULE entrée
}

// semences liste ce qu'on remonte dans le coffre.
//
// UNE ENTRÉE PAR COMPTE OU PAR PAQUET, PAS UNE PAR CLÉ. C'est une correction
// tirée de l'usage : rangé par clé, le compte d'administration de Nextcloud
// n'existait nulle part en tant qu'entrée — on trouvait « un mot de passe » sans
// savoir à quoi il ouvrait, et le chercher ne donnait rien. Un coffre dont on ne
// trouve pas ce qu'on y a mis ne remplit pas son office.
//
// L'ORDRE COMPTE : on commence par les FEUILLES — un composant dont peu de
// choses dépendent. Stalwart d'abord : un compte, un consommateur, aucune
// duplication. Talk et l'expédition SMTP viennent ensuite, et eux en portent —
// mais SEMER n'y touche pas : on recopie, on ne modifie rien.
//
// RIEN N'EST OMIS PAR PRUDENCE, et c'est délibéré. J'avais écarté Nextcloud et
// Keycloak de la première liste au nom du risque — mais « semer » est une COPIE :
// il n'y a rien à casser. Un secret absent du coffre se lit comme un défaut
// d'installation, et c'est exactement ce qui s'est produit. La retenue vaut pour
// la dernière étape — basculer la CONSOMMATION — pas pour celle-ci.
var semences = []semence{
	// Feuilles
	{composant: "stalwart", nom: "admin", ns: "ceffio-mail", secret: "stalwart-admin",
		cles: []string{"username", "password", "storage"}},
	{composant: "onlyoffice", nom: "jwt", ns: "ceffio-office", secret: "onlyoffice-secret",
		cles: []string{"jwt"}},
	{composant: "talk", nom: "signaling", ns: "ceffio-video", secret: "talk-secrets",
		cles: []string{"hash-key", "block-key", "partage", "turn-secret"}},
	{composant: "console", nom: "api", ns: "ceffio-system", secret: "ceffio-console-key",
		cles: []string{"key"}},
	{composant: "smtp", nom: "relais", ns: "ceffio-files", secret: "nextcloud-smtp",
		cles: []string{"username", "password"}},

	// Comptes locaux des services : c'est ce qu'on vient chercher ici en premier.
	{composant: "nextcloud", nom: "admin", ns: "ceffio-files", secret: "nextcloud-admin",
		cles: []string{"username", "password"}},
	{composant: "nextcloud", nom: "db", ns: "ceffio-files", secret: "nextcloud-db",
		cles: []string{"username", "password"}},
	{composant: "console", nom: "nextcloud-api", ns: "ceffio-system", secret: "nextcloud-console-api",
		cles: []string{"username", "password"}},
	{composant: "keycloak", nom: "admin", ns: "ceffio-identity", secret: "keycloak-admin",
		cles: []string{"username", "password"}},
	{composant: "keycloak", nom: "db", ns: "ceffio-identity", secret: "keycloak-db",
		cles: []string{"username", "password"}},
	{composant: "postgres", nom: "app", ns: "ceffio-data", secret: "ceffio-pg-app",
		// Seuls les identifiants : le même Secret contient des chaînes de
		// connexion qui les RECOPIENT. Les semer ferait trois copies d'un même
		// mot de passe, et trois endroits à corriger le jour d'une rotation.
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
//   - ON N'ÉCRASE JAMAIS. Une entrée déjà présente n'est pas remplacée : elle
//     peut être plus récente que la copie Kubernetes, ou en train de servir.
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
	var poses, deja, incompletes int
	for _, s := range semences {
		chemin := "kv/ceffio/" + s.composant + "/" + s.nom

		donnees := map[string]string{}
		manquantes := []string{}
		for _, cle := range s.cles {
			valeur, err := cli.LireSecret(ctx, s.ns, s.secret, cle)
			if err != nil {
				return fmt.Errorf("lecture de %s/%s : %w", s.ns, s.secret, err)
			}
			if valeur == "" {
				manquantes = append(manquantes, cle)
				continue
			}
			donnees[cle] = valeur
		}
		if len(manquantes) > 0 {
			// On le DIT plutôt que de compléter par une valeur inventée : une
			// entrée à moitié fausse a l'air complète, et c'est le pire des cas.
			fmt.Printf("  ∙ %s : %v absente(s) de Kubernetes — non inventée(s)\n", chemin, manquantes)
			incompletes++
		}
		if len(donnees) == 0 {
			continue
		}

		presente, err := entreePresente(ctx, cli, adm, chemin, s.cles[0])
		if err != nil {
			return err
		}
		if presente {
			deja++
			continue
		}
		if err := poserAuCoffre(ctx, cli, adm, chemin, donnees); err != nil {
			return fmt.Errorf("écriture de %s : %w", chemin, err)
		}
		fmt.Printf("  + %s (%d clé(s))\n", chemin, len(donnees))
		poses++
	}
	fmt.Printf("  ∙ semence : %d entrée(s) posée(s), %d déjà présente(s), %d incomplète(s)\n",
		poses, deja, incompletes)
	return nil
}

// entreePresente dit si l'entrée existe déjà au coffre.
//
// ON NE SE CONTENTE PAS D'UN ÉCHEC POUR CONCLURE « ABSENTE ». Une erreur peut
// vouloir dire « pas encore là » — le cas courant au premier passage — ou bien
// un refus d'accès, voire un coffre injoignable. Confondre les deux ferait
// écrire à l'aveugle, ou pire, sauter une entrée à tort en croyant qu'elle
// existe. On tranche en interrogeant une seconde fois, autrement.
//
// ATTENTION AU CHEMIN : les commandes `kv` prennent le chemin LOGIQUE
// (« kv/ceffio », sous-entendu la clé). Elles ajoutent elles-mêmes le segment
// « metadata/ » quand il faut. Passer « kv/metadata/ceffio » produit donc
// « kv/metadata/metadata/ceffio », et l'erreur qui en résulte — « No value
// found » — se lit à tort comme un coffre en panne. Constaté en service.
func entreePresente(ctx context.Context, cli *k8sapi.Client, jeton, chemin, cleTemoin string) (bool, error) {
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", "-field="+cleTemoin, chemin); err == nil {
		return true, nil
	}
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "list", "kv/ceffio"); err != nil {
		return false, fmt.Errorf("le coffre ne répond pas correctement (entrée %s) : %w", chemin, err)
	}
	return false, nil
}

// poserAuCoffre écrit une entrée, en passant par un fichier de charge.
//
// POURQUOI PAS EN ARGUMENT : les valeurs SONT les secrets. Sur une ligne de
// commande, elles seraient lisibles dans la liste des processus du conteneur —
// et le coffre existe précisément pour éviter ce genre de trace.
func poserAuCoffre(ctx context.Context, cli *k8sapi.Client, jeton, chemin string, donnees map[string]string) error {
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/semence.json", donnees); err != nil {
		return err
	}
	_, err := baoAvecJeton(ctx, cli, jeton, "kv", "put", chemin, "@/tmp/semence.json")
	// La charge a porté les valeurs : elle disparaît dès qu'elle a servi, quel
	// que soit le résultat.
	retirerPayloadCoffre(ctx, cli, "/tmp/semence.json")
	return err
}
