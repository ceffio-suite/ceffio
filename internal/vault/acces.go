package vault

import (
	"context"
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// Acces rend l'adresse et le jeton qui permettent d'utiliser le coffre depuis la
// machine d'installation.
//
// POURQUOI CETTE FONCTION EXISTE, ET POURQUOI ELLE EST INDISPENSABLE : le module
// internal/secrets lit BAO_ADDR et BAO_TOKEN dans l'environnement — c'est ce qui
// lui permet de viser n'importe quel coffre sans rien savoir de son installation.
// Mais une commande lancée SEULE n'a personne pour les poser : `install` les pose
// pour ses propres modules, dans son propre processus. Sans cette fonction, une
// commande autonome se rabattrait SILENCIEUSEMENT sur les Secrets Kubernetes et
// ne lirait jamais le coffre. C'est la pire des pannes : tout paraît fonctionner,
// et la source de vérité n'est pas celle qu'on croit.
//
// L'ADRESSE EST CELLE DU NODEPORT, joignable depuis la machine. Le nom de service
// interne ne résout pas depuis là — l'installation ne tourne pas dans le cluster.
func Acces(ctx context.Context, cli *k8sapi.Client) (string, string, error) {
	port, err := cli.NodePortDuService(ctx, ns, service, "api")
	if err != nil {
		return "", "", fmt.Errorf("port externe du coffre illisible : %w", err)
	}
	if port == 0 {
		return "", "", fmt.Errorf("le service du coffre n'expose aucun port : le coffre n'est pas déployé")
	}
	// Le jeton vit dans un Secret Kubernetes, posé par le déploiement du coffre.
	// Le recopier dans un fichier de configuration créerait une copie de plus à
	// faire tourner.
	jeton, err := cli.LireSecret(ctx, ns, "openbao-token", "token")
	if err != nil {
		return "", "", fmt.Errorf("jeton du coffre illisible : %w", err)
	}
	if jeton == "" {
		return "", "", fmt.Errorf("jeton du coffre absent (Secret openbao-token vide)")
	}
	noeud := os.Getenv("CEFFIO_NOEUD")
	if noeud == "" {
		noeud = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d", noeud, port), jeton, nil
}
