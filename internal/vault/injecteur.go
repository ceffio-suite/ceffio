package vault

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

//go:embed injecteur/rendu.yaml
var manifesteInjecteur string

// VersionChartInjecteur est la version du chart OpenBao dont ce rendu provient.
//
// LE RENDU EST VERSIONNÉ AVEC LE CODE, pas tiré à l'installation : un installeur
// ne doit dépendre ni de Helm ni du réseau vers un dépôt de charts. Pour mettre à
// jour, on re-rend le chart à cette version, on remplace le fichier, et le diff dit
// exactement ce qui change.
const VersionChartInjecteur = "0.30.3"

// nomWebhookInjecteur est le nom de la configuration de webhook créée par le chart.
// Il sert de témoin de disponibilité — voir poserInjecteur.
const nomWebhookInjecteur = "ceffio-injector-openbao-agent-injector-cfg"

// poserInjecteur installe l'agent-injecteur d'OpenBao, et VÉRIFIE qu'il est prêt à
// injecter avant de rendre la main.
//
// POURQUOI AVANT LES CHARGES ANNOTÉES : les pods migrés portent des annotations que
// seul l'injecteur sait lire. Sa politique d'échec est « Ignore » — un choix sain
// pour le cluster, puisqu'un injecteur tombé ne bloque pas la création des pods —
// mais elle a une conséquence : sans injecteur, les pods démarrent SANS secrets et
// sans aucune erreur d'admission. Un silence complet, exactement le mode de panne
// qu'on cherche à éliminer. Comme ce contrôle est typé et bloque le déploiement, il
// ne peut pas passer pour un succès.
//
// LE TÉMOIN EST LA GRAINE DE CONFIANCE DU WEBHOOK, et pas l'état du pod : c'est
// l'injecteur qui l'écrit, une fois son certificat généré. Un pod « Ready » peut
// très bien l'être avant d'avoir patché son webhook ; un caBundle renseigné, non.
func poserInjecteur(ctx context.Context, cli *k8sapi.Client) error {
	fmt.Println("∙ agent-injecteur OpenBao (chart " + VersionChartInjecteur + ")")
	if err := cli.Appliquer(ctx, manifesteInjecteur); err != nil {
		return fmt.Errorf("pose de l'agent-injecteur : %w", err)
	}

	fin := time.Now().Add(150 * time.Second)
	for time.Now().Before(fin) {
		pret, err := cli.WebhookEstPret(ctx, nomWebhookInjecteur)
		if err == nil && pret {
			fmt.Println("  ✓ injecteur prêt : graine de confiance du webhook publiée")
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("l'agent-injecteur n'a pas publié sa graine de confiance en 150 s — " +
		"les pods annotés démarreraient SANS secrets, sans erreur d'admission")
}
