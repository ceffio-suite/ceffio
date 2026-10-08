// Package ingress — correctifs issus du deploiement reel derriere OPNsense.
//
// Ce fichier ajoute ce qui manquait pour qu'un deploiement Ceffio soit
// utilisable derriere un proxy amont qui termine le TLS (le cas normal : le
// pare-feu expose *.domaine, Traefik ne voit que du HTTP).
//
// Sans ces correctifs, les applications generent des redirections en http://
// et vers l'ancien domaine : le service repond, mais la navigation casse.
// Constaté en production : keycloak redirigeait vers http://keycloak.demo.local
// depuis un client en https.
package ingress

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// candidatsAnciensDomaines liste les domaines qu'une installation a pu porter
// avant sa migration. On les retire des configurations au moment d'adopter un
// nouveau domaine : sinon les redirections continuent de pointer vers eux
// (cas vecu : demo.local restait code en dur dans Keycloak, Nextcloud, Element
// et Synapse apres la bascule vers *.ceffio.mandem-it.com).
var candidatsAnciensDomaines = []string{
	"demo.local",
	"ceffio.local",
}

// ProxyAmont configure Traefik pour qu'il croie a l'en-tete X-Forwarded-Proto
// venant du proxy superieur (OPNsense, Caddy, nginx...).
//
// POURQUOI c'est necessaire, et pourquoi ailleurs ca ne marche pas :
// Quand un pare-feu termine le TLS et transmet en HTTP, Traefik annonce aux
// applications « la requete est arrivee en HTTP ». Les applications honorant
// correctement cet en-tete (Keycloak, Nextcloud, ONLYOFFICE) construisent alors
// leurs redirections en http://, et l'utilisateur bascule en clair ou tombe sur
// une URL inexistante. Configurer KC_HOSTNAME_URL en https ne suffit PAS : le
// proto de redirection vient de l'en-tete, pas de cette variable.
//
// La correction se fait donc dans Traefik, seul endroit ou l'information est
// disponible de facon fiable, et non dans chaque application.
//
// SECURITE : forwardedHeaders.insecure fait confiance a l'en-tete entrant. Ce
// n'est acceptable que si Traefik n'est joignable QUE depuis un reseau de
// confiance (ici : le pare-feu, sur le reseau interne). Sur une machine
// exposee directement, il faudrait une liste d'IP de confiance explicite.
func ProxyAmont(ctx context.Context, reseauDeConfiance string) error {
	manifest := fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    additionalArguments:
      - "--entryPoints.web.forwardedHeaders.insecure=true"
      - "--entryPoints.websecure.forwardedHeaders.insecure=true"
`)
	_ = reseauDeConfiance
	if err := apply(ctx, manifest); err != nil {
		return err
	}
	if err := rolloutRestart(ctx, "deploy/traefik"); err != nil {
		return err
	}
	fmt.Println("✓ Traefik configuré pour un proxy amont (X-Forwarded-Proto respecté)")
	return nil
}

// NettoyerAncienDomaine retire un ancien domaine des configurations des
// applications, en le remplacant par le domaine courant.
//
// Cibles : les ConfigMaps et variables d'environnement ou un ancien nom peut
// rester code en dur. On remplace partout ou il apparait, puis on redemarre les
// deployments concernes. Idempotent : si l'ancien domaine n'est plus present,
// rien n'est modifie.
func NettoyerAncienDomaine(ctx context.Context, ancien, nouveau string) error {
	if ancien == "" || nouveau == "" || ancien == nouveau {
		return nil
	}
	fmt.Printf("Nettoyage de l'ancien domaine %s -> %s...\n", ancien, nouveau)

	// 1) ConfigMaps : Element, Synapse (+ tout autre qui contiendrait le nom).
	cibles := []struct{ ns, cm, cle string }{
		{"ceffio-chat", "element-config", "config.json"},
		{"ceffio-chat", "synapse-config", "homeserver.yaml"},
	}
	for _, c := range cibles {
		data, err := cmData(ctx, c.ns, c.cm, c.cle)
		if err != nil || !strings.Contains(data, ancien) {
			continue
		}
		data = strings.ReplaceAll(data, ancien, nouveau)
		if err := applyCMData(ctx, c.ns, c.cm, c.cle, data); err != nil {
			return fmt.Errorf("%s/%s : %w", c.ns, c.cm, err)
		}
		fmt.Printf("  ✓ %s/%s mis à jour\n", c.ns, c.cm)
	}

	// 2) Deployments : variables d'environnement contenant l'ancien nom.
	//    Keycloak est le cas critique — son KC_HOSTNAME pointe le domaine public.
	deps := []struct{ ns, nom string }{
		{"ceffio-identity", "keycloak"},
	}
	for _, d := range deps {
		out, err := k8s.Command(ctx, "kubectl", "get", "deploy", d.nom, "-n", d.ns,
			"-o", "jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}={.value}{\"\\n\"}{end}").Output()
		if err != nil {
			continue
		}
		var args []string
		for _, ligne := range strings.Split(string(out), "\n") {
			ligne = strings.TrimSpace(ligne)
			if ligne == "" || !strings.Contains(ligne, ancien) {
				continue
			}
			cle := strings.SplitN(ligne, "=", 2)[0]
			args = append(args, cle+"="+strings.ReplaceAll(ligne[len(cle)+1:], ancien, nouveau))
		}
		if len(args) == 0 {
			continue
		}
		kargs := append([]string{"set", "env", "-n", d.ns, "deploy/" + d.nom}, args...)
		if out, err := k8s.Command(ctx, "kubectl", kargs...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s/%s : %w : %s", d.ns, d.nom, err, string(out))
		}
		fmt.Printf("  ✓ %s/%s : %s\n", d.ns, d.nom, strings.Join(args, ", "))
	}

	// 3) Nextcloud : occ, plusieurs cles peuvent citer l'ancien nom.
	for _, cmd := range [][]string{
		{"config:system:get", "overwritehost"},
		{"config:system:get", "overwrite.cli.url"},
	} {
		res, err := k8s.Command(ctx, "kubectl", "exec", "-n", "ceffio-files",
			"deploy/nextcloud", "--", "su", "-s", "/bin/sh", "www-data", "-c",
			"php occ "+strings.Join(cmd, " ")).Output()
		if err == nil && strings.Contains(string(res), ancien) {
			fmt.Printf("  · Nextcloud : %s contient encore l'ancien domaine\n", cmd[1])
		}
	}

	// 4) Redemarrer ce qui a ete modifie.
	for _, t := range []string{"deploy/synapse", "deploy/element"} {
		_ = rolloutRestart(ctx, t)
	}
	return nil
}

// DomainesConnus renvoie la liste des anciens domaines a nettoyer pour un
// domaine cible donne (tous ceux qui ne sont pas le domaine courant).
func DomainesConnus(courant string) []string {
	var out []string
	for _, d := range candidatsAnciensDomaines {
		if d != courant {
			out = append(out, d)
		}
	}
	return out
}
