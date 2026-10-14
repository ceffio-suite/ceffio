// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package talk

import (
	"encoding/json"
	"strings"
	"testing"
)

// L'ENREGISTREMENT DE CETTE CLE EST UN CORRECTIF, PAS UNE PREFERENCE.
//
// Talk lit $server['server'] et non $server['url'] :
//
//	getAllServerUrlsForCSP() {
//	    foreach ($this->getSignalingServers() as $server) {
//	        $urls[] = $this->getWebSocketDomainForSignalingServer($server['server']);
//	    }
//	}
//
// et getWebSocketDomainForSignalingServer() prend un string NON NULLABLE. Une
// cle nommee "url" laisse donc le champ null et Talk leve une TypeError a
// CHAQUE chargement de page — c'est le dashboard entier qui tombe, pas
// seulement Talk.
//
// Ce test echouerait si quelqu'un « corrigeait » la cle vers le nom qui semble
// naturel.
func TestSignalingServersUtiliseLaCleServer(t *testing.T) {
	reglage := reglageSignaling("https://spreed.example.test/standalone-signaling", "secret-de-test")

	if !strings.Contains(reglage, `"server":`) {
		t.Errorf("la cle doit etre \"server\" (Talk lit $server['server']) ; recu : %s", reglage)
	}
	if strings.Contains(reglage, `"url":`) {
		t.Errorf("la cle \"url\" fait planter Talk (TypeError : null donne a un parametre string) ; recu : %s", reglage)
	}
}

// LA PRESENCE D'UN PREFIXE DE CHEMIN EST UN PIEGE, pas un detail de style.
//
// Le signaling ecoute sur 0.0.0.0:8081 et sert son point d'entree WebSocket
// directement sur /spreed ([http] de server.conf, aucun prefixe). Une URL
// annoncee avec un prefixe fait donc composer a Talk un chemin que le serveur
// ne sert pas :
//
//	https://spreed.<domaine>                        -> /spreed                     OK
//	https://spreed.<domaine>/standalone-signaling   -> /standalone-signaling/spreed 404
//
// "/standalone-signaling" est le chemin de Nextcloud AIO, ou un reverse proxy
// RETIRE le prefixe avant de transmettre. Le recopier sans cette regle donne un
// client qui frappe un chemin inexistant : Talk affiche « connexion au serveur
// de signalement perdue », et ni l'un ni l'autre journal ne nomme le chemin.
//
// Ce test echouerait si quelqu'un rajoutait un prefixe en s'inspirant d'AIO.
func TestSignalingSansPrefixeDeChemin(t *testing.T) {
	url := urlSignaling("ceffio.mandem-it.com")

	if url != "https://spreed.ceffio.mandem-it.com" {
		t.Errorf("URL = %q, attendu https://spreed.ceffio.mandem-it.com (sans prefixe de chemin)", url)
	}
	if strings.Contains(url, "standalone-signaling") {
		t.Error("l'URL contient /standalone-signaling : le signaling de Ceffio n'expose pas ce chemin (il sert /spreed a la racine)")
	}
}
func TestSignalingServersEstUnJsonValide(t *testing.T) {
	reglage := reglageSignaling("https://spreed.example.test/standalone-signaling", "secret-de-test")

	var d map[string]any
	if err := json.Unmarshal([]byte(reglage), &d); err != nil {
		t.Fatalf("le reglage n'est pas un JSON valide: %v", err)
	}

	// getSignalingServers() renvoie [] si la cle "servers" est absente.
	servers, ok := d["servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("la cle \"servers\" est absente ou vide: getSignalingServers() renverrait []")
	}

	// getSignalingSecret() lit "secret" a la racine de l'objet.
	if d["secret"] != "secret-de-test" {
		t.Errorf("secret = %v, attendu \"secret-de-test\"", d["secret"])
	}

	premier, _ := servers[0].(map[string]any)
	if premier["server"] != "https://spreed.example.test/standalone-signaling" {
		t.Errorf("l'URL n'est pas au bon endroit: %v", premier)
	}
	if premier["verify"] != true {
		t.Errorf("verify = %v, attendu true : la verification du certificat ne doit pas etre desactivee", premier["verify"])
	}
}
