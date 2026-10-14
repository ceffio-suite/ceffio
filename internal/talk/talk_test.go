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

// Le reglage doit etre un JSON valide : Talk le passe a json_decode, et un
// document malforme serait ignore en silence — la configuration semblerait
// posee alors qu'elle ne serait pas lue.
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
