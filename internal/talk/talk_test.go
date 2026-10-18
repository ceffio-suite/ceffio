// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package talk

import (
	"encoding/json"
	"strings"
	"testing"
)

// THE RECORDING OF THIS KEY IS A FIX, NOT A PREFERENCE.
//
// Talk reads $server['server'] and not $server['url']:
//
//	getAllServerUrlsForCSP() {
//	    foreach ($this->getSignalingServers() as $server) {
//	        $urls[] = $this->getWebSocketDomainForSignalingServer($server['server']);
//	    }
//	}
//
// and getWebSocketDomainForSignalingServer() takes a NON NULLABLE string. A key
// named "url" therefore leaves the field null and Talk raises a TypeError on
// EVERY page load — it is the whole dashboard that goes down, not only Talk.
//
// This test would fail if someone "fixed" the key towards the name that seems
// natural.
func TestSignalingServersUtiliseLaCleServer(t *testing.T) {
	reglage := reglageSignaling("https://spreed.example.test/standalone-signaling", "secret-de-test")

	if !strings.Contains(reglage, `"server":`) {
		t.Errorf("la cle doit etre \"server\" (Talk lit $server['server']) ; recu : %s", reglage)
	}
	if strings.Contains(reglage, `"url":`) {
		t.Errorf("la cle \"url\" fait planter Talk (TypeError : null donne a un parametre string) ; recu : %s", reglage)
	}
}

// THE PRESENCE OF A PATH PREFIX IS A TRAP, not a style detail.
//
// The signaling server listens on 0.0.0.0:8081 and serves its WebSocket entry
// point directly on /spreed ([http] of server.conf, no prefix). A URL announced
// with a prefix therefore makes Talk compose a path the server does not serve:
//
//	https://spreed.<domain>                        -> /spreed                     OK
//	https://spreed.<domain>/standalone-signaling   -> /standalone-signaling/spreed 404
//
// "/standalone-signaling" is the path of Nextcloud AIO, where a reverse proxy
// REMOVES the prefix before forwarding. Copying it without that rule yields a
// client that hits a nonexistent path: Talk displays "connection to the
// signaling server lost", and neither log names the path.
//
// This test would fail if someone added a prefix, taking inspiration from AIO.
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

	// getSignalingServers() returns [] if the "servers" key is absent.
	servers, ok := d["servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("la cle \"servers\" est absente ou vide: getSignalingServers() renverrait []")
	}

	// getSignalingSecret() reads "secret" at the root of the object.
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
