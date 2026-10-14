// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package recording

import (
	"encoding/json"
	"strings"
	"testing"
)

// Le manifeste est un document multi-YAML. Comme les autres tests du projet,
// on le verifie par inspection textuelle plutot qu'en ajoutant un parseur :
// une dependance de test pour deux documents n'en vaut pas le cout, et ce qui
// compte ici n'est pas la forme generale du YAML mais des points precis qui ont
// reellement casse en developpement.
func TestManifesteRecorderContientLesObjetsAttendus(t *testing.T) {
	doc := manifesteRecorder("ceffio.mandem-it.com", "    vault.hashicorp.com/role: recording")

	for _, attendu := range []string{"kind: Deployment", "kind: Service", "---"} {
		if !strings.Contains(doc, attendu) {
			t.Errorf("manifeste sans %q", attendu)
		}
	}
}

// LE PIEGE QUI A COUTE UN CRASHLOOP: l'image lit RECORDING_SECRET dans son
// ENVIRONNEMENT, alors que l'injecteur ecrit /secrets/env. Le conteneur doit
// donc sourcer ce fichier, et passer a start.sh les arguments de l'image.
// Sans ce bloc le pod demarre puis sort aussitot sur
// "You need to provide the RECORDING_SECRET." — panne silencieuse du point de
// vue de l'application, qui ne voit qu'une variable vide.
func TestConteneurSourceLesSecretsEtPasseLesArguments(t *testing.T) {
	doc := manifesteRecorder("ceffio.mandem-it.com", "    vault.hashicorp.com/role: recording")

	// start.sh se termine par un exec sur SES arguments : l'appeler sans
	// argument ne demarre rien.
	cas := []struct {
		contient, quoi string
	}{
		{". /secrets/env", "les secrets de l'injecteur ne seront pas vus"},
		{"set -a", "source sans export ne transmet rien au processus"},
		{"nextcloud.talk.recording", "start.sh sans les arguments de l'image ne demarre rien"},
		{"/dev/shm", "sans /dev/shm dimensionne, Firefox crashe de facon opaque"},
		{"medium: Memory", "/dev/shm doit etre monte en memoire"},
	}
	for _, c := range cas {
		if !strings.Contains(doc, c.contient) {
			t.Errorf("manifeste sans %q : %s", c.contient, c.quoi)
		}
	}
}

// Le secret du signaling est ecrit dans l'entree du recorder par le code, pas
// reference directement : le recorder ne doit detenir aucun droit sur talk/*.
// Ce test verifie que le manifeste ne lit QUE son propre chemin dans le coffre.
func TestLeRecorderNeLitQueSaPropreEntree(t *testing.T) {
	ann := annotationsRecorder()
	if strings.Contains(ann, "ceffio/talk/") {
		t.Error("le recorder reference talk/* : il ne doit lire que recording/*, la valeur partagee y est recopiee au deploiement")
	}
	if !strings.Contains(ann, "ceffio/recording/server") {
		t.Error("le recorder ne reference pas sa propre entree dans le coffre")
	}
}

// LA FORME DE CE REGLAGE EST CE QUI FAIT FONCTIONNER LA FONCTIONNALITE, et ce
// n'est pas la forme evidente.
//
// Talk lit un OBJET a deux cles :
//
//	{"servers":[{"server":"URL"}],"secret":"SECRET"}
//
// lu par Config::getRecordingServers() -> $recording['servers']
//
//	et Config::getRecordingSecret()  -> $recording['secret']
//
// Les deux passent par getAppValueArray(), qui json_decode la chaine stockee.
//
// Ce test attrape l'erreur reellement commise : un TABLEAU
// [{"url":...,"secret":...}], qui semble naturel et ne marche pas — la racine
// etant une liste, aucune des deux cles n'existe au premier niveau, les deux
// getters renvoient leur defaut ([] et ""), et isRecordingEnabled() renvoie
// false. Talk grise alors « enregistrer cet appel » avec « le serveur
// d'enregistrement n'est pas installe », alors que le recorder tourne.
func TestReglageRecordingServersEstUnObjetAvecServerEtSecret(t *testing.T) {
	reglage := reglageRecording("http://talk-recording.ceffio-video.svc:1234", "secret-de-test")

	var d map[string]any
	if err := json.Unmarshal([]byte(reglage), &d); err != nil {
		t.Fatalf("le reglage doit etre un OBJET JSON (Talk le passe a getAppValueArray) ; recu %s", reglage)
	}

	// getRecordingServers() renvoie $recording['servers'] ?? []
	servers, ok := d["servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("cle \"servers\" absente ou vide : getRecordingServers() renverrait [] ; recu %s", reglage)
	}
	// getRecordingSecret() renvoie $recording['secret'] ?? ''
	if d["secret"] != "secret-de-test" {
		t.Errorf("secret = %v, attendu \"secret-de-test\"", d["secret"])
	}

	// Le champ de l'entree est "server", pas "url".
	premier, _ := servers[0].(map[string]any)
	if _, ok := premier["server"]; !ok {
		t.Errorf("l'entree doit porter la cle \"server\" ; recu %v", premier)
	}
	if _, ok := premier["url"]; ok {
		t.Errorf("l'entree porte \"url\" : Talk lit $server['server'] ; recu %v", premier)
	}
}
