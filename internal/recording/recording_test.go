// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package recording

import (
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
