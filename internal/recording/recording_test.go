// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package recording

import (
	"encoding/json"
	"strings"
	"testing"
)

// The manifest is a multi-YAML document. Like the other tests in the project,
// we verify it by textual inspection rather than adding a parser: a test
// dependency for two documents is not worth the cost, and what matters here is
// not the general shape of the YAML but precise points that actually broke in
// development.
func TestManifesteRecorderContientLesObjetsAttendus(t *testing.T) {
	doc := manifesteRecorder("ceffio.mandem-it.com", "    vault.hashicorp.com/role: recording")

	for _, attendu := range []string{"kind: Deployment", "kind: Service", "---"} {
		if !strings.Contains(doc, attendu) {
			t.Errorf("manifeste sans %q", attendu)
		}
	}
}

// THE TRAP THAT COST A CRASHLOOP: the image reads RECORDING_SECRET from its
// ENVIRONMENT, while the injector writes /secrets/env. The container must
// therefore source that file, and pass start.sh the image's arguments.
// Without this block the pod starts then exits immediately on
// "You need to provide the RECORDING_SECRET." — a silent failure from the
// application's point of view, which only sees an empty variable.
func TestConteneurSourceLesSecretsEtPasseLesArguments(t *testing.T) {
	doc := manifesteRecorder("ceffio.mandem-it.com", "    vault.hashicorp.com/role: recording")

	// start.sh ends with an exec on ITS arguments: calling it without
	// arguments starts nothing.
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

// The signaling secret is written into the recorder's entry by the code, not
// referenced directly: the recorder must hold no right on talk/*.
// This test verifies that the manifest reads ONLY its own vault path.
func TestLeRecorderNeLitQueSaPropreEntree(t *testing.T) {
	ann := annotationsRecorder()
	if strings.Contains(ann, "ceffio/talk/") {
		t.Error("le recorder reference talk/* : il ne doit lire que recording/*, la valeur partagee y est recopiee au deploiement")
	}
	if !strings.Contains(ann, "ceffio/recording/server") {
		t.Error("le recorder ne reference pas sa propre entree dans le coffre")
	}
}

// THE SHAPE OF THIS SETTING IS WHAT MAKES THE FEATURE WORK, and it is not the
// obvious shape.
//
// Talk reads an OBJECT with two keys:
//
//	{"servers":[{"server":"URL"}],"secret":"SECRET"}
//
// read by Config::getRecordingServers() -> $recording['servers']
//
//	and Config::getRecordingSecret()  -> $recording['secret']
//
// Both go through getAppValueArray(), which json_decodes the stored string.
//
// This test catches the mistake actually made: an ARRAY
// [{"url":...,"secret":...}], which looks natural and does not work — the root
// being a list, neither key exists at the top level, both getters return their
// default ([] and ""), and isRecordingEnabled() returns false. Talk then greys
// out "record this call" with "the recording server is not installed", while
// the recorder is running.
func TestReglageRecordingServersEstUnObjetAvecServerEtSecret(t *testing.T) {
	reglage := reglageRecording("http://talk-recording.ceffio-video.svc:1234", "secret-de-test")

	var d map[string]any
	if err := json.Unmarshal([]byte(reglage), &d); err != nil {
		t.Fatalf("le reglage doit etre un OBJET JSON (Talk le passe a getAppValueArray) ; recu %s", reglage)
	}

	// getRecordingServers() returns $recording['servers'] ?? []
	servers, ok := d["servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatalf("cle \"servers\" absente ou vide : getRecordingServers() renverrait [] ; recu %s", reglage)
	}
	// getRecordingSecret() returns $recording['secret'] ?? ''
	if d["secret"] != "secret-de-test" {
		t.Errorf("secret = %v, attendu \"secret-de-test\"", d["secret"])
	}

	// The entry field is "server", not "url".
	premier, _ := servers[0].(map[string]any)
	if _, ok := premier["server"]; !ok {
		t.Errorf("l'entree doit porter la cle \"server\" ; recu %v", premier)
	}
	if _, ok := premier["url"]; ok {
		t.Errorf("l'entree porte \"url\" : Talk lit $server['server'] ; recu %v", premier)
	}
}
