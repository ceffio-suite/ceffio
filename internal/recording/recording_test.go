// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package recording

import (
	"encoding/json"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
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
	ann, err := annotationsRecorder()
	if err != nil {
		t.Fatalf("annotations refusées : %v", err)
	}
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

// Le pod du recorder porte DEUX conteneurs depuis B2 : l'enregistreur, et le
// relais placé devant lui. Ce test vérifie ce qui, s'il manquait, rendrait le
// montage silencieusement inutile — l'image, les arguments, les limites, les
// sondes — et surtout que le port que Talk connaît n'a pas bougé.
func TestLeRelaisEstDansLePodDuRecorder(t *testing.T) {
	ann, err := annotationsRecorder()
	if err != nil {
		t.Fatalf("annotations refusées : %v", err)
	}
	brut := manifesteRecorder("exemple.org", ann)

	var depl, svc map[string]any
	for _, doc := range strings.Split(brut, "\n---\n") {
		var o map[string]any
		if err := yaml.Unmarshal([]byte(doc), &o); err != nil {
			t.Fatalf("YAML illisible : %v", err)
		}
		switch o["kind"] {
		case "Deployment":
			depl = o
		case "Service":
			svc = o
		}
	}
	if depl == nil || svc == nil {
		t.Fatal("Deployment et Service doivent être présents")
	}

	pod := depl["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	conteneurs := map[string]map[string]any{}
	for _, c := range pod["containers"].([]any) {
		m := c.(map[string]any)
		conteneurs[m["name"].(string)] = m
	}
	for _, nom := range []string{"recording", "relay"} {
		if _, ok := conteneurs[nom]; !ok {
			t.Fatalf("conteneur %q absent : le pod doit porter les deux", nom)
		}
	}

	relais := conteneurs["relay"]

	// THE IMAGE IS THE ONE THE INSTALLATION ALREADY HAS: a new image would have
	// to be published, pinned and imported offline for a few hundred bytes of
	// forwarding.
	if got := relais["image"]; got != imageRelais() {
		t.Errorf("image du relais = %v, attendu %v (l'image du binaire, déjà présente)", got, imageRelais())
	}
	if !strings.HasPrefix(imageRelais(), "ghcr.io/ceffio-suite/ceffio:") {
		t.Errorf("imageRelais() = %q : ce n'est pas l'image du binaire", imageRelais())
	}

	var args []string
	for _, a := range relais["args"].([]any) {
		args = append(args, a.(string))
	}
	joints := strings.Join(args, " ")
	for _, attendu := range []string{
		"recording-relay",
		"--listen=:1235",
		"--upstream=http://127.0.0.1:1234",
		"--notify=http://ceffio-capture.ceffio-video.svc:8080/v1/recording",
		"--secret-file=/secrets/relay-secret",
	} {
		if !strings.Contains(joints, attendu) {
			t.Errorf("arguments du relais = %q, %q manquant", joints, attendu)
		}
	}

	// THE LISTENING PORT AND THE DECLARED ONE MUST AGREE: a mismatch makes the
	// Service point at a port nothing listens on, and Talk's recordings stop
	// with no message that names the port.
	ports := relais["ports"].([]any)
	p := ports[0].(map[string]any)
	if p["name"] != "relay" || p["containerPort"].(float64) != 1235 {
		t.Errorf("port du relais = %v", p)
	}
	if !strings.Contains(joints, "--listen=:1235") {
		t.Error("--listen et containerPort ne disent pas le même port")
	}

	sc := relais["securityContext"].(map[string]any)
	if nr, _ := sc["runAsNonRoot"].(bool); !nr {
		t.Error("le relais n'est pas non-root")
	}
	if ro, _ := sc["readOnlyRootFilesystem"].(bool); !ro {
		t.Error("le relais n'a pas de système de fichiers en lecture seule")
	}

	// THE LIMITS ARE THE POINT: a relay that needs 500 MiB is not a relay.
	res := relais["resources"].(map[string]any)
	if got := res["requests"].(map[string]any)["memory"]; got != "32Mi" {
		t.Errorf("requests.memory = %v, attendu 32Mi", got)
	}
	if got := res["limits"].(map[string]any)["memory"]; got != "64Mi" {
		t.Errorf("limits.memory = %v, attendu 64Mi", got)
	}

	for _, sonde := range []string{"readinessProbe", "livenessProbe"} {
		s, _ := relais[sonde].(map[string]any)
		g, _ := s["httpGet"].(map[string]any)
		if g == nil || g["path"] != "/healthz" || g["port"] != "relay" {
			t.Errorf("%s = %v, attendu /healthz sur le port relay", sonde, s)
		}
	}

	// THE RECORDER KEEPS ITS OWN PORT, reachable inside the pod only.
	rec := conteneurs["recording"]["ports"].([]any)[0].(map[string]any)
	if rec["containerPort"].(float64) != 1234 {
		t.Errorf("port de l'enregistreur = %v, attendu 1234", rec["containerPort"])
	}

	// THE SERVICE: the port Talk knows does not move; only its target does.
	sp := svc["spec"].(map[string]any)["ports"].([]any)[0].(map[string]any)
	if sp["port"].(float64) != 1234 {
		t.Errorf("service.port = %v, attendu 1234 : reconfigurer Talk ferait partie du lot", sp["port"])
	}
	if sp["targetPort"] != "relay" {
		t.Errorf("service.targetPort = %v, attendu le port nommé « relay »", sp["targetPort"])
	}
}

// Les deux fichiers du coffre, avec le mode qui va bien : l'env lisible par
// l'enregistreur (root), le secret brut en 0400 pour le relais (65532).
func TestLesFichiersInjectesDuRecorder(t *testing.T) {
	ann, err := annotationsRecorder()
	if err != nil {
		t.Fatalf("annotations refusées : %v", err)
	}
	for _, attendu := range []struct{ annotation, valeur string }{
		{"vault.hashicorp.com/agent-inject-secret-env", "kv/data/ceffio/recording/server"},
		{"vault.hashicorp.com/agent-inject-perms-env", "0644"},
		{"vault.hashicorp.com/agent-inject-secret-relay-secret", "kv/data/ceffio/recording/server"},
		{"vault.hashicorp.com/agent-inject-perms-relay-secret", "0400"},
		{"vault.hashicorp.com/agent-run-as-user", "65532"},
	} {
		if !strings.Contains(ann, attendu.annotation+": \""+attendu.valeur+"\"") {
			t.Errorf("annotation %s: %q absente ou différente\n%s", attendu.annotation, attendu.valeur, ann)
		}
	}
	// THE TEMPLATE OF THE RAW SECRET ENDS WITH A TRIM: without it the file
	// carries the block scalar's newline, and the relay signs with one byte too
	// many — each notification then fails at the capture with a 403 nobody
	// explains.
	if !strings.Contains(ann, `{{- end -}}`) {
		t.Error("le modèle du secret relais n'a pas de trim final : le fichier finirait par un saut de ligne")
	}
}
