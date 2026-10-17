// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package recording installs the Nextcloud Talk recording server.
//
// WHY A SEPARATE COMPONENT EXISTS AT ALL: the High Performance Backend
// (signaling + Janus) routes media between participants, but it never stores
// anything. Recording needs a distinct process that JOINS the room as a hidden
// participant, renders it, and uploads the result to Nextcloud. Without it,
// Talk shows the "record this call" option and greys it out with "the
// recording server is not installed" — which is exactly what users see today.
//
// WHY THIS SOFTWARE AND NOT ANOTHER: the recording API is not a standard. It is
// a Talk-specific interface (capability "recording-v1", endpoints under
// /ocs/v2.php/apps/spreed/api/v1/recording/), implemented only by the official
// server. There is no independent implementation to choose from — the images
// that exist all wrap that same program.
//
// WHY IT IS HEAVY: it drives a real browser (Firefox + geckodriver) to capture
// the room, so it needs a few hundred megabytes of memory and a writable
// /tmp. It also has to reach the Janus media range. Those constraints shape the
// manifest below; they are not incidental.
package recording

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

const (
	ns       = "ceffio-video"
	deployNS = ns
	nom      = "talk-recording"
	service  = "talk-recording"
	portHTTP = 1234
)

// The image comes from the version registry (internal/version), the single
// source of truth shared with `ceffio status` and `ceffio upgrade --plan` —
// the same rule as the Janus image.
//
// A var and not a const: the value comes from a function call evaluated at
// package init.
var image = imageDuRegistre()

// Deploy installs the recording server (Phase 14), idempotently:
//  1. its secrets in the vault (its own, plus the signaling internal secret)
//  2. the Deployment + Service
//  3. the Talk setting that points Nextcloud at it
//
// PAS DE BLOC [recording] DANS LE SIGNALING, et c'est délibéré : ce bloc a
// été essayé puis retiré après vérification contre les sources du signaling,
// où « recording » ne retourne rien. Le signaling ne participe pas à
// l'enregistrement — Talk appelle le serveur d'enregistrement directement en
// HTTP. Le détail est dans internal/talk/talk.go. Ce commentaire annonçait
// l'étape 2 pendant que le code ne la faisait pas.
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying the call recording server (Phase 14)...")

	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := deployServiceAccount(ctx); err != nil {
		return err
	}
	if err := deployRecorder(ctx, domain); err != nil {
		return err
	}
	if err := attendrePret(ctx); err != nil {
		return err
	}
	if err := brancherTalk(ctx, domain); err != nil {
		return err
	}

	fmt.Println("✓ Recording server deployed (server-side call recording available)")
	return nil
}

// ensureSecrets puts the two values the recorder needs into the vault.
//
// TWO SECRETS, AND THEY ARE NOT THE SAME ONE:
//
//   - RECORDING_SECRET authenticates the conversation between Nextcloud and the
//     recording server. It belongs to this component.
//   - INTERNAL_SECRET authenticates the recorder against the SIGNALING server.
//     It is NOT ours to invent: it must be byte-for-byte the value the
//     signaling already uses ([clients] internalsecret, stored as "partage").
//     Generating a fresh one here would produce a recorder that starts, looks
//     healthy, and is rejected by the signaling on every attempt.
//
// The signaling secret is therefore READ, never regenerated. If it is absent
// the talk layer has not run, and we say so rather than fabricating a value
// that would silently break the pair.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	talk, err := secrets.LireEntreeCoffre(ctx, coffre, "talk", "signaling")
	if err != nil {
		return fmt.Errorf("reading the talk/signaling vault entry (the Talk layer must be deployed first): %w", err)
	}
	partage := talk["partage"]
	if partage == "" {
		return fmt.Errorf("talk/signaling has no \"partage\" secret: the signaling cannot authenticate the recorder")
	}

	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "recording", "server")
	switch {
	case err == nil:
	case secrets.EntreeAbsente(err):
		existant = map[string]string{}
	default:
		return fmt.Errorf("vault unreadable for recording/server: %w", err)
	}

	// A NEW recording secret only on a first install. Regenerating it would
	// desynchronise Nextcloud, which holds the previous value.
	if existant["recording-secret"] == "" {
		g, err := genSecret(32)
		if err != nil {
			return err
		}
		existant["recording-secret"] = g
		fmt.Println("∙ recording secret generated (absent from the vault)")
	}

	// ALWAYS overwritten with the signaling's current value: if the signaling
	// secret was ever rotated, this is what keeps the pair aligned.
	existant["internal-secret"] = partage

	return secrets.EcrireDansCoffre(ctx, coffre, "recording", "server", existant)
}

// deployServiceAccount lays down the identity the vault will validate.
func deployServiceAccount(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
`, nom, deployNS)
	return appliquer(ctx, manifeste)
}

// deployRecorder creates the Deployment and the Service.
//
// THE RESOURCE LIMITS ARE NOT DECORATIVE. This pod runs a browser: Firefox
// plus geckodriver plus the Python server. It is the heaviest component of the
// suite relative to the work it does, and on a single-host cluster an unbounded
// container would starve the media path — the one thing users notice
// immediately.
func deployRecorder(ctx context.Context, domain string) error {
	// Secrets arrive through the OpenBao injector, like every other workload —
	// this function never reads them, it only wires the annotations.
	annotations := annotationsRecorder()
	manifeste := manifesteRecorder(domain, annotations)

	return appliquer(ctx, manifeste)
}

// annotationsRecorder declares the two values the recorder gets from the vault.
//
// ONLY recording/server IS READ — never talk/signaling. The shared internal
// secret is copied into the recorder's own entry by ensureSecrets, precisely so
// that this component never holds a right on the signaling's secrets. The
// matching policy (ceffio-recording) grants read on recording/* and nothing else.
func annotationsRecorder() string {
	return vault.AnnotationsAgent(8, "recording", "kv/data/ceffio/recording/server",
		vault.GabaritExports("kv/data/ceffio/recording/server",
			[2]string{"RECORDING_SECRET", vault.ChampCoffre("recording-secret")},
			[2]string{"INTERNAL_SECRET", vault.ChampCoffre("internal-secret")},
		))
}

// manifesteRecorder builds the Deployment + Service document.
//
// Separated from the apply so the YAML can be rendered and validated without
// touching a cluster — a malformed manifest would otherwise only be discovered
// mid-deployment, after the earlier phases have already run.
func manifesteRecorder(domain, annotations string) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
%[3]s
    spec:
      serviceAccountName: %[1]s
      containers:
      - name: recording
        image: %[4]s
        imagePullPolicy: IfNotPresent
        # THE SECRETS MUST BE SOURCED INTO THE ENVIRONMENT, and this is not
        # cosmetic: the AIO image reads RECORDING_SECRET / INTERNAL_SECRET from
        # ITS OWN ENVIRONMENT and exits immediately when they are missing:
        #
        #   You need to provide the RECORDING_SECRET.
        #
        # The injector writes /secrets/env; a container that does not source it
        # starts with those variables undefined. The three other components
        # that use the injector (stalwart, keycloak, onlyoffice) do exactly the
        # same thing.
        #
        # exec, and PASS THE IMAGE'S OWN COMMAND as arguments: start.sh ends
        # with an exec on its own arguments, so calling it bare would exec
        # nothing and the container would exit immediately. These are the
        # image's declared Cmd (verified with docker inspect).
        command: ["/bin/bash", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /start.sh python -m nextcloud.talk.recording --config /conf/recording.conf
        env:
        # The recorder needs to tell the two suites apart: which Nextcloud it
        # serves, and which signaling it must authenticate against.
        # NC_DOMAIN MUST BE THE URL NEXTCLOUD ANNOUNCES ITSELF AS, not the
        # installation's base domain. The recorder matches it against the
        # "Talk-Recording-Backend" header Talk sends and looks up a secret for
        # that EXACT url: Config.getBackendSecret() strips a trailing slash,
        # then returns None when the url is unknown -> Forbidden.
        #
        # With the base domain here, the recorder generates a section for
        # "https://<base>" while Talk announces "https://cloud.<base>/": no
        # match, no secret, and every recording attempt is rejected with
        #   No secret configured for backend https://cloud.<base>/
        # which is what the first end-to-end test produced.
        - name: NC_DOMAIN
          value: cloud.%[5]s
        - name: HPB_DOMAIN
          value: spreed.%[5]s
        # HPB_PATH MUST BE OVERRIDDEN. The image defaults it to
        # "/standalone-signaling/", a path that exists only where a reverse
        # proxy strips the prefix. This signaling serves /spreed on the root,
        # so the recorder must be told "/" — otherwise it dials
        # https://spreed.<base>/standalone-signaling/ and gets a 404, and the
        # recording fails with no useful message.
        - name: HPB_PATH
          value: /
        - name: TZ
          value: UTC
        ports:
        - {name: http, containerPort: %[6]d}
        # FIREFOX NEEDS WRITABLE SPACE AND SHARED MEMORY. /dev/shm defaults to
        # 64 MiB in a container, which is not enough for a browser and makes it
        # crash in ways that look like a recording failure rather than a
        # resource problem.
        volumeMounts:
        - {name: tmp, mountPath: /tmp}
        - {name: shm, mountPath: /dev/shm}
        resources:
          requests: {memory: 512Mi, cpu: 200m}
          limits: {memory: 2Gi}
        readinessProbe:
          tcpSocket: {port: %[6]d}
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: tmp
        emptyDir: {}
      - name: shm
        emptyDir: {medium: Memory, sizeLimit: 1Gi}
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
spec:
  selector:
    app: %[1]s
  ports:
  - {name: http, port: %[6]d, targetPort: %[6]d}
`, nom, deployNS, indentYaml(annotations, 8), image, domain, portHTTP)
}

// attendrePret blocks until the recorder answers, so a deployment never claims
// success on a component that has not started.
func attendrePret(ctx context.Context) error {
	fmt.Println("∙ waiting for the recording server to be ready...")
	fin := time.Now().Add(180 * time.Second)
	for time.Now().Before(fin) {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nom,
			"-n", deployNS, "--timeout=10s")
		if err := cmd.Run(); err == nil {
			fmt.Println("  ✓ recording server ready")
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("the recording server is not ready after 180s")
}

// brancherTalk declares the server in Nextcloud, which is what makes the
// recording button usable in the interface.
func brancherTalk(ctx context.Context, domain string) error {
	url := fmt.Sprintf("http://%s.%s.svc:%d", service, deployNS, portHTTP)
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "recording", "server")
	if err != nil {
		return err
	}

	// THE SHAPE OF THIS VALUE IS WHAT MAKES THE FEATURE WORK, and it is not the
	// obvious one. Talk reads an OBJECT with two keys:
	//
	//     {"servers":[{"server":"URL"}],"secret":"SECRET"}
	//
	// read by Config::getRecordingServers() -> $recording['servers']
	//     and Config::getRecordingSecret()  -> $recording['secret']
	//
	// Both go through getAppValueArray(), which json_decodes the stored string
	// and returns it as an array. An object with those two keys gives the two
	// lookups something to find.
	//
	// This was written first as an ARRAY — [{"url":...,"secret":...}] — which
	// looks natural and is wrong twice over: the outer shape is a list, so
	// neither key exists at the top level, both getters return their default
	// ([] and ""), and Config::isRecordingEnabled() returns false. Talk then
	// greys out "record this call" with "the recording server is not
	// installed" — while the recorder is running, declared, and healthy.
	//
	// The entry field is "server", NOT "url" — same trap as the signaling
	// server above, verified in the same file.
	reglage := reglageRecording(url, entree["recording-secret"])
	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", "ceffio-files", "deploy/nextcloud",
		"-c", "nextcloud", "--",
		"php", "occ", "config:app:set", "spreed", "recording_servers", "--value", reglage)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("declaring the recording server in Talk: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("  ✓ recording server declared in Talk")
	return nil
}

// reglageRecording builds the value Talk expects for "recording_servers".
//
// A function rather than an inline format so the SHAPE can be tested: getting
// it wrong leaves the recording button greyed out with no error anywhere.
func reglageRecording(url, secret string) string {
	return fmt.Sprintf(`{"servers":[{"server":%q}],"secret":%q}`, url, secret)
}

// Remove takes the recording server out, completely.
//
// MIROIR EXACT DE Deploy, dans l'ordre inverse de ce qui compte :
//  1. le réglage Talk d'abord — tant que le serveur existe encore, un
//     bouton d'enregistrement actif pointerait vers une URL morte au
//     milieu du retrait ;
//  2. puis les ressources Kubernetes : Deployment, Service, ServiceAccount.
//
// CE QUI N'EST PAS SUPPRIMÉ, ET POURQUOI :
//   - la configuration du signaling : il n'existe AUCUN bloc [recording]
//     dedans (voir la note détaillée de internal/talk/talk.go — vérifiée
//     contre les sources du signaling, qui ne connaît pas ce mot). Talk
//     appelle le recorder directement en HTTP ; il n'y a donc rien à
//     défaire de ce côté.
//   - l'entrée recording/server du coffre : la clé y reste, comme
//     exapps.Remove laisse la clé de HaRP. La régénérer au prochain
//     Deploy est inutile, et sa présence ne coûte rien.
//
// Best effort sur chaque suppression : une ressource déjà absente est le
// cas normal au second retrait, et ne doit pas interrompre les autres.
func Remove(ctx context.Context) error {
	fmt.Println("\nRemoving the call recording server...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}

	// 1. le réglage Talk. Via l'API Kubernetes, pas kubectl : ce retrait
	// peut être déclenché depuis la console, dont le conteneur est
	// distroless (ni shell ni kubectl) — la même leçon que partout
	// ailleurs dans le projet.
	if pod, err := cli.PodDuDeploiement(ctx, "ceffio-files", "nextcloud", "nextcloud"); err == nil {
		if _, err := cli.Executer(ctx, "ceffio-files", pod, "nextcloud",
			"php", "occ", "config:app:delete", "spreed", "recording_servers"); err != nil {
			// Non fatal : le réglage peut être déjà absent. Rapporté,
			// pas avalé.
			fmt.Printf("  note: clearing the Talk setting returned: %v\n", err)
		}
	}

	// 2. les ressources Kubernetes, dans le même style que exapps.Remove :
	// chaque suppression est indépendante.
	for _, forme := range []string{
		"Deployment/" + nom,
		"Service/" + service,
		"ServiceAccount/" + nom,
	} {
		if err := cli.SupprimerEfface(ctx, deployNS, forme); err != nil {
			return err
		}
	}

	fmt.Println("✓ Recording server removed (Talk setting cleared, workload and service deleted)")
	return nil
}

// ---------------------------------------------------------------------------

// genSecret produces a random alphanumeric secret of n characters.
//
// Local to this package, like every layer that needs one: the project keeps
// the helper beside its use rather than centralising it, so a layer can be
// read on its own.
func genSecret(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b), nil
}

func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifeste)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func indentYaml(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lignes := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lignes {
		if l != "" {
			lignes[i] = pad + l
		}
	}
	return strings.Join(lignes, "\n")
}

// imageDuRegistre returns the recording server image as declared in the
// version registry — the single source of truth shared with `ceffio status`
// and `ceffio upgrade --plan`, the same rule as the Janus image.
//
// It PANICS on a missing entry, deliberately: an empty image string would
// produce a Deployment that fails later, inside the cluster, with a message
// far less clear than this one.
func imageDuRegistre() string {
	c, ok := version.ParNom("talk-recording")
	if !ok || c.Image == "" {
		panic("talk-recording is missing from the version registry (internal/version)")
	}
	return c.Image
}
