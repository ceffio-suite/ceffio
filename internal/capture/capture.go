// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package capture deploys the per-participant capture service.
//
// WHY THE SERVICE EXISTS: Talk's recording (module recording) produces a .webm
// whose audio is a MIX. Once mixed, who spoke is only a guess. This service
// joins the call as an internal client — the way the transcription app does —
// and receives one audio track PER PARTICIPANT from the SFU. The transcript
// becomes exact, without diarization.
//
// WHY A SEPARATE IMAGE: the signaling client and the transcription are Python
// (aiortc, faster-whisper) while the Ceffio binary is static. The image is
// published by its own repository (ceffio-suite/ceffio-capture) and pinned in
// internal/version; this package only deploys it.
package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	nsFiles  = "ceffio-files"
	nsData   = "ceffio-data"
	nom      = "ceffio-capture"
	pvcNom   = "ceffio-capture-models"
	portHTTP = 8080
)

// image is the capture image, pinned in the version registry — never `latest`,
// for the same reason as every other component: an installation must be
// reproducible and auditable.
//
// CEFFIO_CAPTURE_IMAGE is a DEVELOPMENT override: testing an unpublished image
// should not require rebuilding the binary to obtain the same tag.
var image = imageDuService()

func imageDuService() string {
	if surcharge := os.Getenv("CEFFIO_CAPTURE_IMAGE"); surcharge != "" {
		return surcharge
	}
	composant, ok := version.ParNom("ceffio-capture")
	if !ok || composant.Image == "" {
		panic("ceffio-capture is missing from the version registry (internal/version)")
	}
	return composant.Image
}

// Deploy installs the service, idempotently.
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying per-participant capture...")

	if err := ensureEnvironnement(ctx); err != nil {
		return err
	}
	if err := deployCompteEtDroits(ctx); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteVolume()); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteDeploiement(domain, annotationsCapture())); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteService()); err != nil {
		return err
	}
	if err := attendrePret(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Capture service ready: one audio track per participant")
	return nil
}

// ensureEnvironnement writes the shared secret where the pod will read it.
//
// RULE: secrets live in OpenBao, nowhere else — no workload reads a Kubernetes
// Secret, and no value is ever printed. The signaling's shared secret is
// COPIED into the capture's own entry (capture/server) so that this service
// never holds a right on talk/signaling: its policy grants read on capture/*
// and nothing else. Same reasoning and same shape as the recorder.
func ensureEnvironnement(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	talk, err := secrets.LireEntreeCoffre(ctx, coffre, "talk", "signaling")
	if err != nil {
		return fmt.Errorf("reading talk/signaling (the Talk layer must be deployed first): %w", err)
	}
	partage := talk["partage"]
	if partage == "" {
		return fmt.Errorf("talk/signaling has no shared secret: the capture service could not join a call")
	}
	// ALWAYS overwritten with the signaling's current value: if the shared
	// secret is ever rotated, this is what keeps the pair aligned.
	return secrets.EcrireDansCoffre(ctx, coffre, "capture", "server",
		map[string]string{"internal-secret": partage})
}

// annotationsCapture declares the one value the pod gets from the vault.
func annotationsCapture() string {
	return vault.AnnotationsAgent(8, "capture", "kv/data/ceffio/capture/server",
		vault.GabaritExports("kv/data/ceffio/capture/server",
			[2]string{"CEFFIO_INTERNAL_SECRET", vault.ChampCoffre("internal-secret")},
		))
}

// deployCompteEtDroits creates the identity and its rights, kept narrow.
//
// TWO EXECS, AND NOTHING ELSE:
//   - in ceffio-files, to deposit the files next to the .webm and run
//     `occ files:scan` — the only way to write into the space of the person who
//     started the recording without mounting their volume;
//   - in ceffio-data, to read the recording state and the room language: the
//     application database user cannot reach the Nextcloud database (verified:
//     `permission denied for database "nextcloud"`), so the query goes through
//     the primary's local psql.
func deployCompteEtDroits(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %[1]s
  namespace: %[3]s
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    # GET as well as CREATE: the exec handshake is authorised by a get on the
    # subresource before the websocket upgrade, and create alone answers 403
    # ("cannot get resource pods/exec") — observed on the first live run.
    verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %[1]s
  namespace: %[3]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %[1]s
subjects:
  - kind: ServiceAccount
    name: %[1]s
    namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %[1]s
  namespace: %[4]s
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    # GET as well as CREATE: the exec handshake is authorised by a get on the
    # subresource before the websocket upgrade, and create alone answers 403
    # ("cannot get resource pods/exec") — observed on the first live run.
    verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %[1]s
  namespace: %[4]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %[1]s
subjects:
  - kind: ServiceAccount
    name: %[1]s
    namespace: %[2]s
`, nom, ns, nsFiles, nsData)
	return appliquer(ctx, manifeste)
}

// manifesteVolume holds the OPTIONAL extra models (medium). The small model is
// baked into the image, so this volume starts empty and empty is fine.
func manifesteVolume() string {
	return fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 2Gi
`, pvcNom, ns)
}

// manifesteDeploiement describes the service.
//
// THE LIMITS ARE NOT DECORATIVE: whisper uses up to 4 threads while
// transcribing, AFTER the call. An unbounded container would starve the
// signaling and Janus — that is, the NEXT call.
func manifesteDeploiement(domain, annotations string) string {
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
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
%[9]s
    spec:
      serviceAccountName: %[1]s
      containers:
        - name: capture
          image: %[3]s
          imagePullPolicy: IfNotPresent
          # The injector renders the vault values as shell exports in
          # /secrets/env; sourcing it is how this container reads them. The
          # file is absent outside a cluster, hence the redirect.
          command: ["sh", "-c", ". /secrets/env 2>/dev/null; exec python3 /app/agent.py"]
          env:
            - name: CEFFIO_DOMAIN
              value: %[4]s
            - name: CEFFIO_HPB_URL
              value: wss://spreed.%[4]s/spreed
            - name: CEFFIO_NEXTCLOUD_URL
              value: https://cloud.%[4]s
            - name: CEFFIO_NC_NAMESPACE
              value: %[6]s
            - name: CEFFIO_DB_NAMESPACE
              value: %[7]s
            - name: CEFFIO_THREADS
              value: "4"
          ports:
            - name: http
              containerPort: %[8]d
          readinessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 5
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 30
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
            limits:
              cpu: "4"
              memory: 4Gi
          volumeMounts:
            # /models-extra, NOT /models: the small model is in the image
            # (/models), and mounting an empty volume over it would erase it —
            # turning a self-contained service into one that needs the internet
            # on its first recording.
            - name: modeles
              mountPath: /models-extra
      volumes:
        - name: modeles
          persistentVolumeClaim:
            claimName: %[10]s
`, nom, ns, image, domain, "", nsFiles, nsData, portHTTP, annotations, pvcNom)
}

func manifesteService() string {
	return fmt.Sprintf(`apiVersion: v1
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
    - name: http
      port: %[3]d
      targetPort: http
`, nom, ns, portHTTP)
}

func attendrePret(ctx context.Context) error {
	fmt.Println("∙ waiting for the capture service to be ready...")
	fin := time.Now().Add(180 * time.Second)
	for time.Now().Before(fin) {
		cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nom,
			"-n", ns, "--timeout=10s")
		if err := cmd.Run(); err == nil {
			fmt.Println("  ✓ capture service ready")
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("the capture service did not become ready in time: kubectl -n %s logs deploy/%s", ns, nom)
}

// Etat is what the service says about itself.
//
// WHY A STRUCT AND NOT A BOOLEAN: "the Deployment is ready" and "the last
// recording was transcribed" are two different facts. A pod that runs and
// fails every transcription looked exactly like one that never tried — the
// silent failure the plan lists as a high risk. The module decides what to
// present from both.
type Situation struct {
	Ready  bool
	Reason string         // why it is not ready, when it is not
	Last   map[string]any // GET /status, empty when the service does not answer
}

// LireEtat reads the Deployment, then asks the service for its last job.
func LireEtat(ctx context.Context) Situation {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return Situation{Reason: "Kubernetes unreachable: " + err.Error()}
	}
	if !cli.DeploiementPret(ctx, ns, nom) {
		return Situation{Reason: "the Deployment is not ready"}
	}
	etat := Situation{Ready: true}
	// READ THROUGH THE API'S SERVICE PROXY. An exec inside the pod would need a
	// shell and a client in the image, and would grant a right to run commands
	// in a workload for what is only a GET; `services/proxy` needs `get` on
	// services/proxy alone, and behaves the same from the console and the CLI.
	brut, err := cli.LireService(ctx, ns, nom, "http", "status")
	if err != nil {
		etat.Reason = err.Error()
		return etat
	}
	dernier := map[string]any{}
	if err := json.Unmarshal(bytes.TrimSpace(brut), &dernier); err == nil {
		etat.Last = dernier
	}
	return etat
}

// Supprime removes what Deploy created, volumes included — the registry's
// contract: a removed module leaves nothing behind.
func Supprime(ctx context.Context) error {
	cmd := k8s.Command(ctx, "kubectl", "delete", "-n", ns, "--ignore-not-found",
		"deployment/"+nom, "service/"+nom, "pvc/"+pvcNom, "serviceaccount/"+nom)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("deleting the capture service: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// The Role/RoleBinding live in two other namespaces: one command each,
	// `-n` applying to a single group of arguments.
	for _, espace := range []string{nsFiles, nsData} {
		cmd := k8s.Command(ctx, "kubectl", "delete", "--ignore-not-found",
			"-n", espace, "role/"+nom, "rolebinding/"+nom)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("deleting the capture rights in %s: %w: %s", espace, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// appliquer applies one YAML document through kubectl, like the rest of the
// repository: a single write path to the cluster, the one already proven.
func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifeste)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
