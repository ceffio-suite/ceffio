// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package capture installe le service de capture audio par participant.
//
// POURQUOI CE SERVICE EXISTE : l'enregistrement Talk (module recording) produit
// un .webm dont l'audio est un MÉLANGE. Une fois mélangé, savoir qui a parlé
// n'est plus qu'une déduction. Ce service rejoint l'appel en client interne —
// comme le fait l'app de transcription — et reçoit du SFU une piste PAR
// PARTICIPANT. La transcription devient exacte, sans diarisation.
//
// POURQUOI UNE IMAGE SÉPARÉE : le client de signaling et la transcription sont
// en Python (aiortc, faster-whisper) alors que le binaire Ceffio est statique.
// Le module déploie l'image, il ne l'embarque pas.
package capture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/version"
)

const (
	ns         = "ceffio-video"
	nsFiles    = "ceffio-files"
	nsData     = "ceffio-data"
	nom        = "ceffio-capture"
	secretName = "ceffio-capture-env"
	pvcNom     = "ceffio-capture-models"
	portHTTP   = 8080
)

// L'image suit la version du binaire qui la déploie : elle est construite par
// la même CI, au même tag. Pas de `latest` — un tag figé répondeur.
var image = "ghcr.io/ceffio-suite/ceffio-capture:" + version.ImageTag()

// Deploy installe le service, idempotemment.
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying per-participant capture (Phase 15)...")

	if err := ensureEnvironnement(ctx, domain); err != nil {
		return err
	}
	if err := deployCompteEtDroits(ctx); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteVolume()); err != nil {
		return err
	}
	if err := appliquer(ctx, manifesteDeploiement(domain)); err != nil {
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

// ensureEnvironnement forme le Secret natif du service.
//
// POURQUOI PAS L'INJECTEUR DU COFFRE : le service n'a besoin que de deux
// valeurs, dont une (le secret interne du signaling) appartient au module
// talk. Une entrée de coffre dédiée demanderait une politique OpenBao de plus
// pour recopier un secret existant ; le Secret natif dit exactement ce qu'il
// contient, et le module le régénère à chaque installation.
func ensureEnvironnement(ctx context.Context, domain string) error {
	coffre := secrets.DepuisEnvironnement()
	talk, err := secrets.LireEntreeCoffre(ctx, coffre, "talk", "signaling")
	if err != nil {
		return fmt.Errorf("reading talk/signaling (the Talk layer must be deployed first): %w", err)
	}
	partage := talk["partage"]
	if partage == "" {
		return fmt.Errorf("talk/signaling has no \"partage\" secret: the capture service could not join a call")
	}

	manifeste := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[3]s
type: Opaque
stringData:
  CEFFIO_INTERNAL_SECRET: %[4]s
`, secretName, ns, nom, partage)
	return appliquer(ctx, manifeste)
}

// deployCompteEtDroits crée l'identité et ses droits, réduits au strict.
//
// DEUX EXECS, ET RIEN D'AUTRE :
//   - dans ceffio-files, pour déposer les fichiers à côté du .webm et lancer
//     `occ files:scan` — c'est le seul moyen d'écrire dans l'espace de la
//     personne qui a lancé l'enregistrement sans monter son volume ;
//   - dans ceffio-data, pour lire l'état d'enregistrement et la langue de la
//     salle (psql local, sans identifiant : la base refuse l'utilisateur
//     applicatif hors de sa propre base).
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
    verbs: ["create"]
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
    verbs: ["create"]
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

// manifesteVolume porte les modèles (Vosk pour les langues déjà téléchargées,
// whisper pour la transcription). 2 Gi : `small` fait 250 Mo, `medium` 750 Mo.
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

// manifesteDeploiement décrit le service.
//
// LES LIMITES NE SONT PAS DÉCORATIVES : whisper occupe jusqu'à 8 threads
// pendant la transcription, APRÈS l'appel. Un conteneur non borné étoufferait
// le signaling et Janus, c'est-à-dire l'appel suivant.
func manifesteDeploiement(domain string) string {
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
    spec:
      serviceAccountName: %[1]s
      containers:
        - name: capture
          image: %[3]s
          imagePullPolicy: IfNotPresent
          env:
            - name: CEFFIO_DOMAIN
              value: %[4]s
            - name: CEFFIO_HPB_URL
              value: wss://spreed.%[4]s/spreed
            - name: CEFFIO_INTERNAL_SECRET
              valueFrom:
                secretKeyRef:
                  name: %[5]s
                  key: CEFFIO_INTERNAL_SECRET
            - name: CEFFIO_NC_NAMESPACE
              value: %[6]s
            - name: CEFFIO_DB_NAMESPACE
              value: %[7]s
            - name: CEFFIO_MODEL
              value: small
            - name: CEFFIO_THREADS
              value: "4"
            - name: CEFFIO_MODELS
              value: /models
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
            - name: modeles
              mountPath: /models
      volumes:
        - name: modeles
          persistentVolumeClaim:
            claimName: %[9]s
`, nom, ns, image, domain, secretName, nsFiles, nsData, portHTTP, pvcNom)
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

// Etat lit le cluster : le Deployment est-il prêt ?
func Etat(ctx context.Context) bool {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return false
	}
	return cli.DeploiementPret(ctx, ns, nom)
}

// Supprime retire tout ce que Deploy a créé, volumes compris — le contrat du
// registre : un module retiré ne laisse rien derrière lui.
func Supprime(ctx context.Context) error {
	cmd := k8s.Command(ctx, "kubectl", "delete", "-n", ns, "--ignore-not-found",
		"deployment/"+nom, "service/"+nom, "pvc/"+pvcNom,
		"secret/"+secretName, "serviceaccount/"+nom)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("deleting the capture service: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// Les Role/RoleBinding vivent dans deux autres namespaces : une commande
	// par namespace, `-n` ne s'appliquant qu'à un seul groupe d'arguments.
	for _, espace := range []string{nsFiles, nsData} {
		cmd := k8s.Command(ctx, "kubectl", "delete", "--ignore-not-found",
			"-n", espace, "role/"+nom, "rolebinding/"+nom)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("deleting the capture rights in %s: %w: %s", espace, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// appliquer applique un document YAML par kubectl, comme le reste du dépôt :
// un seul chemin d'écriture vers le cluster, celui qui est déjà vérifié.
func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifeste)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
