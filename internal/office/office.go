// Package office orchestre le déploiement de la couche office (Phase 6) :
// le serveur ONLYOFFICE Docs Server (JWT), puis le connecteur dans Nextcloud.
//
// Secrets générés au runtime (JWT), jamais en clair dans Git (§111).
package office

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/version"
	"os"
	"strings"
	"time"
)

// Versions pinnées (découvertes via Docker Hub / Quay, pas inventées).
const (
	officeImage = "docker.io/onlyoffice/documentserver:9.4.0.1"
	ns          = "ceffio-office"
	// Nom du service OnlyOffice pour le connecteur (URL interne).
	officeService = "http://onlyoffice.ceffio-office.svc"
	// Nextcloud (namespace ceffio-files) pour installer le connecteur.
	nextcloudNS = "ceffio-files"
)

// Deploy installe la couche office (Phase 6), de façon idempotente :
//  1. secret JWT ONLYOFFICE (généré, partagé avec le connecteur)
//  2. ONLYOFFICE Docs Server + PVC + Service
//  3. attente du healthcheck
//  4. connecteur ONLYOFFICE dans Nextcloud
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche office (Phase 6)...")

	if err := ensureJWTSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitOfficeReady(ctx); err != nil {
		return err
	}
	if err := connectNextcloud(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche office déployée (ONLYOFFICE + connecteur Nextcloud)")
	return nil
}

func ensureJWTSecret(ctx context.Context) error {
	// LE COFFRE D'ABORD, le Secret Kubernetes en repli, la génération en dernier.
	// Même ordre que pour Stalwart, et pour la même raison : une valeur vivante
	// est REPRISE, jamais refabriquée. Un jeton régénéré casserait la signature
	// des deux côtés à la fois, et le symptôme serait « Invalid token » — un
	// message qui ne dit pas lequel des deux a changé.
	coffre := secrets.DepuisEnvironnement()
	jwt, err := secrets.LireOuSecret(ctx, coffre, "onlyoffice", "jwt", "jwt",
		"ceffio-office/onlyoffice-secret", "jwt")
	if err != nil || jwt == "" {
		jwt, err = genSecret(24)
		if err != nil {
			return err
		}
		fmt.Println("∙ jeton JWT ONLYOFFICE généré (absent du coffre et de Kubernetes)")
	}
	// Le Secret Kubernetes est TOUJOURS posé : c'est à la fois le repli du pod et
	// ce que lit le connecteur Nextcloud si le coffre venait à manquer.
	return createSecret(ctx, "onlyoffice-secret", map[string]string{"jwt": jwt})
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ ONLYOFFICE Docs Server " + officeImage)
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: onlyoffice-data
  namespace: %s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 20Gi
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: onlyoffice-agent
  namespace: %s
data:
  # LA CONFIGURATION DE L'AGENT, DÉCLARATIVE. Elle remplace les commandes
  # « bao » écrites à la main dans le conteneur : plus de manipulation de secret
  # dans un shell, jeton renouvelé par l'agent, et un gabarit qu'on relit.
  agent.hcl: |
    pid_file = "/tmp/bao-agent.pid"

    vault {
      address = "http://openbao.ceffio-vault.svc:8200"
      retry { num_retries = 2 }
    }

    auto_auth {
      method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = {
          role       = "onlyoffice"
          token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        }
      }
    }

    # ÉCHEC BRUYANT plutôt qu'un jeton vide : un serveur de documents qui tourne
    # avec une signature vide n'est pas un serveur qui marche, c'est un serveur
    # qui accepte n'importe quoi — ou qui refuse tout, sans le dire.
    template_config {
      exit_on_retry_failure = true
    }

    env_template "JWT_ENABLED" {
      contents = "true"
    }

    # LE CHEMIN EST CELUI DE L'API (kv/data/...), comme pour la politique.
    env_template "JWT_SECRET" {
      contents             = "{{ with secret \"kv/data/ceffio/onlyoffice/jwt\" }}{{ .Data.data.jwt }}{{ end }}"
      error_on_missing_key = true
    }

    # L'AGENT LANCE LE SCRIPT D'ENTRÉE D'ORIGINE — celui de l'image, qui prépare
    # le serveur. Le remplacer casserait tout ; c'est lui qui doit tourner.
    exec {
      command = ["/bin/bash", "/app/ds/run-document-server.sh"]
    }
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: onlyoffice
  namespace: %s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: onlyoffice
  namespace: %s
  labels:
    app: onlyoffice
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: onlyoffice
  template:
    metadata:
      labels:
        app: onlyoffice
    spec:
      # L'IDENTITÉ QUE LE COFFRE VALIDE, et le groupe partagé qui rend le volume
      # lisible par les deux conteneurs : ils ne tournent pas sous le même
      # utilisateur, et le fichier écrit par l'un serait sinon illisible pour
      # l'autre — « Permission denied », en boucle.
      serviceAccountName: onlyoffice
      securityContext:
        fsGroup: 1000
      # LE BINAIRE DE L'AGENT EST COPIÉ DEPUIS L'IMAGE DU COFFRE : le mode superviseur
      # exige que l'agent et le service vivent dans le MÊME conteneur, puisque
      # c'est l'agent qui lance le service.
      initContainers:
        - name: binaire-de-l-agent
          image: %s
          command: ["/bin/sh", "-c"]
          args: ["cp /usr/bin/bao /bao-bin/bao && chmod 0555 /bao-bin/bao"]
          volumeMounts:
            - name: bao-bin
              mountPath: /bao-bin
      containers:
        - name: onlyoffice
          image: %s
          # LA GARDE, PUIS L'AGENT. « bao status » est un test de vie rapide ; s'il
          # échoue, on repart du Secret Kubernetes — la suite doit tenir sans
          # OpenBao, et le repli doit s'annoncer, sinon il donne l'illusion que
          # les secrets viennent du coffre.
          command: ["/bin/bash", "-c"]
          args:
            - |
              set -e
              if BAO_ADDR="$COFFRE_ADDR" /bao-bin/bao status >/dev/null 2>&1; then
                exec /bao-bin/bao agent -config=/etc/agent/agent.hcl
              fi
              echo "coffre injoignable : repli sur le Secret Kubernetes"
              export JWT_ENABLED="true"
              export JWT_SECRET="$JWT_SECRET_REPLI"
              exec /bin/bash /app/ds/run-document-server.sh
          env:
            - name: COFFRE_ADDR
              value: "http://openbao.ceffio-vault.svc:8200"
            - name: JWT_SECRET_REPLI
              valueFrom:
                secretKeyRef:
                  name: onlyoffice-secret
                  key: jwt
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            - name: bao-bin
              mountPath: /bao-bin
            - name: agent-config
              mountPath: /etc/agent
              readOnly: true
            - name: data
              mountPath: /var/www/onlyoffice/Data
          readinessProbe:
            tcpSocket:
              port: http
          resources:
            limits:
              memory: 2Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: onlyoffice-data
        # Le binaire de l'agent, copié à chaque démarrage depuis l'image du coffre.
        - name: bao-bin
          emptyDir: {}
        # La configuration de l'agent : un gabarit qu'on relit, pas une commande.
        - name: agent-config
          configMap:
            name: onlyoffice-agent
---
apiVersion: v1
kind: Service
metadata:
  name: onlyoffice
  namespace: %s
spec:
  selector:
    app: onlyoffice
  ports:
    - name: http
      port: 80
      targetPort: 80
`, ns, ns, ns, ns, version.ImageDe("openbao"), officeImage, ns)
	return apply(ctx, manifest)
}

func waitOfficeReady(ctx context.Context) error {
	fmt.Println("∙ attente ONLYOFFICE Ready...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/onlyoffice", "-n", ns, "--timeout=420s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("onlyoffice pas prêt: %w", err)
	}
	return waitHealthcheck(ctx)
}

// waitHealthcheck vérifie /healthcheck == "true" (l'app est fonctionnelle).
func waitHealthcheck(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, "deploy/onlyoffice", "--",
			"sh", "-c", `curl -s http://localhost/healthcheck`).CombinedOutput()
		if err == nil && strings.Contains(string(out), "true") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("healthcheck ONLYOFFICE non vert après 180s")
}

// connectNextcloud installe et configure le connecteur ONLYOFFICE dans Nextcloud.
func connectNextcloud(ctx context.Context) error {
	fmt.Println("∙ connecteur ONLYOFFICE dans Nextcloud")

	jwt, err := readSecretJWT(ctx)
	if err != nil {
		return err
	}

	if err := ensureOccApp(ctx, "onlyoffice"); err != nil {
		return err
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "DocumentServerUrl", "--value="+officeService); err != nil {
		return fmt.Errorf("DocumentServerUrl: %w", err)
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "DocumentServerInternalUrl", "--value="+officeService); err != nil {
		return fmt.Errorf("DocumentServerInternalUrl: %w", err)
	}
	// Le connecteur ONLYOFFICE lit la clé « jwt_secret » (AppConfig::$_jwtSecret),
	// PAS « secret ». Écrire « secret » laissait le connecteur signer les requêtes
	// avec un secret vide → le Document Server répondait error -8 « Invalid token »
	// et Nextcloud affichait « le jeton de sécurité n'était pas formé correctement ».
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_secret", "--value="+jwt); err != nil {
		return fmt.Errorf("secret (JWT): %w", err)
	}
	// Ouvre PAR DÉFAUT tous les formats supportés (OOXML + ODF) au clic simple.
	// defFormats est une map JSON {format: bool}. Sans ça, les ODF se téléchargent au clic.
	const defFormats = `{"docx":true,"docxf":true,"oform":true,"xlsx":true,"csv":true,"pptx":true,"odt":true,"odf":true,"ots":true,"ott":true,"ods":true,"odp":true,"odg":true,"pdf":true,"txt":true,"doc":true,"xls":true,"ppt":true,"rtf":true,"html":true}`
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "defFormats", "--value="+defFormats); err != nil {
		return fmt.Errorf("defFormats: %w", err)
	}
	if err := runOcc(ctx, "config:app:set", "onlyoffice", "jwt_header", "--value=Authorization"); err != nil {
		return fmt.Errorf("jwt_header: %w", err)
	}

	fmt.Println("∙ connecteur configuré")
	return nil
}

func runOcc(ctx context.Context, args ...string) error {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "--", "php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", occArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureOccApp installe (ou réinstalle sans erreur si déjà présente) une app.
func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err == nil {
		return nil
	}
	if strings.Contains(out, "already installed") || strings.Contains(out, "already enabled") {
		fmt.Printf("∙ app %s déjà installée\n", app)
		return nil
	}
	return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", nextcloudNS, "deploy/nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// readSecretJWT rend le jeton de signature, DU COFFRE EN PRIORITÉ.
//
// C'EST LE POINT DE LA DOUBLE ÉCRITURE, et donc le cœur du sujet ici : le même
// jeton alimente ONLYOFFICE ET la configuration du connecteur dans Nextcloud. On
// le lit au même endroit pour les deux — sinon une rotation n'en toucherait
// qu'un, la signature cesserait de correspondre, et le symptôme serait une erreur
// d'authentification sur les documents plutôt qu'une rotation à moitié faite.
func readSecretJWT(ctx context.Context) (string, error) {
	coffre := secrets.DepuisEnvironnement()
	jwt, err := secrets.LireOuSecret(ctx, coffre, "onlyoffice", "jwt", "jwt",
		"ceffio-office/onlyoffice-secret", "jwt")
	if err != nil || jwt == "" {
		return "", fmt.Errorf("jeton JWT introuvable : ni dans le coffre, ni dans le Secret onlyoffice-secret")
	}
	return jwt, nil
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	args := []string{"create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range kv {
		args = append(args, "--from-literal="+k+"="+v)
	}
	out, err := k8s.Command(ctx, "kubectl", args...).Output()
	if err != nil {
		return fmt.Errorf("secret dry-run: %w", err)
	}
	return apply(ctx, string(out))
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
