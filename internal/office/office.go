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
	"github.com/ceffio-suite/ceffio/internal/vault"
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
	coffre := secrets.DepuisEnvironnement()

	// LE COFFRE EST LA SOURCE UNIQUE — plus aucune copie dans Kubernetes.
	// Le Secret « onlyoffice-secret » n'est plus créé : une valeur qui vit à deux
	// endroits finit par diverger, et la double écriture vers Nextcloud rendrait
	// cette divergence invisible jusqu'au jour où la signature ne correspond plus.
	donnees := map[string]string{}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "onlyoffice", "jwt")
	switch {
	case err == nil:
		donnees = existant
	case secrets.EntreeAbsente(err):
		// Première installation : on génère ci-dessous.
	default:
		return fmt.Errorf("coffre illisible pour onlyoffice/jwt : %w", err)
	}
	jwt := donnees["jwt"]
	if jwt == "" {
		// Une valeur vivante est REPRISE, jamais refabriquée : un jeton régénéré
		// ferait cesser la signature côté serveur et côté connecteur à la fois, et
		// le symptôme — « Invalid token » — ne dit pas lequel des deux a changé.
		genere, err := genSecret(24)
		if err != nil {
			return err
		}
		jwt = genere
		donnees = map[string]string{"jwt": jwt}
		fmt.Println("∙ jeton JWT ONLYOFFICE généré (absent du coffre)")
	}
	return secrets.EcrireDansCoffre(ctx, coffre, "onlyoffice", "jwt", donnees)
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ ONLYOFFICE Docs Server " + officeImage)
	// LES SECRETS SONT POSÉS PAR L'INJECTEUR D'OPENBAO.
	annotations := vault.AnnotationsAgent(8, "onlyoffice", "kv/data/ceffio/onlyoffice/jwt",
		vault.GabaritExports("kv/data/ceffio/onlyoffice/jwt",
			[2]string{"JWT_ENABLED", "true"},
			[2]string{"JWT_SECRET", vault.ChampCoffre("jwt")},
		))

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
      # LES SECRETS SONT POSÉS PAR L'INJECTEUR D'OPENBAO, qui ajoute lui-même
      # l'init-container, le volume EN MÉMOIRE et le bon couple utilisateur/groupe.
      annotations:
%s
    spec:
      # C'EST CE ServiceAccount QUE LE RÔLE DU COFFRE DÉSIGNE.
      serviceAccountName: onlyoffice
      containers:
        - name: onlyoffice
          image: %s
          # LE CONTENEUR PRINCIPAL CHARGE LE FICHIER RENDU, PUIS LANCE LE SCRIPT
          # D'ENTRÉE D'ORIGINE — celui de l'image, qui prépare le serveur.
          command: ["/bin/bash", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /bin/bash /app/ds/run-document-server.sh
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            # L'injecteur ajoute de lui-même le montage des secrets à /secrets.
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
`, ns, ns, ns, annotations, officeImage, ns)
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

// readSecretJWT rend le jeton de signature, DEPUIS LE COFFRE, sans aucun repli.
//
// C'EST LE POINT DE LA DOUBLE ÉCRITURE, et donc le cœur du sujet ici : le même
// jeton alimente ONLYOFFICE ET la configuration du connecteur dans Nextcloud. On
// le lit au même endroit pour les deux — sinon une rotation n'en toucherait
// qu'un, la signature cesserait de correspondre, et le symptôme serait une erreur
// d'authentification sur les documents plutôt qu'une rotation à moitié faite.
func readSecretJWT(ctx context.Context) (string, error) {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "onlyoffice", "jwt")
	if err != nil {
		return "", fmt.Errorf("jeton JWT illisible au coffre : %w", err)
	}
	jwt := entree["jwt"]
	if jwt == "" {
		// Un jeton vide ne se recopie pas « en attendant » : il produirait un
		// connecteur qui refuse toutes les signatures, sans rien dire.
		return "", fmt.Errorf("jeton JWT absent de l'entrée onlyoffice/jwt du coffre")
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
