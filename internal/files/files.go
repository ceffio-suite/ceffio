// Package files orchestre le déploiement de la couche fichiers (Phase 5) :
// l'utilisateur/secret PostgreSQL dédié, l'admin Nextcloud, puis Nextcloud
// branché sur la base `nextcloud` et Redis. Données sur un PVC.
//
// Secrets générés au runtime (crypto/rand), jamais en clair dans Git (§111).
package files

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strings"
	"time"
)

// Versions pinnées (découvertes via Docker Hub, pas inventées).
const (
	nextcloudImage = "docker.io/library/nextcloud:34.0.3"
	ns             = "ceffio-files"
	// PostgreSQL : pod CNPG (créer le rôle) et service rw (connexion).
	pgPod     = "ceffio-pg-1"
	pgNSPod   = "ceffio-data"
	dbName    = "nextcloud"
	dbUser    = "nextcloud"
	dbService = "ceffio-pg-rw.ceffio-data.svc"
	// Redis (déployé Phase 3).
	redisService = "ceffio-redis.ceffio-data.svc"
	redisPort    = "6379"
)

// Deploy installe la couche fichiers (Phase 5), de façon idempotente :
//  1. rôle + mot de passe PostgreSQL dédié à Nextcloud
//  2. secret admin Nextcloud (généré)
//  3. Nextcloud (postgres + redis + PVC data) + Service
//  4. vérification de l'instance (présence de l'admin dans la base)
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de la couche fichiers (Phase 5)...")

	if err := ensureNextcloudDB(ctx); err != nil {
		return err
	}
	if err := ensureServiceAccount(ctx); err != nil {
		return err
	}
	if err := ensureAdminSecret(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx); err != nil {
		return err
	}
	if err := waitNextcloudReady(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Couche fichiers déployée (Nextcloud installé)")
	return nil
}

// ensureNextcloudDB garantit le rôle PostgreSQL DANS LE COFFRE, et nulle part ailleurs.
//
// Le mot de passe vient du coffre s'il y est déjà : une valeur vivante est REPRISE,
// jamais refabriquée. Le régénérer laisserait Nextcloud avec un mot de passe que la
// base refuse — la panne ne se verrait qu'au redémarrage suivant.
func ensureNextcloudDB(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "nextcloud", "db")
	switch {
	case err == nil:
		entree = actuelle
	case secrets.EntreeAbsente(err):
		// Première installation : on génère et on crée le rôle ci-dessous.
	default:
		return fmt.Errorf("coffre illisible pour nextcloud/db : %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ création du rôle PostgreSQL dédié à Nextcloud")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	sql := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s';\nALTER DATABASE %s OWNER TO %s;\n",
		dbUser, pw, dbName, dbUser)
	if err := psqlExec(ctx, sql); err != nil {
		return err
	}
	entree["username"] = dbUser
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "nextcloud", "db", entree)
}

// ensureAdminSecret garantit le compte d'administration DANS LE COFFRE.
func ensureAdminSecret(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()
	entree := map[string]string{"username": "admin"}
	actuelle, err := secrets.LireEntreeCoffre(ctx, coffre, "nextcloud", "admin")
	switch {
	case err == nil:
		for k, v := range actuelle {
			entree[k] = v
		}
	case secrets.EntreeAbsente(err):
	default:
		return fmt.Errorf("coffre illisible pour nextcloud/admin : %w", err)
	}
	if entree["password"] != "" {
		return nil
	}
	fmt.Println("∙ mot de passe admin Nextcloud généré (absent du coffre)")
	pw, err := genSecret(16)
	if err != nil {
		return err
	}
	entree["password"] = pw
	return secrets.EcrireDansCoffre(ctx, coffre, "nextcloud", "admin", entree)
}

// ensureServiceAccount pose l'identité que le rôle du coffre désigne. Sans elle, le
// pod ne démarre pas : la référence ne résout pas.
//
// ELLE EST POSÉE SÉPARÉMENT, et pas ajoutée au grand manifeste : chaque document
// ajouté à une chaîne de format décale tous les arguments suivants, et c'est
// exactement l'erreur qui a déjà coûté un déploiement silencieusement cassé.
func ensureServiceAccount(ctx context.Context) error {
	return apply(ctx, fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: nextcloud
  namespace: %s
`, ns))
}

func applyWorkload(ctx context.Context) error {
	fmt.Println("∙ Nextcloud " + nextcloudImage)
	// TROIS SOURCES POUR UN SEUL FICHIER : les identifiants de base, le compte
	// d'administration, et le relais d'expédition. Le conteneur n'a pas à savoir
	// d'où vient chaque valeur ; il charge un fichier, l'injecteur le compose.
	annotations := vault.AnnotationsAgent(8, "nextcloud", "kv/data/ceffio/nextcloud/db",
		vault.GabaritMulti([]vault.Source{
			{Chemin: "kv/data/ceffio/nextcloud/db", Paires: [][2]string{
				{"POSTGRES_USER", vault.ChampCoffre("username")},
				{"POSTGRES_PASSWORD", vault.ChampCoffre("password")},
			}},
			{Chemin: "kv/data/ceffio/nextcloud/admin", Paires: [][2]string{
				{"NEXTCLOUD_ADMIN_USER", vault.ChampCoffre("username")},
				{"NEXTCLOUD_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			}},
		}))

	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nextcloud-data
  namespace: %s
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nextcloud
  namespace: %s
  labels:
    app: nextcloud
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nextcloud
  template:
    metadata:
      labels:
        app: nextcloud
      # LES SECRETS SONT POSÉS PAR L'INJECTEUR D'OPENBAO (vault.AnnotationsAgent).
      annotations:
%s
    spec:
      # C'EST CE ServiceAccount QUE LE RÔLE DU COFFRE DÉSIGNE.
      serviceAccountName: nextcloud
      containers:
        - name: nextcloud
          image: %s
          # LE SCRIPT D'ENTRÉE D'ORIGINE EST PRÉSERVÉ : c'est lui qui prépare
          # l'instance. On charge seulement le fichier rendu avant de le lancer.
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /entrypoint.sh apache2-foreground
          env:
            - name: POSTGRES_HOST
              value: %s
            - name: POSTGRES_DB
              value: %s
            - name: REDIS_HOST
              value: %s
            - name: REDIS_HOST_PORT
              value: "%s"
            - name: NEXTCLOUD_TRUSTED_DOMAINS
              value: "cloud.demo.local localhost 10.42.0.0/24"
          ports:
            - name: http
              containerPort: 80
          volumeMounts:
            - name: data
              mountPath: /var/www/html
          readinessProbe:
            tcpSocket:
              port: http
          resources:
            limits:
              memory: 1Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: nextcloud-data
---
apiVersion: v1
kind: Service
metadata:
  name: nextcloud
  namespace: %s
spec:
  selector:
    app: nextcloud
  ports:
    - name: http
      port: 80
      targetPort: 80
`, ns, ns, annotations, nextcloudImage, dbService, dbName, redisService, redisPort, ns)
	return apply(ctx, manifest)
}

func waitNextcloudReady(ctx context.Context) error {
	fmt.Println("∙ attente Nextcloud Ready + installation...")
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status",
		"deployment/nextcloud", "-n", ns, "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nextcloud pas prêt: %w", err)
	}
	return waitNextcloudInstalled(ctx)
}

// waitNextcloudInstalled vérifie que l'admin existe (table oc_users), signe
// qu'Occurrent installation est terminée.
func waitNextcloudInstalled(ctx context.Context) error {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		out, err := queryNextcloudDB(ctx, `SELECT count(*) FROM oc_users;`)
		if err == nil && strings.TrimSpace(out) >= "1" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("instance Nextcloud non initialisée après 180s")
}

func psqlExec(ctx context.Context, sql string) error {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("psql: %w: %s", err, out)
	}
	return nil
}

func queryNextcloudDB(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-c", "postgres",
		"-n", pgNSPod, pgPod, "--", "psql", "-U", "postgres", "-d", dbName, "-tAc", sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql: %w: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func secretExists(ctx context.Context, name string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
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

// ConfigureOIDC branche Nextcloud sur le SSO Keycloak : app user_oidc + provider.
// Idempotent (l'app et le provider tolèrent "déjà présent").
func ConfigureOIDC(ctx context.Context, domain string) error {
	fmt.Println("SSO Nextcloud ← Keycloak...")
	if err := ensureOccApp(ctx, "user_oidc"); err != nil {
		return err
	}
	clientID, err := readSecretValue(ctx, "ceffio-identity", "nextcloud-oidc", "client-id")
	if err != nil {
		return fmt.Errorf("secret nextcloud-oidc: %w", err)
	}
	clientSecret, err := readSecretValue(ctx, "ceffio-identity", "nextcloud-oidc", "client-secret")
	if err != nil {
		return fmt.Errorf("secret nextcloud-oidc: %w", err)
	}
	// Le point de découverte doit être le nom PUBLIC, pas l'adresse interne du
	// cluster. Nextcloud reprend les endpoints annoncés par Keycloak : interrogé
	// en interne, il recevait « http://keycloak.ceffio-identity.svc:8080 » et
	// redirigeait le navigateur vers une adresse injoignable de l'extérieur
	// (constaté : « keycloak...:8080 » dans l'URL d'autorisation).
	//
	// Keycloak porte KC_HOSTNAME_URL : interrogé par son nom public, il annonce
	// des endpoints publics — ceux que le navigateur peut réellement joindre.
	// Le domaine n'est donc plus figé ici : il vient du déploiement.
	if domain == "" {
		return fmt.Errorf("domaine requis pour construire le point de découverte OIDC")
	}
	discovery := "https://keycloak." + domain + "/realms/ceffio/.well-known/openid-configuration"
	out, err := runOccOutput(ctx, "user_oidc:provider", "Ceffio", "-c", clientID, "-s", clientSecret, "-d", discovery)
	if err != nil && !strings.Contains(out, "already") {
		return fmt.Errorf("user_oidc:provider: %w: %s", err, out)
	}
	// Le provider existant peut avoir été créé avec l'ancienne URL interne : on
	// le met à jour pour que la correction s'applique sans reinstaller.
	runOccOutput(ctx, "user_oidc:provider", "Ceffio", "-d", discovery)
	runOccOutput(ctx, "user_oidc:provider", "Ceffio", "--update")

	// PURGER le cache de découverte. Nextcloud mémorise les endpoints obtenus lors
	// de la découverte et les réutilise : sans purge, il continuait de rediriger
	// vers l'ancien domaine (constaté : auth.ceffio.local) alors que Keycloak
	// annonçait déjà la bonne adresse. Le cache doit suivre la configuration.
	for _, cle := range []string{"provider-1-jwksCache", "provider-1-jwksCacheTimestamp"} {
		runOccOutput(ctx, "config:app:delete", "user_oidc", cle)
	}
	fmt.Println("✓ SSO Nextcloud configuré (user_oidc + provider Ceffio)")
	return nil
}

func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err != nil && !strings.Contains(out, "already installed") && !strings.Contains(out, "already enabled") {
		return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
	}
	return nil
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, "deploy/nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

func readSecretValue(ctx context.Context, sNs, name, key string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", sNs, "-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", err
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}
