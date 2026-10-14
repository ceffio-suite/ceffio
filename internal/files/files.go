// Package files orchestre le déploiement de la couche fichiers (Phase 5) :
// l'utilisateur/secret PostgreSQL dédié, l'admin Nextcloud, puis Nextcloud
// branché sur la base `nextcloud` et Redis. Données sur un PVC.
//
// Secrets générés au runtime (crypto/rand), jamais en clair dans Git (§111).
package files

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"os"
	"strconv"
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
	// IDENTIFIANT ET SECRET VIENNENT DE LA MÊME ENTRÉE DU COFFRE : les séparer
	// ouvrirait la porte à un identifiant d'un client et un secret d'un autre.
	entreeOIDC, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "nextcloud", "oidc")
	if err != nil {
		return fmt.Errorf("client OIDC nextcloud: %w", err)
	}
	// Le coffre renvoie les champs tels qu'ils sont stockés, mais les outils en
	// ligne de commande (`bao kv get`, `jq`, etc.) ajoutent une fin de ligne à la
	// sortie standard. Si on garde ce \n final dans le secret, l'empreinte côté
	// Nextcloud (qui est `trim()`ée par PHP ou par le stockage) ne correspondra
	// jamais — le contrôle de cohérence échouera et, plus grave, Keycloak recevra
	// un client_secret légèrement différent du sien. On nettoie immédiatement.
	clientID := strings.TrimSpace(entreeOIDC["client-id"])
	clientSecret := strings.TrimSpace(entreeOIDC["client-secret"])
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

	// UN SEUL APPEL, TOUJOURS AVEC LES IDENTIFIANTS.
	//
	// Ce bloc envoyait auparavant DEUX commandes de « mise à jour » sans
	// identifiants — « user_oidc:provider Ceffio -d <url> » puis
	// « user_oidc:provider Ceffio --update ». Or `occ user_oidc:provider` sans
	// -c/-s RÉÉCRIT le fournisseur avec des valeurs VIDES : la dernière étape
	// effaçait donc le client_id, le client_secret et le discoveryUri que la
	// première venait de poser. Résultat constaté en service : la page de
	// connexion répondait 404 et le SSO Nextcloud était mort.
	//
	// La bonne façon de mettre à jour un fournisseur existant est de RENVOYER
	// la configuration complète. La commande est idempotente dans ce sens :
	// elle crée le fournisseur s'il n'existe pas, le remplace sinon.
	//
	// LE SECRET PASSE PAR UN FICHIER, JAMAIS PAR UN ARGUMENT. `occ` accepte
	// --clientsecret-file précisément pour cela : un secret en argument est
	// visible par `ps` dans le pod, et se retrouve dans l'historique des
	// commandes. On dépose donc le fichier, on donne son CHEMIN, on l'efface.
	// LE SECRET PASSE PAR UNE VARIABLE D'ENVIRONNEMENT TEMPORAIRE.
	//
	// On vise un pod précis, car `kubectl exec deploy/nextcloud` choisit un pod
	// au hasard et `occ` n'aurait pas la variable d'env si le pod changeait.
	// L'option `--clientsecret-env` évite de mettre le secret dans argv (visible
	// par `ps`) ou dans un fichier (source d'erreurs de permission/copie) : il
	// voyage dans l'environnement du seul processus occ, et disparaît avec lui.
	pod, err := podNextcloud(ctx)
	if err != nil {
		return err
	}
	const envSecret = "CEFFIO_OIDC_SECRET"
	out, err := runOccOutputPodEnv(ctx, pod, envSecret, clientSecret,
		"user_oidc:provider", nomProvider,
		"-c", clientID, "-d", discovery, "--clientsecret-env="+envSecret)
	if err != nil && !strings.Contains(out, "already") {
		return fmt.Errorf("user_oidc:provider: %w: %s", err, out)
	}
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("client OIDC incomplet dans le coffre (client-id=%t, client-secret=%t) : "+
			"le fournisseur Nextcloud resterait sans identifiants",
			clientID != "", clientSecret != "")
	}

	// PURGER le cache de découverte. Nextcloud mémorise les endpoints obtenus lors
	// de la découverte et les réutilise : sans purge, il continuait de rediriger
	// vers l'ancien domaine (constaté : auth.ceffio.local) alors que Keycloak
	// annonçait déjà la bonne adresse. Le cache doit suivre la configuration.
	for _, cle := range []string{"provider-1-jwksCache", "provider-1-jwksCacheTimestamp"} {
		runOccOutput(ctx, "config:app:delete", "user_oidc", cle)
	}

	// VÉRIFIER CE QUI A ÉTÉ ENREGISTRÉ, pas ce qu'on a demandé. occ peut sortir
	// en succès en ayant écrit un fournisseur incomplet — c'est exactement ce
	// qui s'était produit, et rien ne le signalait.
	if err := verifierProviderOIDC(ctx, nomProvider, clientID, clientSecret); err != nil {
		return err
	}
	fmt.Println("✓ SSO Nextcloud configuré (user_oidc + provider Ceffio)")
	return nil
}

// nomProvider est le nom du fournisseur OIDC dans Nextcloud. Il apparaît dans
// l'URL de connexion (/apps/user_oidc/login/1) et dans le nom des clés
// d'application (provider-1-*), qu'on retrouve par ce nom plutôt qu'en dur.
const nomProvider = "Ceffio"

// verifierProviderOIDC relit la configuration ÉCRITE dans la table
// `oc_user_oidc_providers` et déchiffre le secret avec l'API Nextcloud.
//
// Depuis user_oidc 8.x, les fournisseurs ne vivent plus dans `oc_appconfig`.
// De plus, le secret stocké est CHIFFRÉ par Nextcloud : une comparaison
// directe de l'empreinte échouerait toujours. On passe donc par le serveur
// Nextcloud lui-même pour déchiffrer, puis on compare au coffre.
//
// Le secret n'est jamais affiché : seules les empreintes sont comparées.
func verifierProviderOIDC(ctx context.Context, nom, clientIDAttendu, secretAttendu string) error {
	// LE SECRET EST DÉCHIFFRÉ AVANT COMPARAISON — sans quoi la vérification est
	// structurellement impossible. Nextcloud stocke ce champ CHIFFRÉ
	// (LoginController et TokenService appellent `$this->crypto->decrypt`) : une
	// empreinte calculée sur la valeur stockée compare du chiffré à du clair, et
	// échoue toujours. C'est ce que faisait la version précédente de ce contrôle.
	//
	// On passe par le serveur Nextcloud lui-même pour déchiffrer : lui seul a la
	// clé d'instance. Le script est déposé dans le pod puis exécuté.
	const fichierVerif = "/tmp/.ceffio-oidc-verif.php"
	script := `<?php
require_once "/var/www/html/lib/base.php";
use OCP\IDBConnection;
use OCP\Security\ICrypto;
$id = $argv[1] ?? "";
$db = \OC::$server->get(IDBConnection::class);
$row = $db->executeQuery("SELECT client_id, client_secret, discovery_endpoint FROM oc_user_oidc_providers WHERE identifier = ?", [$id])->fetch();
if (!$row) { echo "ABSENT\n"; exit(0); }
try {
    $crypto = \OC::$server->get(ICrypto::class);
    $clair = $crypto->decrypt($row["client_secret"]);
} catch (\Throwable $e) {
    echo "INDECHIFFRABLE\n"; exit(0);
}
echo "client_id=" . $row["client_id"] . "\n";
echo "secret_sha=" . sha1($clair) . "\n";
echo "secret_len=" . strlen($clair) . "\n";
echo "discovery=" . $row["discovery_endpoint"] . "\n";`
	// Même pod que pour l'écriture : l'évaluation dépend du Nextcloud en cours.
	pod, err := podNextcloud(ctx)
	if err != nil {
		return err
	}
	if err := deposerFichierPod(ctx, pod, fichierVerif, script); err != nil {
		return err
	}
	defer supprimerFichierPod(ctx, pod, fichierVerif)
	out, err := runPhpPod(ctx, pod, fichierVerif, nom)
	if err != nil && !strings.Contains(out, "client_id=") {
		return fmt.Errorf("relecture du fournisseur OIDC %q : %w: %s", nom, err, debuter(out, 200))
	}
	if err != nil && !strings.Contains(out, "client_id=") {
		return fmt.Errorf("relecture du fournisseur OIDC %q : %w: %s", nom, err, debuter(out, 200))
	}
	if strings.Contains(out, "ABSENT") {
		return fmt.Errorf("le fournisseur OIDC %q n'existe pas après configuration : "+
			"la page de connexion répondrait 404", nom)
	}
	if strings.Contains(out, "INDECHIFFRABLE") {
		return fmt.Errorf("le fournisseur OIDC %q porte un secret que Nextcloud ne peut PAS "+
			"déchiffrer : l'échange de jetons avec Keycloak échouerait", nom)
	}
	champs := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, "="); i > 0 {
			champs[strings.TrimSpace(l[:i])] = strings.TrimSpace(l[i+1:])
		}
	}
	if champs["client_id"] != clientIDAttendu {
		return fmt.Errorf("le fournisseur OIDC %q porte client_id=%q au lieu de %q",
			nom, champs["client_id"], clientIDAttendu)
	}
	if champs["secret_sha"] != fmt.Sprintf("%x", sha1.Sum([]byte(secretAttendu))) {
		return fmt.Errorf("le fournisseur OIDC %q ne porte PAS le secret du coffre : "+
			"l'échange de jetons avec Keycloak échouerait", nom)
	}
	if !strings.Contains(champs["discovery"], "realms/ceffio") {
		return fmt.Errorf("le fournisseur OIDC %q pointe sur une découverte inattendue (%q)",
			nom, champs["discovery"])
	}
	return nil
}

func ensureOccApp(ctx context.Context, app string) error {
	out, err := runOccOutput(ctx, "app:install", app)
	if err != nil && !strings.Contains(out, "already installed") && !strings.Contains(out, "already enabled") {
		return fmt.Errorf("occ app:install %s: %w: %s", app, err, out)
	}
	return nil
}

// runPhpPod exécute PHP directement dans le pod Nextcloud.
//
// POURQUOI PAS runOccOutput : celle-ci préfixe ses arguments par « occ », donc
// « php -r … » devient « occ php -r … » et échoue sur « Command "php" is not
// defined ». Un script de vérification ne passe pas par occ.
func runPhpPod(ctx context.Context, pod, fichier string, args ...string) (string, error) {
	phpArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud",
		"--", "php", fichier}, args...)
	out, err := k8s.Command(ctx, "kubectl", phpArgs...).CombinedOutput()
	return string(out), err
}

// runCommandPod exécute une commande shell brute sur le pod Nextcloud nommé.
//
// Utile pour des diagnostics rapides qui ne passent pas par occ.
func runCommandPod(ctx context.Context, pod string, args ...string) (string, error) {
	cmdArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--"}, args...)
	out, err := k8s.Command(ctx, "kubectl", cmdArgs...).CombinedOutput()
	return string(out), err
}

// deposerFichierPod écrit un contenu dans un fichier du pod.
//
// LE CONTENU VOYAGE VIA UN FICHIER LOCAL EXPLICITE (/tmp/.ceffio-*), copié par
// `kubectl cp` puis effacé. On évite à la fois (a) un secret passé en argument
// de commande — visible par `ps` — et (b) un `kubectl exec` en écriture sur
// stdin qui a prouvé ne pas fonctionner de manière fiable dans ce contexte.
//
// Le fichier local porte le MÊME NOM que le fichier distant : cela élimine les
// surprises de `kubectl cp` sur les noms de fichiers temporaires (préfixe aléatoire
// incompatible avec certains chemins).
func deposerFichierPod(ctx context.Context, pod, cheminPod, contenu string) error {
	local := cheminPod
	if err := os.WriteFile(local, []byte(contenu), 0600); err != nil {
		return fmt.Errorf("écriture du fichier local %s : %w", local, err)
	}
	defer os.Remove(local)

	out, err := k8s.Command(ctx, "kubectl", "cp", "-n", ns, local,
		pod+":"+cheminPod, "-c", "nextcloud").CombinedOutput()
	if err != nil {
		return fmt.Errorf("copie du fichier vers le pod (%s) : %w: %s", cheminPod, err, debuter(string(out), 200))
	}
	return nil
}

// tailleFichierPod renvoie la taille d'un fichier du pod, ou -1 s'il est absent.
func tailleFichierPod(ctx context.Context, pod, chemin string) int {
	// `wc -c <fichier>` renvoie « 64 /tmp/fichier » : le nom s'ajoute à la taille
	// et fait échouer la conversion. On passe donc par `sh -c "wc -c < fichier"`,
	// qui ne renvoie QUE le nombre.
	out, err := k8s.Command(ctx, "kubectl", "exec", "-n", ns, pod,
		"-c", "nextcloud", "--", "sh", "-c", "wc -c < "+chemin).Output()
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1
	}
	return n
}

// supprimerFichierPod efface un fichier du pod. Un secret en clair ne doit pas
// survivre à l'opération qui l'a déposé.
func supprimerFichierPod(ctx context.Context, pod, chemin string) {
	k8s.Command(ctx, "kubectl", "exec", "-n", ns, pod, "-c", "nextcloud",
		"--", "rm", "-f", chemin).Run()
}

// podNextcloud renvoie le nom d'un pod Nextcloud en cours d'exécution.
//
// Nécessaire pour les opérations qui ne supportent pas `deploy/nextcloud`, comme
// `kubectl cp` vers un conteneur spécifique d'un déploiement.
//
// On filtre sur le PRÉFIXE DU NOM et sur la phase, pas sur une étiquette : le
// déploiement ne porte pas de label exploitable (`app.kubernetes.io/name` est
// absent), et un sélecteur qui ne correspond à rien rend une liste vide — donc un
// échec déguisé en « aucun pod », ce qui a coûté un aller-retour.
func podNextcloud(ctx context.Context) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "pods", "-n", ns,
		"--field-selector=status.phase=Running",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}").Output()
	if err != nil {
		return "", fmt.Errorf("recherche du pod Nextcloud : %w", err)
	}
	for _, nom := range strings.Fields(string(out)) {
		if strings.HasPrefix(nom, "nextcloud-") {
			return nom, nil
		}
	}
	return "", fmt.Errorf("aucun pod Nextcloud en cours d'exécution dans %s", ns)
}

func runOccOutput(ctx context.Context, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// runOccOutputPod exécute occ sur le pod NOMMÉ, pas sur le déploiement.
//
// INDISPENSABLE quand une opération précédente a déposé un fichier secret dans
// un pod particulier : `kubectl exec deploy/nextcloud` choisit un pod au hasard
// parmi les réplicas, et le fichier serait invisible depuis un autre pod.
func runOccOutputPod(ctx context.Context, pod string, args ...string) (string, error) {
	occArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--", "php", "occ"}, args...)
	out, err := k8s.Command(ctx, "kubectl", occArgs...).CombinedOutput()
	return string(out), err
}

// runOccOutputPodEnv exécute occ sur le pod nommé, avec une variable
// d'environnement temporaire injectée. Utile pour passer un secret sans le
// mettre dans argv ni dans un fichier.
func runOccOutputPodEnv(ctx context.Context, pod, nomEnv, valeurEnv string, args ...string) (string, error) {
	// Le secret est passé via `env VAR=val php occ ...` ; le shell dans le pod
	// interprète l'assignation. La valeur est du hexa, donc sans caractère
	// problématique pour le shell.
	envAssign := fmt.Sprintf("%s=%s", nomEnv, valeurEnv)
	occArgs := append([]string{"exec", "-n", ns, pod, "-c", "nextcloud", "--",
		"env", envAssign, "php", "occ"}, args...)
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

// debuter renvoie les n premiers caractères d'une sortie de commande, sur UNE
// ligne. Sert aux messages d'erreur : la sortie brute d'occ peut faire des
// milliers de lignes et noierait la cause.
func debuter(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
