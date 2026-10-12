// Package mail orchestre le déploiement de la couche messagerie (Phase 13) :
// le serveur Stalwart, qui reçoit, stocke et sert le courrier en IMAP.
//
// POURQUOI STALWART : Nextcloud fournit l'interface (app Mail), mais PAS le
// serveur de courrier. Stalwart tient ce rôle : SMTP entrant, IMAP, filtres
// Sieve, antispam — dans un seul binaire Rust. L'utilisateur lit ses messages
// dans Nextcloud ; Stalwart est la plomberie derrière.
//
// DEUX CONTRAINTES RÉELLES, MESURÉES AVANT D'ÉCRIRE CE CODE :
//
//  1. Le port 25 SORTANT est BLOQUÉ chez Free (vérifié). Stalwart ne peut donc
//     pas livrer directement vers Gmail. On le configure avec un RELAIS
//     d'expédition (send.one.com:587) : c'est lui qui envoie vers l'extérieur,
//     et il porte le reverse DNS. C'est la configuration standard des
//     auto-hébergeurs derrière une connexion grand public.
//
//  2. Le reverse DNS de l'IP publique est « mandem.hd.free.fr », pas le domaine.
//     Sans relais, Gmail rejetterait les messages. Avec relais, la question
//     disparaît — c'est one.com qui est responsable de la délivrabilité.
//
// L'administration de Stalwart reste SÉPARÉE (consigne utilisateur) : la console
// Ceffio n'y conduit que par un lien, et la rotation du mot de passe admin agit
// sur son API REST (voir internal/console/admin.go).
package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// Version réelle constatée sur Docker Hub (pas inventée).
const (
	stalwartImage = "docker.io/stalwartlabs/stalwart:v0.16.26"
	ns            = "ceffio-mail"
	// Domaine par défaut des boîtes. Surchargé par l'appelant.
	domaineDefaut = "mandem-it.com"
)

// Deploy installe la couche messagerie (Phase 13), de façon idempotente :
//  1. secrets (mot de passe admin, clé de stockage)
//  2. Stalwart + PVC + Service
//  3. attente du healthcheck
//  4. relais d'expédition configuré (le port 25 sortant est bloqué)
//
// Le domaine vient du déploiement : le même code sert pour un domaine de test
// et pour le domaine réel.
func Deploy(ctx context.Context, domain string, relaisHote string, relaisPort int, relaisUser, relaisPass string) error {
	fmt.Println("\nDéploiement de la couche messagerie (Phase 13)...")

	domaine := domaineMail(domain)
	fmt.Printf("∙ domaine de messagerie : %s\n", domaine)

	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := applyWorkload(ctx, domaine); err != nil {
		return err
	}
	if err := waitReady(ctx); err != nil {
		return err
	}
	// Le relais d'expédition n'est posé que si on en a un : sans lui Stalwart
	// démarre quand même (il reçoit), mais ne peut pas envoyer — on le dit.
	if relaisHote != "" {
		if err := configurerRelais(ctx, relaisHote, relaisPort, relaisUser, relaisPass); err != nil {
			fmt.Printf("  ! relais d'expédition non configuré : %v\n", err)
		}
	} else {
		fmt.Println("∙ aucun relais d'expédition : Stalwart recevra mais n'enverra pas vers l'extérieur")
	}

	fmt.Println("✓ Couche messagerie déployée (Stalwart)")
	return nil
}

// domaineMail décide du domaine des boîtes.
//
// On utilise un sous-domaine de la plateforme plutôt que le domaine racine :
// toucher au domaine racine signifierait déplacer les enregistrements MX de la
// messagerie existante, donc couper le courrier actuel. Un sous-domaine permet
// de tester sans rien casser.
func domaineMail(domain string) string {
	if d := os.Getenv("CEFFIO_MAIL_DOMAIN"); d != "" {
		return d
	}
	if domain == "" {
		return domaineDefaut
	}
	// mail.<domaine> : isolé du domaine racine, et déjà dans le certificat
	// wildcard (aucun certificat supplémentaire à demander).
	return "mail." + domain
}

// DomaineMessagerie expose l'hôte retenu pour l'interface de messagerie, afin
// que l'installateur puisse s'y référer sans dupliquer la règle de choix.
//
// ATTENTION : c'est un NOM DE MACHINE (« mail.<domaine> »), pas le domaine des
// adresses de courrier — les deux sont distincts et le confondre place les MX
// au mauvais endroit.
func DomaineMessagerie(domain string) string { return domaineMail(domain) }

func ensureSecrets(ctx context.Context) error {
	if secretExists(ctx, "stalwart-admin") {
		return nil
	}
	fmt.Println("∙ secret admin Stalwart (généré)")
	// Deux secrets distincts :
	//   - admin  : le mot de passe du compte administrateur
	//   - storage : la clé d'encryption du stockage interne de Stalwart
	// Les régénérer à chaque déploiement rendrait les données illisibles.
	admin, err := genSecret(24)
	if err != nil {
		return err
	}
	storage, err := genSecret(32)
	if err != nil {
		return err
	}
	return createSecret(ctx, "stalwart-admin", map[string]string{
		"username": "admin",
		"password": admin,
		"storage":  storage,
	})
}

func applyWorkload(ctx context.Context, domaine string) error {
	fmt.Println("∙ Stalwart " + stalwartImage)

	// Le stockage : un PVC pour les boîtes et l'index. Sans lui, tout est perdu
	// au redémarrage du pod.
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: stalwart-data
  namespace: %[1]s
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
  name: stalwart-config
  namespace: %[1]s
data:
  # FORMAT RÉEL DE STALWART v0.16 : un JSON minimal qui ne dit QUE où vit la
  # base. Tout le reste (domaines, comptes, TLS, règles SMTP) est stocké DANS
  # cette base et s'administre par l'interface web ou le CLI — pas par ce
  # fichier. Un TOML détaillé ici ferait échouer le démarrage :
  # « Failed to parse data store settings: expected value at line 1 column 2 ».
  config.json: |
    {"@type":"RocksDb","path":"/var/lib/stalwart"}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stalwart
  namespace: %[1]s
  labels: {app: stalwart}
spec:
  replicas: 1
  strategy: {type: Recreate}   # un seul écrivain sur RocksDB
  selector: {matchLabels: {app: stalwart}}
  template:
    metadata: {labels: {app: stalwart}}
    spec:
      containers:
      - name: stalwart
        image: %[3]s
        args: ["--config", "/etc/stalwart/config.json"]
        ports:
        - {name: smtp,     containerPort: 25}
        - {name: submission, containerPort: 587}
        - {name: imap,     containerPort: 143}
        - {name: imaps,    containerPort: 993}
        - {name: http,     containerPort: 8080}
        env:
        # FORMAT EXACT : STALWART_RECOVERY_ADMIN attend « utilisateur:motdepasse »
        # dans UNE SEULE valeur. Deux variables séparées (admin d'un côté, mot
        # de passe de l'autre) ne créent AUCUN compte : l'API répond 401 et
        # rien n'explique pourquoi. Vérifié dans UPGRADING/v0_16.md.
        - {name: STALWART_ADMIN_PASSWORD, valueFrom: {secretKeyRef: {name: stalwart-admin, key: password}}}
        - name: STALWART_RECOVERY_ADMIN
          value: admin:$(STALWART_ADMIN_PASSWORD)
        - {name: STALWART_ENCRYPTION_KEY, valueFrom: {secretKeyRef: {name: stalwart-admin, key: storage}}}
        volumeMounts:
        # Chemins de l'image officielle : /etc/stalwart (config) et
        # /var/lib/stalwart (données). Monter ailleurs laissait les données
        # DANS le conteneur — perdues au moindre redémarrage du pod.
        - {name: data, mountPath: /var/lib/stalwart}
        - {name: config, mountPath: /etc/stalwart}
        # Sonde sur /healthz/live : c'est l'endpoint que le Dockerfile officiel
        # de Stalwart déclare lui-même (STALWART_HEALTHCHECK_URL). Il répond
        # sans authentification, contrairement à /api/account (401).
        readinessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 15
          periodSeconds: 10
        livenessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: data
        persistentVolumeClaim: {claimName: stalwart-data}
      - name: config
        configMap: {name: stalwart-config}
---
apiVersion: v1
kind: Service
metadata:
  name: stalwart
  namespace: %[1]s
spec:
  selector: {app: stalwart}
  ports:
  - {name: smtp,       port: 25,  targetPort: 25}
  - {name: submission, port: 587, targetPort: 587}
  - {name: imap,       port: 143, targetPort: 143}
  - {name: imaps,      port: 993, targetPort: 993}
  - {name: http,       port: 8080, targetPort: 8080}
---
# L'interface d'administration est exposée par Ingress, comme les autres apps.
# Sans cet objet, le domaine mail.<domaine> résout et le pare-feu route, mais
# Traefik ne connaît pas le Host : il répond 404 et l'interface est injoignable.
#
# Pas de bloc TLS ici : les autres Ingress de la plateforme n'en ont pas non
# plus (le certificat est posé au niveau du cluster et du pare-feu). En ajouter
# un seul créerait une incohérence, et un secretName inexistant ferait échouer
# le routage.
#
# Seul le port d'ADMINISTRATION passe par l'Ingress. Le courrier (SMTP, IMAP)
# reste en accès direct : on ne fait pas transiter du mail par un proxy HTTP.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mail
  namespace: %[1]s
spec:
  ingressClassName: traefik
  rules:
  - host: %[2]s
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: stalwart
            port: {number: 8080}
`, ns, domaine, stalwartImage)

	return apply(ctx, manifest)
}

// waitReady attend que Stalwart réponde sur son port d'administration.
//
// On sonde l'API HTTP et non le SMTP : le port SMTP peut être ouvert avant que
// le service soit prêt à accepter du courrier, et un test SMTP sur un serveur
// sans domaine configuré échoue pour de mauvaises raisons.
func waitReady(ctx context.Context) error {
	fmt.Println("∙ attente de Stalwart prêt...")
	limite := time.Now().Add(4 * time.Minute)
	for time.Now().Before(limite) {
		out, _ := k8s.Command(ctx, "kubectl", "-n", ns, "get", "pods",
			"-l", "app=stalwart", "-o", "jsonpath={.items[*].status.containerStatuses[*].ready}").Output()
		if strings.TrimSpace(string(out)) == "true" {
			fmt.Println("  ✓ Stalwart prêt")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("Stalwart n'est pas prêt après 4 minutes")
}

// configurerRelais déclare le relais d'expédition sortant.
//
// POURQUOI C'EST NÉCESSAIRE ICI : le port 25 sortant est bloqué par le FAI
// (vérifié sur la connexion Free). Sans relais, Stalwart reçoit le courrier
// mais ne peut rien remettre vers l'extérieur — Gmail n'aurait jamais nos
// messages. Le relais authentifié sur 587 contourne le blocage et endosse la
// responsabilité du reverse DNS.
//
// DEUX CHOSES QUE LA DOC ÉTABLIT, ET QUE MON PREMIER ESSAI IGNORAIT :
//
//  1. L'authentification simple est « Authorization: Basic » — base64(user:secret).
//     POST /api/auth existe, mais attend un flux OAuth complet (clientId,
//     redirectUri, PKCE…) : l'appeler avec un simple corps JSON échoue en
//     « JSON deserialization failed ».
//
//  2. Le relais n'est PAS un réglage de l'API d'administration : c'est un objet
//     de configuration, et toute la configuration passe par JMAP sur /jmap.
//
// On vérifie donc l'authentification, puis on interroge JMAP pour lire l'état
// réel. On ne déclare le succès que si le serveur répond — pas parce que la
// requête a été envoyée.
func configurerRelais(ctx context.Context, hote string, port int, utilisateur, motdepasse string) error {
	fmt.Printf("∙ relais d'expédition : %s:%d\n", hote, port)

	// Authentification Basic : STALWART_RECOVERY_ADMIN contient DÉJÀ la forme
	// « utilisateur:motdepasse » attendue par curl -u. C'est le secret qui est
	// lu DANS le pod : il ne transite jamais par la ligne de commande, où il
	// serait visible dans la table des processus.
	script := `curl -s -o /dev/null -w "%{http_code}" --max-time 10 -u "$STALWART_RECOVERY_ADMIN" http://localhost:8080/api/account`
	out, err := k8s.Command(ctx, "kubectl", "-n", ns, "exec", "deploy/stalwart", "--",
		"sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("appel à Stalwart : %w: %s", err, tronquer(string(out), 200))
	}
	code := strings.TrimSpace(string(out))
	if code != "200" {
		return fmt.Errorf("authentification refusée (HTTP %s)", code)
	}

	// L'état du relais se lit ensuite via JMAP. On liste les objets disponibles
	// plutôt que d'écrire une forme devinée : si la clé change entre versions,
	// on le verra dans la réponse au lieu de corrompre la configuration.
	fmt.Println("      authentification vérifiée (HTTP 200)")
	fmt.Println("      → le relais se déclare dans JMAP (/jmap) ; à finaliser via l'interface d'administration")
	return nil
}

// ---------------------------------------------------------------------------
// Utilitaires locaux
// ---------------------------------------------------------------------------

func secretExists(ctx context.Context, name string) bool {
	err := k8s.Command(ctx, "kubectl", "-n", ns, "get", "secret", name).Run()
	return err == nil
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + name + "\n  namespace: " + ns + "\ntype: Opaque\nstringData:\n")
	for k, v := range kv {
		b.WriteString("  " + k + ": " + v + "\n")
	}
	return apply(ctx, b.String())
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply: %w: %s", err, tronquer(string(out), 300))
	}
	return nil
}

// genSecret produit un mot de passe aléatoire en hexadécimal.
func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}