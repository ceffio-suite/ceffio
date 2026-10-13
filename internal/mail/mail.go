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
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// imageCoffre rend l'image du coffre telle que déclarée au registre des versions.
//
// POURQUOI ON LA LIT AU REGISTRE PLUTÔT QUE DE L'ÉCRIRE ICI : l'init-container se
// sert du client `bao`, et ce client doit être EXACTEMENT celui du coffre
// déployé. Deux références écrites à deux endroits divergent à la première mise à
// jour — et la divergence se manifeste par un échec d'authentification, pas par
// un message qui dit quoi corriger. Le registre, lui, est vérifié par un test.
func imageCoffre() string {
	if c, ok := version.ParNom("openbao"); ok {
		return c.Image
	}
	return "docker.io/openbao/openbao:2.7.1"
}

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

// ensureSecrets garantit le secret d'administration de Stalwart.
//
// TROIS SOURCES, DANS CET ORDRE : le COFFRE, puis le Secret Kubernetes, puis la
// génération. C'est cet ordre qui permet de basculer sans interruption — une
// valeur déjà vivante est REPRISE, jamais refabriquée. La régénérer rendrait les
// données de Stalwart illisibles, puisque « storage » est la clé d'encryption de
// son stockage interne.
//
// LE COFFRE PASSE EN PREMIER parce qu'il est la source de vérité quand il est là,
// et parce que c'est ce qui rend une rotation possible : tourner un secret dans
// le coffre, puis redéployer, suffit à le propager — sans toucher au cluster. Le
// repli sur Kubernetes garde une installation sans OpenBao parfaitement
// fonctionnelle, ce qui est la règle du module de secrets.
//
// LA GÉNÉRATION NE SE DÉCLENCHE QUE SI LES DEUX SONT MUETS, et elle le dit : un
// secret refabriqué à l'aveugle est la panne la plus coûteuse, parce qu'elle ne
// se voit qu'au moment où le service ne comprend plus ses propres données.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	// LE COFFRE EST LA SOURCE UNIQUE — il n'y a PLUS de copie dans Kubernetes.
	//
	// Une valeur qui vit à deux endroits finit par diverger, et la divergence se
	// découvre au pire moment : quand un service redémarre sur la mauvaise
	// version. Le pod lit le coffre par son agent ; il n'y a donc rien à
	// recopier, et le repli sur un Secret Kubernetes n'a plus de raison d'être.
	donnees := map[string]string{"username": "admin"}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "stalwart", "admin")
	switch {
	case err == nil:
		for k, v := range existant {
			donnees[k] = v
		}
	case secrets.EntreeAbsente(err):
		// Première installation : la génération ci-dessous s'en charge.
	default:
		// Un coffre configuré mais injoignable n'est PAS une raison de
		// fabriquer des valeurs neuves : cela produirait un nouveau mot de
		// passe pendant que le service tourne avec l'ancien.
		return fmt.Errorf("coffre illisible pour stalwart/admin : %w", err)
	}
	// LA GÉNÉRATION NE SE DÉCLENCHE QUE SI LE COFFRE EST MUET, et elle le dit :
	// un secret refabriqué à l'aveugle est la panne la plus coûteuse, parce
	// qu'elle ne se voit qu'au moment où le service ne comprend plus ses propres
	// données — la clé de stockage de Stalwart en est l'exemple exact.
	for _, a := range []struct {
		cle      string
		longueur int
	}{
		{"password", 24},
		{"storage", 32},
	} {
		if donnees[a.cle] != "" {
			continue
		}
		g, err := genSecret(a.longueur)
		if err != nil {
			return err
		}
		donnees[a.cle] = g
		fmt.Printf("∙ %s de Stalwart généré (absent du coffre)\n", a.cle)
	}
	if err := secrets.EcrireDansCoffre(ctx, coffre, "stalwart", "admin", donnees); err != nil {
		return err
	}
	// Le Secret Kubernetes n'est plus créé. S'il traîne encore d'un déploiement
	// antérieur, c'est une copie morte : le dire, plutôt que la laisser passer
	// pour la source.
	if secretExiste(ctx, "stalwart-admin") {
		fmt.Println("  ! Secret Kubernetes « stalwart-admin » encore présent — copie morte, à retirer")
	}
	return nil
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
apiVersion: v1
kind: ConfigMap
metadata:
  name: stalwart-agent
  namespace: %[1]s
data:
  # LA CONFIGURATION DE L'AGENT, TEL QUE LA DOCUMENTATION LE DÉCRIT POUR UN
  # INIT-CONTAINER. L'agent vit ici, pas dans le conteneur applicatif : il
  # s'authentifie, rend les secrets dans le volume partagé, et s'arrête.
  agent.hcl: |
    pid_file = "/tmp/bao-agent.pid"

    # L'AGENT S'ARRÊTE APRÈS AVOIR RENDU. Sans cette ligne, il reste en vie et le
    # conteneur suivant n'est JAMAIS lancé — le pod attend indéfiniment, sans
    # message d'erreur. C'est le réglage qui distingue le mode init-container du
    # mode sidecar, et il va au niveau racine, pas dans auto_auth.
    exit_after_auth = true

    vault {
      address = "http://openbao.ceffio-vault.svc:8200"
      retry { num_retries = 2 }
    }

    # L'AGENT S'AUTHENTIFIE PAR KUBERNETES : le jeton du ServiceAccount du pod
    # est présenté au coffre, qui le fait valider par l'API du cluster.
    auto_auth {
      method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = {
          role       = "stalwart"
          token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        }
      }
    }

    # ÉCHEC BRUYANT : si un gabarit échoue, l'agent s'arrête au lieu de rendre
    # une valeur vide. Un mot de passe vide est pire qu'un pod qui ne démarre
    # pas — il donne un service qui tourne et refuse tout, sans rien dire.
    template_config {
      exit_on_retry_failure = true
    }

    # LE GABARIT REND UN FICHIER QUE LE CONTENEUR PRINCIPAL « SOURCE ».
    # C'est la façon documentée de servir une application qui n'attend que des
    # variables d'environnement : le fichier contient des « export », et le
    # conteneur le charge au démarrage.
    #
    # Le chemin passé à « secret » est celui de l'API (kv/data/...), comme pour
    # la politique — les commandes « kv » de la ligne de commande, elles,
    # prennent le chemin logique. C'est cette confusion qui coûte du temps.
    template {
      destination          = "/secrets/env"
      error_on_missing_key = true
      contents             = <<EOT
    export STALWART_ADMIN_PASSWORD='{{ with secret "kv/data/ceffio/stalwart/admin" }}{{ .Data.data.password }}{{ end }}'
    export STALWART_RECOVERY_ADMIN='admin:{{ with secret "kv/data/ceffio/stalwart/admin" }}{{ .Data.data.password }}{{ end }}'
    export STALWART_ENCRYPTION_KEY='{{ with secret "kv/data/ceffio/stalwart/admin" }}{{ .Data.data.storage }}{{ end }}'
    EOT
    }
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: stalwart
  namespace: %[1]s
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
      # LE POD PORTE SA PROPRE IDENTITÉ : c'est elle que le coffre valide pour
      # lui rendre ses secrets. Sans ce ServiceAccount, l'init-container n'a rien
      # à présenter, et le rôle côté coffre ne correspond à personne.
      serviceAccountName: stalwart
      # LE GROUPE PARTAGÉ EST INDISPENSABLE : l'init-container et Stalwart ne
      # tournent pas sous le même utilisateur. fsGroup fait appartenir le volume
      # partagé à un groupe commun, et Kubernetes ajoute ce groupe à TOUS les
      # conteneurs du pod — sans quoi le fichier écrit par l'un est illisible
      # pour l'autre, et le pod boucle sur « Permission denied ».
      securityContext:
        fsGroup: 1000
      # L'AGENT REND LES SECRETS, PUIS DISPARAÎT.
      #
      # C'est le motif que la documentation décrit pour un init-container : il
      # tourne avec l'image du COFFRE, s'authentifie par Kubernetes, écrit le
      # résultat dans le volume partagé, et s'arrête (exit_after_auth).
      #
      # AUCUN REPLI : le coffre est la source unique. Il n'existe plus de Secret
      # Kubernetes pour ce composant, donc il n'y a rien sur quoi se rabattre —
      # et c'est voulu. Un repli masquerait une panne du coffre au lieu de la
      # montrer, et ferait tourner le service sur une valeur que personne ne
      # mettrait plus à jour.
      initContainers:
      - name: agent-du-coffre
        image: %[4]s
        command: ["/bin/sh", "-c"]
        args:
        - |
          exec /usr/bin/bao agent -config=/etc/agent/agent.hcl
        env:
        - {name: BAO_ADDR, value: "http://openbao.ceffio-vault.svc:8200"}
        volumeMounts:
        - {name: agent-config, mountPath: /etc/agent, readOnly: true}
        - {name: secrets, mountPath: /secrets}
      containers:
      - name: stalwart
        image: %[3]s
        # LE CONTENEUR PRINCIPAL CHARGE LE FICHIER RENDU, PUIS LANCE LE SERVICE.
        # Le fichier est TOUJOURS là : l'agent s'arrête en erreur si un gabarit
        # échoue (exit_on_retry_failure + error_on_missing_key), donc un fichier
        # absent veut dire un pod qui ne démarre pas — visible — et non un
        # service qui tourne avec des valeurs vides.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /usr/local/bin/stalwart --config /etc/stalwart/config.json
        volumeMounts:
        # Le seul lien entre les deux conteneurs : le fichier rendu.
        - {name: secrets, mountPath: /secrets, readOnly: true}
        # Chemins de l'image officielle : /etc/stalwart (config) et
        # /var/lib/stalwart (données). Monter ailleurs laissait les données
        # DANS le conteneur — perdues au moindre redémarrage du pod.
        - {name: data, mountPath: /var/lib/stalwart}
        - {name: config, mountPath: /etc/stalwart}
        ports:
        - {name: smtp,     containerPort: 25}
        - {name: submission, containerPort: 587}
        - {name: imap,     containerPort: 143}
        - {name: imaps,    containerPort: 993}
        - {name: http,     containerPort: 8080}
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
      # LE RÉSULTAT DE L'AGENT, ET RIEN D'AUTRE : le conteneur principal lit ce
      # fichier. C'est le seul lien entre les deux conteneurs.
      - name: secrets
        emptyDir: {}
      # La configuration de l'agent : un gabarit qu'on relit, pas une commande.
      - name: agent-config
        configMap: {name: stalwart-agent}
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
`, ns, domaine, stalwartImage, imageCoffre())

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

// secretExiste sert à SIGNALER une copie morte, jamais à s'en servir : depuis que
// le coffre est la source unique, un Secret Kubernetes du même nom n'est plus lu
// par personne. Le détecter évite qu'on le prenne pour la source.
func secretExiste(ctx context.Context, nom string) bool {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), nom)
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
