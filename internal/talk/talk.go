// Package talk déploie Nextcloud Talk avec son High Performance Backend (HPB).
//
// POURQUOI CE MODULE : Talk remplace à la fois le chat (ex-Synapse/Element) et
// la visioconférence (ex-Jitsi). C'est une application Nextcloud — donc
// l'authentification est native (celle de Nextcloud, elle-même branchée sur
// Keycloak) et il n'y a plus aucun pont d'authentification à maintenir.
//
// ARCHITECTURE — quatre services, tous dans le namespace ceffio-video :
//
//	Talk          app Nextcloud (activée par « occ app:enable spreed »)
//	signaling     coordination : qui est là, qui rejoint quoi (Go, léger)
//	Janus         SFU : transporte le média WebRTC (c'est lui qui compte)
//	NATS          messagerie entre instances de signaling (scalabilité)
//	coturn        relais TURN : indispensable aux réseaux restrictifs
//
// Correspondance avec l'ancienne pile Jitsi, pour qui la connaît :
//
//	Interface        Jitsi Meet      → Talk
//	Coordination     Prosody (XMPP)  → signaling + NATS
//	Transport média  JVB (SFU)       → Janus
//	coturn           intégré         → service séparé
//
// ISOLATION : Ceffio et AgenTorch ne partagent AUCUNE ressource réseau — ni
// plage média, ni port TURN, ni secret. Voir docs/plan-talk-hpb.md §4bis.
package talk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Versions épinglées. Rien ne suit `latest` : un composant qui suit un tag
// mouvant ne peut être ni audité ni mis à niveau de façon reproductible.
const (
	ns = "ceffio-video"

	// Images du HPB.
	signalingImage = "docker.io/strukturag/nextcloud-spreed-signaling:2.1.1"
	janusImage     = "ghcr.io/ceffio-suite/janus-gateway:1.4.0-1"
	natsImage      = "docker.io/library/nats:2.15"
	coturnImage    = "docker.io/coturn/coturn:4.18"

	// Serveur STUN chargé de découvrir l'adresse publique que Janus doit
	// annoncer, quand elle n'est pas fournie au déploiement.
	//
	// PUBLIC, impérativement : un serveur du réseau local (coturn, par exemple)
	// voit la requête arriver depuis l'intérieur et répond l'adresse PRIVÉE —
	// mesuré : « Our public address is 192.168.1.48 ». La détection « réussit »
	// alors en annonçant une adresse injoignable depuis Internet.
	//
	// L'entrypoint de l'image résout ce nom en IPv4 avant de l'écrire dans la
	// configuration : laissé en nom d'hôte, Janus le résout en IPv6 sur une
	// machine double-pile et n'annonce qu'une adresse IPv6.
	stunPublic = "stun.l.google.com"
	stunPort   = 19302

	// Réseau — ports DÉDIÉS à Ceffio, sans chevauchement avec AgenTorch
	// (qui occupe 50000-60000, 30000-40000 et 3478).
	plageMediaDebut = 20000
	plageMediaFin   = 20100 // 100 ports : largement suffisant pour une PME
	portTurn        = 3479  // 3478 = AgenTorch, ne pas y toucher
	portTurnTLS     = 5349
	portSignaling   = 8081 // HTTP interne du signaling server
	portJanusAPI    = 8088 // API HTTP de Janus (utilisée par le signaling)
	portJanusWS     = 8188 // transport WebSocket de Janus
)

// Deploy installe Talk + HPB, de façon idempotente.
//
// AUCUNE ADRESSE PUBLIQUE N'EST DEMANDÉE, et c'est délibéré : elle est
// nécessaire à trois endroits (les candidats ICE de Janus, ceux du relais
// coturn, et l'adresse TURN que le signaling remet aux navigateurs), mais
// aucun n'a besoin qu'on la lui fournisse.
//
//   - Janus et coturn la découvrent eux-mêmes au démarrage, par STUN, avec le
//     client présent dans leurs images respectives ;
//   - le signaling annonce un NOM public (talk.<domaine>), qui survit à un
//     changement d'adresse là où une valeur figée cesserait de fonctionner
//     sans rien dire.
//
// Un paramètre à connaître AVANT de déployer était une dépendance inutile, et
// une valeur en dur dans l'installation est une panne différée.
func Deploy(ctx context.Context) error {
	fmt.Println("\nDéploiement de Talk + High Performance Backend (Phase 10)...")

	// 1. Secrets d'abord : les Deployments les référencent.
	if err := ensureSecrets(ctx); err != nil {
		return err
	}
	if err := deployAgent(ctx); err != nil {
		return err
	}
	if err := deployNATS(ctx); err != nil {
		return err
	}
	// coturn AVANT Janus : Janus le référence comme serveur STUN/TURN.
	if err := deployCoturn(ctx); err != nil {
		return err
	}
	if err := ensurePullSecret(ctx); err != nil {
		return err
	}
	if err := deployJanus(ctx); err != nil {
		return err
	}
	if err := deploySignaling(ctx); err != nil {
		return err
	}
	// 2. Raccorder Nextcloud au HPB (via occ, jamais à la main).
	if err := brancherNextcloud(ctx); err != nil {
		return err
	}

	fmt.Println("✓ Talk + HPB déployés (messagerie et visioconférence dans Nextcloud)")
	return nil
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// ensureSecrets garantit les secrets du HPB DANS LE COFFRE, ET NULLE PART AILLEURS.
//
// Ils ne sont JAMAIS dans les manifests ni dans Git. Depuis que le coffre est la
// source unique, ils ne sont plus non plus dans un Secret Kubernetes : les deux
// charges qui les consomment — coturn et le signaling — les lisent par leur agent
// au démarrage. Une valeur recopiée à deux endroits finit par diverger, et la
// divergence se paie au moment où le service ne comprend plus ses propres données.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	donnees := map[string]string{}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "talk", "signaling")
	switch {
	case err == nil:
		donnees = existant
	case secrets.EntreeAbsente(err):
		// Première installation : la génération ci-dessous s'en charge.
	default:
		// Un coffre injoignable n'est pas une raison de fabriquer des valeurs
		// neuves : les clients raccordés continueraient avec les anciennes, et
		// plus rien ne se comprendrait.
		return fmt.Errorf("coffre illisible pour talk/signaling : %w", err)
	}

	for _, a := range []struct {
		cle      string
		longueur int
	}{
		{"hash-key", 32},
		{"block-key", 16},
		{"partage", 32},
		{"turn-secret", 32},
	} {
		if donnees[a.cle] != "" {
			continue
		}
		g, err := genSecret(a.longueur)
		if err != nil {
			return err
		}
		donnees[a.cle] = g
		fmt.Printf("∙ secret Talk « %s » généré (absent du coffre)\n", a.cle)
	}
	return secrets.EcrireDansCoffre(ctx, coffre, "talk", "signaling", donnees)
}

// ---------------------------------------------------------------------------
// Agent du coffre
// ---------------------------------------------------------------------------

// deployAgent pose ce qui est commun aux deux charges qui lisent le coffre : le
// ServiceAccount que le coffre valide, et la configuration de l'agent.
//
// POURQUOI UNE SEULE CONFIGURATION POUR DEUX CHARGES : coturn et le signaling
// lisent la MÊME entrée du coffre, donc leurs gabarits sont identiques. Un
// fichier dupliqué finirait par diverger de l'autre — et la divergence, ici,
// ferait que le signaling et Nextcloud ne partageraient plus le même secret.
func deployAgent(ctx context.Context) error {
	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: talk
  namespace: %[1]s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: talk-agent
  namespace: %[1]s
data:
  # L'AGENT S'ARRÊTE APRÈS AVOIR RENDU — c'est ce qui en fait un init-container.
  # « index » EST OBLIGATOIRE POUR LES CLÉS À TIRET : « .Data.data.hash-key »
  # n'est pas une expression valide en syntaxe Go, le tiret étant un opérateur.
  # L'erreur de rendu ne dit pas cela ; elle parle de gabarit invalide.
  agent.hcl: |
    pid_file = "/tmp/bao-agent.pid"

    exit_after_auth = true

    vault {
      address = "http://openbao.ceffio-vault.svc:8200"
      retry { num_retries = 2 }
    }

    auto_auth {
      method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = {
          role       = "talk"
          token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        }
      }
    }

    template_config {
      exit_on_retry_failure = true
    }

    template {
      destination          = "/secrets/env"
      error_on_missing_key = true
      contents             = <<EOT
    export HASH_KEY='{{ with secret "kv/data/ceffio/talk/signaling" }}{{ index .Data.data "hash-key" }}{{ end }}'
    export BLOCK_KEY='{{ with secret "kv/data/ceffio/talk/signaling" }}{{ index .Data.data "block-key" }}{{ end }}'
    export SHARED_SECRET='{{ with secret "kv/data/ceffio/talk/signaling" }}{{ index .Data.data "partage" }}{{ end }}'
    export TURN_SECRET='{{ with secret "kv/data/ceffio/talk/signaling" }}{{ index .Data.data "turn-secret" }}{{ end }}'
    EOT
    }
`, ns)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// NATS
// ---------------------------------------------------------------------------

func deployNATS(ctx context.Context) error {
	fmt.Println("∙ NATS " + natsImage + " (coordination du signaling)")
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nats
  namespace: %[1]s
  labels: {app: nats}
spec:
  replicas: 1
  selector: {matchLabels: {app: nats}}
  template:
    metadata: {labels: {app: nats}}
    spec:
      containers:
      - name: nats
        image: %[2]s
        ports:
        - {name: client, containerPort: 4222}
        resources: {limits: {memory: 256Mi, cpu: 500m}}
---
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: %[1]s
spec:
  selector: {app: nats}
  ports:
  - {name: client, port: 4222, targetPort: 4222}
`, ns, natsImage)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// coturn
// ---------------------------------------------------------------------------

// deployCoturn déploie le relais TURN.
//
// Il sert à DEUX choses :
//  1. relais média pour les utilisateurs dont le réseau bloque l'UDP direct
//     (4G d'entreprise, réseaux d'hôtel) — sans lui, ils n'ont aucun chemin ;
//  2. serveur STUN pour Janus, qui peut alors découvrir seul son adresse
//     publique (détection automatique, à activer).
//
// Le secret d'authentification est partagé avec le signaling server, qui
// génère les identifiants TURN temporaires pour les clients.
func deployCoturn(ctx context.Context) error {
	fmt.Println("∙ coturn " + coturnImage + " (relais TURN, port " + fmt.Sprint(portTurn) + ")")

	// L'ADRESSE PUBLIQUE EST DÉCOUVERTE AU DÉMARRAGE, JAMAIS FIGÉE.
	//
	// coturn doit annoncer une adresse joignable depuis Internet dans ses
	// candidats de relais (option --external-ip). Sans elle, il annonce la
	// sienne, privée — mesuré : « UDP reflexive addr: 192.168.1.48 » — et un
	// participant derrière un NAT restrictif reçoit une adresse qu'il ne peut
	// pas joindre, exactement dans le cas où le relais sert à quelque chose.
	//
	// Mais cette adresse ne doit PAS figurer dans l'installation : elle change
	// (FAI, déménagement) et un déploiement qui la porte en dur cesse de
	// fonctionner sans rien dire le jour où elle change. Aucune valeur
	// d'infrastructure n'entre dans le dépôt.
	//
	// coturn la découvre donc lui-même au démarrage, avec le client STUN présent
	// dans son image, contre le même serveur que celui donné à Janus — une seule
	// source de vérité pour toute la plateforme.
	//
	// Si la détection échoue (UDP filtré), l'option est simplement omise : le
	// relais ne sert plus qu'à l'intérieur du réseau, ce qui vaut mieux qu'une
	// adresse inventée — et l'avertissement est explicite dans les journaux.
	// Aucune substitution de commande ni d'accolade dans ce script : Kubernetes
	// interprète $(...) et ${...} dans les arguments d'un conteneur, ce qui
	// abîmerait le script. On n'utilise que des variables simples et une
	// redirection vers un fichier temporaire.
	script := fmt.Sprintf(`turnutils_stunclient -p %[1]d %[2]s 2>&1 \
    | sed -n 's/.*UDP reflexive addr: \([0-9.]*\):.*/\1/p' \
    | head -1 > /tmp/adresse-publique.txt || true

ADRESSE=""
read ADRESSE < /tmp/adresse-publique.txt || true
ARG_EXTERNE=""
if [ -n "$ADRESSE" ]; then
    ARG_EXTERNE="--external-ip=$ADRESSE"
    echo "coturn: adresse publique detectee = $ADRESSE"
else
    echo "coturn: AVERTISSEMENT - adresse publique non detectee (STUN %[2]s:%[1]d injoignable)." >&2
    echo "coturn: les candidats de relais porteront l'adresse privee ;" >&2
    echo "coturn: le relais ne servira qu'a l'interieur du reseau." >&2
fi

exec turnserver \
    --realm=%[3]s \
    --use-auth-secret \
    --static-auth-secret="$TURN_SECRET" \
    --lt-cred-mech \
    --fingerprint \
    --no-software-attribute \
    --no-multicast-peers \
    --no-stdout-log \
    --log-file=stdout \
    --stale-nonce=600 \
    --min-port=49152 \
    --max-port=49200 \
    --listening-port=%[4]d \
    $ARG_EXTERNE
`, stunPort, stunPublic, "talk."+domaineDe(ctx), portTurn)

	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: coturn
  namespace: %[1]s
  labels: {app: coturn}
spec:
  # Recreate : même raison que Janus — pod en hostNetwork, donc ports de l'hôte
  # occupés. Voir le commentaire détaillé sur le déploiement de Janus.
  strategy: {type: Recreate}
  replicas: 1
  selector: {matchLabels: {app: coturn}}
  template:
    metadata: {labels: {app: coturn}}
    spec:
      # hostNetwork : même raison que Janus — la plage de relais TURN
      # (49152-49200) ne peut pas s'exprimer en NodePort, qui n'accepte qu'un
      # port unique. Le pod écoute donc directement sur l'IP de la VM.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      # L'IDENTITÉ QUE LE COFFRE VALIDE, et le groupe partagé qui rend le fichier
      # rendu lisible par le conteneur applicatif — les deux ne tournent pas sous
      # le même utilisateur.
      serviceAccountName: talk
      securityContext:
        fsGroup: 1000
      # L'AGENT REND TURN_SECRET, PUIS DISPARAÎT (exit_after_auth). Aucun repli :
      # c'est le coffre ou rien, et le pod ne démarre pas si le coffre ne répond
      # pas — visible, plutôt qu'un service qui tourne avec un secret vide.
      initContainers:
      - name: agent-du-coffre
        image: %[6]s
        # L'ENTRÉE DE CETTE IMAGE EST bao : on ne remplace QUE ses arguments.
        args: ["agent", "-config=/etc/agent/agent.hcl"]
        env:
        - {name: BAO_ADDR, value: "http://openbao.ceffio-vault.svc:8200"}
        volumeMounts:
        - {name: agent-config, mountPath: /etc/agent, readOnly: true}
        - {name: secrets, mountPath: /secrets}
      containers:
      - name: coturn
        image: %[2]s
        # Enveloppe de démarrage : elle charge les secrets rendus par l'agent,
        # découvre l'adresse publique, puis la transmet à coturn.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
%[3]s
        volumeMounts:
        - {name: secrets, mountPath: /secrets, readOnly: true}
        ports:
        - {name: turn, containerPort: %[4]d, protocol: UDP}
        - {name: turn-tcp, containerPort: %[4]d, protocol: TCP}
        - {name: turns, containerPort: %[5]d, protocol: TCP}
        resources: {limits: {memory: 1Gi, cpu: "1"}}
      volumes:
      # Le fichier rendu par l'agent : le seul lien entre les deux conteneurs.
      - name: secrets
        emptyDir: {}
      - name: agent-config
        configMap: {name: talk-agent}
---
# NodePort, PAS ClusterIP : ces ports doivent être joignables depuis Internet,
# via les règles de redirection du pare-feu vers l'IP de la VM. Un ClusterIP
# n'écoute que sur le réseau interne de k3s — les paquets arrivent à la VM et
# personne ne les prend (symptôme : tout est « Running », rien ne passe).
apiVersion: v1
kind: Service
metadata:
  name: coturn
  namespace: %[1]s
spec:
  selector: {app: coturn}
  ports:
  - {name: turn, port: %[4]d, targetPort: %[4]d, protocol: UDP}
  - {name: turn-tcp, port: %[4]d, targetPort: %[4]d, protocol: TCP}
  - {name: turns, port: %[5]d, targetPort: %[5]d, protocol: TCP}
`, ns, coturnImage, indentYaml(script, 10), portTurn, portTurnTLS, version.ImageDe("openbao"))
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Janus
// ---------------------------------------------------------------------------

// ensurePullSecret crée le secret d'authentification pour tirer l'image Janus
// depuis GHCR.
//
// POURQUOI UN SECRET DE TIRAGE : l'image Janus est publiée sur GHCR (dépôt
// privé). Kubernetes ne peut pas la tirer sans identifiants. On préfère un
// secret de tirage à un passage de l'image en public : l'image ne regarde
// personne, et le déployeur garde le contrôle de qui peut la récupérer.
//
// Le token est fourni par variable d'environnement au moment du déploiement
// (GHCR_TOKEN) — il n'est JAMAIS écrit dans le code ni dans un manifeste.
func ensurePullSecret(ctx context.Context) error {
	// L'EXISTENCE DU SECRET SE REGARDE AVANT LE JETON, pas après.
	//
	// Sinon toute ré-exécution sans la variable d'environnement échoue, alors que
	// le secret est déjà en place et suffit — et l'échec coupe le déploiement à
	// cet endroit : les composants suivants ne sont jamais appliqués, sans que
	// rien ne le dise. C'est exactement ce qui est arrivé au signaling de Talk.
	if secretExiste(ctx, "ghcr-pull") {
		return nil
	}
	token := os.Getenv("GHCR_TOKEN")
	if token == "" {
		return fmt.Errorf("GHCR_TOKEN absent : l'image Janus est sur GHCR (privé) et " +
			"le cluster doit pouvoir la tirer. Fournir un token avec read:packages")
	}
	fmt.Println("∙ secret de tirage GHCR créé")

	// Le fichier .dockerconfigjson attendu par Kubernetes.
	auth := base64.StdEncoding.EncodeToString([]byte("ceffio-suite:" + token))
	cfg := fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`, auth)

	manifeste := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: ghcr-pull
  namespace: %s
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: %s
`, ns, base64.StdEncoding.EncodeToString([]byte(cfg)))

	return appliquer(ctx, manifeste)
}

// deployJanus déploie le SFU.
//
// C'est le composant qui TRANSPORTE le média : chaque participant envoie son
// flux une fois, Janus le redistribue à tous. Sans lui, Talk plafonne à ~4-6
// participants (connexions directes entre navigateurs).
func deployJanus(ctx context.Context) error {
	fmt.Printf("∙ Janus %s (SFU, média UDP %d-%d)\n", janusImage, plageMediaDebut, plageMediaFin)

	// L'ADRESSE PUBLIQUE EST DÉCOUVERTE PAR JANUS LUI-MÊME, AU DÉMARRAGE.
	//
	// Janus doit annoncer aux navigateurs une adresse qu'ils peuvent joindre.
	// Derrière un NAT ses interfaces sont privées : s'il les annonce telles
	// quelles dans les candidats ICE, le média ne passe jamais depuis Internet.
	//
	// Elle n'est PAS fournie au déploiement : un paramètre à connaître avant de
	// déployer est une dépendance, et une valeur en dur cesse de fonctionner
	// sans rien dire le jour où le FAI change l'adresse. Janus interroge donc un
	// serveur STUN PUBLIC au démarrage et annonce l'adresse qu'il en déduit.
	//
	// Le serveur STUN DOIT être joignable depuis Internet. Pointé sur coturn,
	// qui tourne sur le même réseau, il renvoie l'adresse PRIVÉE — mesuré :
	// « Our public address is 192.168.1.48 ». La détection « réussit » alors en
	// annonçant une adresse injoignable, ce qui est pire qu'un échec franc.
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: janus
  namespace: %[1]s
  labels: {app: janus}
spec:
  # Recreate, PAS RollingUpdate. Le pod est en hostNetwork : il occupe les
  # ports de la VM (média 20000-20100, API 8088, WS 8188). Un déploiement
  # progressif est alors IMPOSSIBLE — le nouveau pod ne peut pas démarrer tant
  # que l'ancien tient ces ports, et l'ancien n'est retiré qu'une fois le
  # nouveau prêt. Mesuré : « FailedScheduling: 1 node(s) didn't have free ports
  # for the requested pod ports », déploiement bloqué indéfiniment.
  strategy: {type: Recreate}
  replicas: 1
  selector: {matchLabels: {app: janus}}
  template:
    metadata: {labels: {app: janus}}
    spec:
      # hostNetwork : le pod sort directement sur l'IP de la VM, sans passer par
      # kube-proxy. Indispensable pour le MÉDIA : un ServiceNodePort ne peut
      # exposer qu'UN port, pas une plage de 101 ports. Le média WebRTC a besoin
      # de toute la plage 20000-20100 ouverte de bout en bout, et le pare-feu
      # redirige vers l'IP de la VM — donc le pod doit écouter sur cette IP.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      imagePullSecrets:
      - name: ghcr-pull
      containers:
      - name: janus
        image: %[2]s
        env:
        - {name: JANUS_RTP_PORT_RANGE, value: "%[4]d-%[5]d"}
        # Serveur STUN PUBLIC : source de l'adresse publique annoncée aux
        # navigateurs. L'entrypoint le résout en IPv4 (un nom d'hôte résolu en
        # IPv6 ferait annoncer une adresse IPv6, injoignable en IPv4).
        - {name: JANUS_STUN_SERVER, value: %[7]q}
        - {name: JANUS_STUN_PORT, value: "%[8]d"}
        ports:
        - {name: api, containerPort: 8088, protocol: TCP}
        - {name: ws, containerPort: 8188, protocol: TCP}
        resources: {limits: {memory: 2Gi, cpu: "2"}}
---
# NodePort pour TOUTE la plage média : c'est le flux vidéo lui-même qui passe
# par là. Le signaling indique aux navigateurs ces ports (via l'adresse
# publique annoncée), qui doivent donc être ouverts de bout en bout — pare-feu
# ET Kubernetes.
apiVersion: v1
kind: Service
metadata:
  name: janus
  namespace: %[1]s
spec:
  selector: {app: janus}
  ports:
  - {name: api, port: 8088, targetPort: 8088, protocol: TCP}
  - {name: ws, port: 8188, targetPort: 8188, protocol: TCP}
`, ns, janusImage, "", plageMediaDebut, plageMediaFin, portTurn, stunPublic, stunPort)
	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Signaling server
// ---------------------------------------------------------------------------

// turnURL construit la liste des serveurs TURN remise AUX NAVIGATEURS par le
// serveur de signalisation.
//
// L'adresse doit être joignable depuis Internet, sinon le relais est
// inutilisable. On donne un NOM public plutôt qu'une adresse : il survit à un
// changement d'adresse publique, et c'est le même que celui déclaré côté
// Nextcloud. C'est le seul endroit où l'adresse publique apparaît, et elle y
// apparaît sous forme de nom, jamais de valeur figée.
func turnURL(domaine string) string {
	hote := "talk." + domaine
	udp := fmt.Sprintf("turn:%s:%d?transport=udp", hote, portTurn)
	tcp := fmt.Sprintf("turn:%s:%d?transport=tcp", hote, portTurn)
	return udp + "," + tcp
}

// deploySignaling déploie le serveur de signalisation.
//
// Rôle : dire aux participants qui est présent et où se connecter. Il ne
// transporte AUCUN média — c'est un routeur de métadonnées, très léger. C'est
// l'équivalent de Prosody dans la pile Jitsi, avec NATS pour la coordination.
//
// Deux réglages conditionnent le fait que les appels FONCTIONNENT réellement :
// la section de backend (sans elle, aucune connexion de client n'est acceptée)
// et l'adresse TURN remise aux navigateurs (sans elle, le relais est
// injoignable depuis Internet). Voir les commentaires dans la configuration.
func deploySignaling(ctx context.Context) error {
	fmt.Println("∙ signaling " + signalingImage + " (coordination, passe par Janus)")

	// Configuration : le signaling connaît Janus, NATS, et le secret partagé
	// avec Nextcloud (qui l'appelle pour authentifier les sessions).
	// Configuration du signaling. La structure N'EST PAS devinable : elle a été
	// relevée dans server.conf.in du dépôt upstream, après qu'une première
	// version écrite de mémoire ait échoué au démarrage (« hash key is not set »).
	//
	// Les trois erreurs évitées ici :
	//   - hashkey/blockkey vont dans [sessions], PAS dans [clients] ;
	//   - le secret applicatif s'appelle internalsecret ([clients]), et le nom
	//     du backend se déclare dans [backend] backends=... ;
	//   - il n'existe PAS de section [backend.<nom>] en mode static — c'est un
	//     réglage du mode etcd.
	config := fmt.Sprintf(`[http]
listen = 0.0.0.0:%[1]d

[app]
debug = false

# Clés de session : 32 octets exigés (le serveur refuse de démarrer sinon,
# avec un message explicite « hash key should be 32 or 64 bytes »).
[sessions]
hashkey = $(HASH_KEY)
blockkey = $(BLOCK_KEY)

# Secret partagé avec Nextcloud : c'est LUI qui authentifie les requêtes entre
# l'instance Nextcloud et ce serveur. Doit être identique des deux côtés.
[clients]
internalsecret = $(SHARED_SECRET)

# Coordination entre instances (une seule ici, mais NATS est requis).
[nats]
url = nats://nats:4222

# Le SFU : Janus, joint en WebSocket.
[mcu]
type = janus
url = ws://janus:8188

# Backend : l'instance Nextcloud qui nous appelle.
[backend]
backends = nextcloud
allowall = false
secret = $(SHARED_SECRET)

# LE BACKEND LUI-MÊME — SANS CETTE SECTION, AUCUN CLIENT NE PEUT SE CONNECTER.
#
# Le nom de section doit correspondre EXACTEMENT à un identifiant listé dans
# « backends » ci-dessus. Son absence ne produit pas d'erreur fatale : le
# serveur démarre, sert ses pages, accepte les requêtes — et refuse silencieusement
# toute connexion de client :
#
#   backend_storage_static.go:116: WARNING: No backends configured,
#     client connections will not be possible.
#
# Le symptôme est trompeur : l'appelant croit à un problème de média (TURN, ICE)
# alors que le serveur n'accepte aucune session. Les journaux de Nextcloud, eux,
# restent parfaitement normaux — les deux clients échangent présence et messages,
# seul le média ne s'établit jamais.
[nextcloud]
urls = https://cloud.%[3]s

# Relais TURN, avec identifiants temporaires générés par ce serveur.
#
# L'ADRESSE ICI EST CELLE QUE LES NAVIGATEURS VONT CONTACTER. Elle doit donc
# être joignable depuis Internet. Un nom interne au cluster (« coturn ») ne
# résout PAS dans le navigateur : le relais serait alors inutilisable dans le
# seul cas où il sert — le participant derrière un NAT restrictif.
#
# On utilise le nom public de la plateforme plutôt que l'adresse IP : il reste
# valable si l'adresse publique change. C'est le MÊME nom que celui déclaré
# côté Nextcloud pour ses propres serveurs TURN.
[turn]
apikey = $(SHARED_SECRET)
secret = $(TURN_SECRET)
servers = %[2]s
`, portSignaling, turnURL(domaineDe(ctx)), domaineDe(ctx))

	manifeste := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: talk-signaling-config
  namespace: %[1]s
data:
  server.conf: |
%[2]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: talk-signaling
  namespace: %[1]s
  labels: {app: talk-signaling}
spec:
  replicas: 1
  selector: {matchLabels: {app: talk-signaling}}
  template:
    metadata: {labels: {app: talk-signaling}}
    spec:
      # L'IDENTITÉ QUE LE COFFRE VALIDE, et le groupe partagé qui rend le fichier
      # rendu lisible — les deux conteneurs ne tournent pas sous le même
      # utilisateur.
      serviceAccountName: talk
      securityContext:
        fsGroup: 1000
      # L'AGENT REND LES SECRETS DU SIGNALING, PUIS DISPARAÎT.
      #
      # Le signaling attend quatre variables — HASH_KEY, BLOCK_KEY, SHARED_SECRET,
      # TURN_SECRET — dont les deux dernières doivent être IDENTIQUES à celles que
      # Nextcloud détient. Une seule source, donc : le coffre. Le raccordement
      # Nextcloud lit la même entrée.
      initContainers:
      - name: agent-du-coffre
        image: %[5]s
        # L'ENTRÉE DE CETTE IMAGE EST bao : on ne remplace QUE ses arguments.
        args: ["agent", "-config=/etc/agent/agent.hcl"]
        env:
        - {name: BAO_ADDR, value: "http://openbao.ceffio-vault.svc:8200"}
        volumeMounts:
        - {name: agent-config, mountPath: /etc/agent, readOnly: true}
        - {name: secrets, mountPath: /secrets}
      containers:
      - name: signaling
        image: %[3]s
        # Le fichier rendu est chargé AVANT le serveur : le signaling refuse de
        # démarrer sans ses clés de session (« hash key is not set »), donc un
        # secret manquant se voit tout de suite.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /usr/bin/nextcloud-spreed-signaling -config /config/server.conf
        volumeMounts:
        - {name: secrets, mountPath: /secrets, readOnly: true}
        - {name: config, mountPath: /config}
        ports:
        - {name: http, containerPort: %[4]d, protocol: TCP}
        resources: {limits: {memory: 512Mi, cpu: 500m}}
      volumes:
      - name: config
        configMap: {name: talk-signaling-config}
      # Le fichier rendu par l'agent : le seul lien entre les deux conteneurs.
      - name: secrets
        emptyDir: {}
      - name: agent-config
        configMap: {name: talk-agent}
---
apiVersion: v1
kind: Service
metadata:
  name: talk-signaling
  namespace: %[1]s
spec:
  selector: {app: talk-signaling}
  ports:
  - {name: http, port: %[4]d, targetPort: %[4]d, protocol: TCP}
`, ns, indentYaml(config, 4), signalingImage, portSignaling, version.ImageDe("openbao"))

	return appliquer(ctx, manifeste)
}

// ---------------------------------------------------------------------------
// Raccordement Nextcloud
// ---------------------------------------------------------------------------

// brancherNextcloud active l'application Talk et la raccorde au HPB.
//
// TOUT PASSE PAR « occ » : jamais de modification manuelle en base, jamais de
// fichier de configuration édité à la main. C'est la seule façon d'obtenir un
// état que Nextcloud considère comme cohérent.
func brancherNextcloud(ctx context.Context) error {
	fmt.Println("∙ activation de Talk + raccordement au HPB")

	// 1. Installer puis activer l'app (idempotent : « install » échoue si déjà
	//    présente, on l'ignore ; « enable » est sans effet si déjà activée).
	_ = occ(ctx, "app:install", "spreed")
	if err := occ(ctx, "app:enable", "spreed"); err != nil {
		return fmt.Errorf("activation de Talk : %w", err)
	}

	// 2. Déclarer le serveur de signalisation externe. Sans cette étape, Talk
	//    fonctionne en connexions directes (~4-6 participants) et ignore le HPB.
	url := fmt.Sprintf("https://spreed.%s/standalone-signaling", domaineDe(ctx))
	if err := occ(ctx, "config:app:set", "spreed", "signaling_server_url", "--value", url); err != nil {
		return fmt.Errorf("URL du signaling : %w", err)
	}

	// 3. Les secrets du signaling, LUS AU COFFRE — source unique depuis que les
	//    Secrets Kubernetes ont disparu. Le signaling lit la même entrée par son
	//    agent : les deux côtés ne peuvent pas diverger.
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "talk", "signaling")
	if err != nil {
		return fmt.Errorf("secrets Talk illisibles au coffre : %w", err)
	}
	secret := entree["partage"]
	if secret == "" {
		return fmt.Errorf("secret partagé absent de l'entrée talk/signaling du coffre")
	}
	if err := occ(ctx, "config:app:set", "spreed", "signaling_server_secret", "--value", secret); err != nil {
		return fmt.Errorf("secret du signaling : %w", err)
	}

	// 4. Déclarer les serveurs TURN (natifs, pas de dépendance externe).
	serveurs := fmt.Sprintf("turn:talk.%s:%d?transport=udp,turn:talk.%s:%d?transport=tcp",
		domaineDe(ctx), portTurn, domaineDe(ctx), portTurn)
	if err := occ(ctx, "config:app:set", "spreed", "turn_servers", "--value", serveurs); err != nil {
		return fmt.Errorf("serveurs TURN : %w", err)
	}
	turnSecret := entree["turn-secret"]
	if turnSecret == "" {
		return fmt.Errorf("secret TURN absent de l'entrée talk/signaling du coffre")
	}
	if err := occ(ctx, "config:app:set", "spreed", "turn_secret", "--value", turnSecret); err != nil {
		return fmt.Errorf("secret TURN : %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// occ exécute une commande occ dans le pod Nextcloud.
func occ(ctx context.Context, args ...string) error {
	complet := append([]string{"exec", "-n", "ceffio-files", "deploy/nextcloud", "--",
		"php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", complet...)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// domaineDe déduit le domaine de déploiement depuis les ingress existants.
//
// On ne le passe pas en paramètre : le seul hôte qui fait autorité est celui
// réellement configuré dans le cluster. Lire l'ingress évite de dupliquer une
// information qui pourrait diverger.
func domaineDe(ctx context.Context) string {
	cmd := k8s.Command(ctx, "kubectl", "get", "ingress", "-n", "ceffio-files", "cloud",
		"-o", "jsonpath={.spec.rules[0].host}")
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "ceffio.local"
	}
	h := strings.TrimSpace(string(out))
	if i := strings.Index(h, "."); i > 0 {
		return h[i+1:]
	}
	return h
}

func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(manifeste)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func secretExiste(ctx context.Context, nom string) bool {
	cmd := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns)
	cmd.Env = k8s.Env()
	return cmd.Run() == nil
}

func lireSecret(ctx context.Context, nom, cle string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns,
		"-o", "jsonpath={.data."+cle+"}")
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("lecture du secret %s/%s : %w", nom, cle, err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

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

// indentYaml indente un bloc de texte pour l'insérer dans un ConfigMap YAML.
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
