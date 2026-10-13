// Package vault déploie le coffre OpenBao de la suite Ceffio.
//
// POURQUOI CE MODULE, ET PAS SEULEMENT UN CLIENT : internal/secrets sait déjà
// LIRE et ÉCRIRE un coffre, mais il suppose qu'un coffre existe ailleurs et
// qu'on connaît son adresse. Or Ceffio est une suite qu'on installe chez
// quelqu'un : le coffre doit voyager AVEC la pile. Un produit qui exigerait que
// le client fournisse son propre serveur de secrets ne serait pas auto-portant.
// Ce module déploie donc le coffre comme un composant de la suite, au même titre
// que Keycloak ou Nextcloud.
//
// RELATION AVEC internal/secrets : c'est ce module qui pose l'adresse et le
// jeton que internal/secrets lira ensuite (BAO_ADDR / BAO_TOKEN). Les deux
// moitiés d'un même mécanisme : celui-ci CRÉE le coffre, l'autre le CONSOMME.
//
// PARLE AU CLUSTER PAR internal/k8sapi, ET UNIQUEMENT PAR LUI.
//
// Ce module a d'abord lancé `kubectl` et lu sa sortie. Cinq défauts en sont
// sortis, tous de la même famille — confondre « je n'ai pas pu demander » avec
// « on m'a répondu » :
//
//   - `kubectl run` mêle ses messages d'accompagnement à la sortie utile : une
//     clé de 32 octets est devenue un Secret de 309 caractères contenant
//     « pod deleted » et « if you don't see a command prompt » ;
//   - `CombinedOutput` fusionne les deux flux, et `kubectl exec` s'en accommode
//     mal : « failed to start exec » ;
//   - un message d'erreur analysé comme du JSON redevenait un objet vide, donc
//     un état plausible — et faux ;
//   - un outil absent de l'image (`curl`) transformait un échec d'exécution en
//     « coffre non initialisé » ;
//   - un jsonpath revenu vide n'a jamais pu être expliqué, précisément parce que
//     rien dans ce programme ne pouvait l'observer.
//
// L'API Kubernetes est TYPÉE : un Secret est un Secret, une erreur est une
// erreur. La classe entière de défauts disparaît avec l'intermédiaire.
//
// LE SECRET-ZÉRO, ET POURQUOI IL EST ICI : pour que le coffre soit utilisable
// sans intervention humaine, il se descelle tout seul, grâce au sceau
// « static » d'OpenBao : une clé de 32 octets lue depuis un fichier. Cette clé
// vit dans un Secret Kubernetes, sur la même machine que le coffre.
//
//	C'est un compromis assumé, pas un oubli.
//
// Qui obtient la machine obtient le coffre. C'était déjà vrai avant : les
// secrets étaient dans des Secrets Kubernetes, sur cette même machine. La
// différence est qu'à partir d'ici ils sont centralisés, traçables et rotables —
// trois propriétés qu'on n'avait pas. Déplacer le coffre sur une autre machine
// ne supprimerait pas ce point faible, cela ajouterait un composant à
// administrer.
//
// POURQUOI PAS DE DESCELlement MANUEL : demander une intervention humaine à
// chaque redémarrage ferait d'un redémarrage une panne, dans un produit dont
// l'argument est « une commande et ça tourne ». Le choix est fait en connaissance
// de cause.
//
// CE QUI N'EST PAS FAIT, ET QU'IL FAUT SAVOIR : la ROTATION de la clé de sceau
// n'est pas implémentée. OpenBao la prévoit (`previous_key` accompagne
// `current_key` pour relire ce qui est déjà chiffré) ; aujourd'hui, changer
// cette clé rendrait le coffre illisible. C'est une lacune réelle.
//
// LE COFFRE EST OPTIONNEL (voir internal/secrets) : si ce module échoue, le
// déploiement continue et les secrets restent dans Kubernetes. Une panne du
// coffre ne doit jamais empêcher la suite de tourner — c'est ce qui sépare
// « centraliser pour la robustesse » de « ajouter un point de panne ».
package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/sso"
)

const (
	// Version réelle constatée sur Docker Hub (pas inventée) : 2.7.1, publiée
	// le 2026-10-01.
	openbaoImage = "docker.io/openbao/openbao:2.7.1"

	ns      = "ceffio-vault"
	service = "openbao"
	pod     = "openbao-0"

	cheminDonnees = "/openbao/data"
	cheminCle     = "/openbao/secrets/unseal.key"
	cheminAudit   = "/openbao/audit/audit.log"
)

// Resultat rend à l'appelant de quoi consommer le coffre (BAO_ADDR/BAO_TOKEN).
// Pret=false signifie « le coffre n'est pas là, continue avec Kubernetes » : ce
// n'est pas une erreur, c'est le cas nominal dégradé.
type Resultat struct {
	Adresse string
	Jeton   string
	Pret    bool
}

// Deploy installe le coffre, de façon idempotente :
//
//  1. le namespace et la clé de descellement (le secret-zéro) ;
//  2. la configuration (stockage raft, sceau statique, journal d'audit DÉCLARÉ) ;
//  3. le StatefulSet + PVC + Service ;
//  4. l'initialisation, si le coffre ne l'est pas déjà ;
//  5. le moteur KV versionné ;
//  6. une politique d'administration et un jeton, puis RÉVOCATION du jeton racine ;
//  7. un aller-retour réel : écrire, relire, et prouver que ça REFUSE.
//
// Ne rend JAMAIS d'erreur fatale pour la suite : en cas d'échec, un
// avertissement est imprimé et Resultat{Pret:false} est rendu, pour que le
// déploiement se poursuive avec les Secrets Kubernetes.
//
// PAS DE PARAMÈTRE DE DOMAINE... JUSQU'ICI. La première version n'en prenait
// aucun, avec cette justification : « le jour où le coffre sera exposé en
// https://bao.<domaine>, l'entrée publique demandera le domaine — et c'est à ce
// moment-là qu'il faudra ajouter le paramètre, pas avant ».
//
// Ce jour est arrivé avec la Phase 2, et pour une raison précise : l'OIDC a
// besoin de connaître l'adresse publique du coffre, parce que c'est elle qui
// construit l'adresse de retour vers laquelle le navigateur est redirigé. Sans
// elle, OpenBao renvoie le navigateur vers un nom de service interne, que le
// navigateur ne sait pas joindre.
func Deploy(ctx context.Context, domaine string) *Resultat {
	fmt.Println("\nDéploiement du coffre de secrets (OpenBao)...")

	cli, err := k8sapi.Nouveau()
	if err != nil {
		// ICI SE JOUE TOUT : pas de client, donc pas de cluster. On le DIT. La
		// version précédente laissait une configuration introuvable se manifester
		// plus tard, sous forme de sorties vides qu'on interprétait comme des
		// états — et le déploiement poursuivait sur un cluster qu'il n'atteignait
		// pas.
		fmt.Printf("  ∙ coffre non déployé : %v\n", err)
		return &Resultat{}
	}

	if err := cli.Appliquer(ctx, namespaceManifest()); err != nil {
		fmt.Printf("  ∙ coffre non déployé (namespace) : %v\n", err)
		return &Resultat{}
	}
	if err := ensureCleDescellement(ctx, cli); err != nil {
		fmt.Printf("  ∙ coffre non déployé (clé de descellement) : %v\n", err)
		return &Resultat{}
	}
	empreinte, err := applyConfig(ctx, cli, domaine)
	if err != nil {
		fmt.Printf("  ∙ coffre non déployé (configuration) : %v\n", err)
		return &Resultat{}
	}
	if err := cli.Appliquer(ctx, identiteManifest()); err != nil {
		fmt.Printf("  ∙ coffre non déployé (identité) : %v\n", err)
		return &Resultat{}
	}
	if err := cli.Appliquer(ctx, workloadManifest(empreinte)); err != nil {
		fmt.Printf("  ∙ coffre non déployé (charge de travail) : %v\n", err)
		return &Resultat{}
	}
	// L'AGENT-INJECTEUR EST POSÉ ICI, ET SON ÉCHEC EST BLOQUANT.
	//
	// Les charges migrées ne contiennent plus l'init-container qui allait chercher
	// les secrets : elles portent des annotations que seul l'injecteur sait lire.
	// Continuer sans lui produirait des pods SANS secrets et sans erreur
	// d'admission — un silence, pas une panne visible.
	if err := poserInjecteur(ctx, cli); err != nil {
		fmt.Printf("  ∙ coffre non déployé (agent-injecteur) : %v\n", err)
		return &Resultat{}
	}

	// Le pod doit être INSTALLÉ SUR UN NŒUD avant qu'une exécution soit possible.
	// Le contrôle est typé : son échec ne peut plus ressembler à un résultat.
	if _, err := cli.AttendrePodInstalle(ctx, ns, pod, 180*time.Second); err != nil {
		fmt.Printf("  ∙ coffre injoignable : %v\n", err)
		return &Resultat{}
	}
	if err := waitReady(ctx, cli); err != nil {
		fmt.Printf("  ∙ coffre injoignable : %v\n", err)
		return &Resultat{}
	}
	if err := initialiser(ctx, cli); err != nil {
		fmt.Printf("  ∙ initialisation impossible : %v\n", err)
		return &Resultat{}
	}
	// LES POLITIQUES ET LES JETONS AVANT LE MONTAGE DU MOTEUR — et cet ordre
	// n'est pas cosmétique. Monter un moteur est une opération d'administration
	// qui exige une politique à jour. Placée après, une politique corrigée ne
	// pouvait jamais s'appliquer à l'étape qui en avait besoin : le déploiement
	// échouait sur un 403, on corrigeait la politique, on relançait — et il
	// échouait au même endroit, puisque le code n'atteignait jamais l'écriture de
	// la politique. Un blocage circulaire, constaté en service.
	jeton, err := poserPolitiquesEtJetons(ctx, cli)
	if err != nil {
		fmt.Printf("  ∙ jetons non créés : %v\n", err)
		return &Resultat{}
	}
	if err := monterMoteurKV(ctx, cli); err != nil {
		fmt.Printf("  ∙ moteur KV non monté : %v\n", err)
		return &Resultat{}
	}
	// L'AUTHENTIFICATION VIENT APRÈS LES POLITIQUES, puisqu'un rôle les
	// référence : poser un rôle avant sa politique ferait échouer la création du
	// rôle, ou pire, créerait un rôle qui ne donne aucun droit.
	if err := configurerAuthKubernetes(ctx, cli); err != nil {
		fmt.Printf("  ∙ authentification Kubernetes non configurée : %v\n", err)
		return &Resultat{}
	}
	// LES PERSONNES APRÈS LES SERVICES : l'OIDC dépend d'un client Keycloak, donc
	// d'une partie de la pile qui doit déjà être debout. Le configurer avant ne
	// ferait qu'échouer plus tôt, sur une cause moins claire.
	if err := configurerOIDC(ctx, cli, domaine); err != nil {
		fmt.Printf("  ∙ authentification des personnes non configurée : %v\n", err)
		return &Resultat{}
	}
	if err := retirerJetonRacine(ctx, cli); err != nil {
		// Non bloquant : le jeton racine reste, et on le DIT. Un jeton maître
		// qui survit sans le dire est un défaut ; qui survit en le signalant est
		// un incident à traiter.
		fmt.Printf("  ∙ ATTENTION : jeton racine non révoqué (%v) — à traiter\n", err)
	}
	if err := verifierAllerRetour(ctx, cli, jeton); err != nil {
		fmt.Printf("  ∙ vérification de bout en bout échouée : %v\n", err)
		return &Resultat{}
	}

	// LA SEMENCE VIENT EN DERNIER, et elle n'est PAS fatale.
	//
	// En dernier, parce qu'on ne confie des copies de secrets vivants qu'à un
	// coffre dont on vient de vérifier qu'il fonctionne.
	//
	// Non fatale, parce qu'un coffre opérationnel dont la copie de référence est
	// incomplète reste plus utile qu'un déploiement arrêté. Le module suit la
	// doctrine d'ensemble : le coffre améliore, il ne bloque pas.
	if err := Semer(ctx, cli); err != nil {
		fmt.Printf("  ∙ ATTENTION : semence incomplète (%v) — aucune valeur n'a été inventée\n", err)
	} else {
		fmt.Println("  ∙ secrets existants remontés au coffre (copie de référence)")
	}

	fmt.Printf("✓ Coffre OpenBao déployé (%s, %s)\n", openbaoImage, ns)
	// L'adresse rendue est celle du NodePort, et non le nom de service interne.
	//
	// POURQUOI : l'installation tourne SUR LA MACHINE, pas dans le cluster. Le
	// nom openbao.ceffio-vault.svc n'y résout pas — un coffre que l'installation
	// ne peut pas atteindre ne sert à rien. Le NodePort est joignable depuis la
	// machine ET depuis les pods, ce qui donne une seule adresse aux deux.
	//
	// LE NUMÉRO EST LU, PAS CHOISI : fixer un NodePort le réserve pour tout le
	// cluster, et une recréation échoue alors sur « provided port is already
	// allocated ». Kubernetes l'attribue, on le relit.
	//
	// CE QU'ON ASSUME ICI, ET QU'IL FAUT DIRE : ce NodePort parle en clair sur le
	// réseau de la machine. C'est un point à corriger quand l'ingress TLS de la
	// suite sera en place — le coffre y gagnera une adresse https://bao.<domaine>.
	port, err := cli.NodePortDuService(ctx, ns, service, "api")
	if err != nil || port == 0 {
		fmt.Printf("  ∙ ATTENTION : port externe du coffre illisible (%v) — le coffre tourne, mais son adresse n'est pas connue\n", err)
		return &Resultat{Pret: false}
	}
	noeud := os.Getenv("CEFFIO_NOEUD")
	if noeud == "" {
		noeud = "127.0.0.1"
	}
	return &Resultat{
		Adresse: fmt.Sprintf("http://%s:%d", noeud, port),
		Jeton:   jeton,
		Pret:    true,
	}
}

// ---------------------------------------------------------------------------
// 1. Namespace et clé de descellement
// ---------------------------------------------------------------------------

// namespaceManifest décrit le namespace, posé par `apply` donc IDEMPOTENT.
//
// POURQUOI PAS une création directe : créer échoue si l'objet existe déjà, et
// cet échec ferait abandonner tout le déploiement. Le coffre ne pourrait donc
// jamais être redéployé — précisément au moment où l'on en a le plus besoin,
// après une mise à niveau ou un changement de configuration.
func namespaceManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, ns)
}

// ensureCleDescellement crée la clé de 32 octets du sceau « static », si elle
// n'existe pas. On ne la régénère JAMAIS : la régénérer rendrait le coffre
// illisible, puisque les données existantes sont chiffrées avec elle.
//
// LA CLÉ EST ENGENDRÉE EN GO, ET C'EST UN GAIN RÉEL : plus de pod jetable, plus
// de sortie de commande à découper, donc plus aucun risque de récupérer autre
// chose que la clé. La version précédente passait par `kubectl run` et a
// enregistré un Secret de 309 caractères dont la moitié était un message d'aide.
//
// 32 OCTETS, ET PAS UN AUTRE NOMBRE : c'est la taille qu'exige le sceau
// statique, qui s'en sert comme clé AES-256. Une taille différente fait échouer
// le démarrage du serveur sur « unknown encoding for AES-256 key » — constaté.
func ensureCleDescellement(ctx context.Context, cli *k8sapi.Client) error {
	existante, err := cli.LireSecret(ctx, ns, "openbao-unseal-key", "unseal.key")
	if err != nil {
		return err
	}
	if existante != "" {
		return nil
	}

	brut := make([]byte, 32)
	if _, err := rand.Read(brut); err != nil {
		return fmt.Errorf("génération de la clé : %w", err)
	}
	// base64 sur une ligne : la forme que le fichier attend, et l'une de celles
	// qu'OpenBao sait décoder (« raw, hex, or base64-encoded »).
	cle := base64.StdEncoding.EncodeToString(brut)

	// ON CONTRÔLE LA FORME AVANT DE S'EN SERVIR. Le contrôle est trivial
	// maintenant que la valeur ne sort plus d'une commande — mais il documente la
	// contrainte, et il attraperait une modification future qui réintroduirait un
	// détour. 32 octets en base64 font exactement 44 caractères.
	if len(cle) != 44 {
		return fmt.Errorf("clé mal formée : %d caractères au lieu de 44", len(cle))
	}

	if err := cli.PoserSecret(ctx, ns, "openbao-unseal-key",
		map[string][]byte{"unseal.key": []byte(cle)}); err != nil {
		return fmt.Errorf("pose de la clé : %w", err)
	}
	fmt.Println("  ∙ clé de descellement créée (32 octets = 256 bits → AES-256)")
	return nil
}

// ---------------------------------------------------------------------------
// 2. Configuration : stockage, écoute, sceau, AUDIT
// ---------------------------------------------------------------------------

// configManifest décrit la configuration du serveur.
//
// QUATRE CHOIX À EXPLIQUER :
//
//   - L'ÉCOUTE SE FAIT SANS TLS À L'INTÉRIEUR DU CLUSTER. Le trafic ne quitte
//     pas le réseau des pods. Le dire explicitement plutôt que de le laisser
//     deviner : un serveur TLS qui reçoit du clair répond 400, donc un code
//     d'erreur ne prouve pas qu'on parle à un serveur en clair.
//
//   - `disable_mlock` EST ABSENT, et c'est délibéré : OpenBao le signale comme
//     « unknown or unsupported field » au démarrage. Le garder produirait un
//     avertissement à chaque démarrage, et un avertissement permanent finit par
//     être ignoré — y compris le jour où il annonce autre chose.
//
//   - LE JOURNAL D'AUDIT EST DÉCLARÉ ICI, dans le fichier de configuration, et
//     non activé par une commande : c'est la forme que la version actuelle
//     d'OpenBao attend, et elle survit aux redémarrages. Retirer ce bloc
//     supprimerait le journal.
//
//     LA SYNTAXE EXACTE COMPTE : `audit "<type>" "<chemin>"` prend DEUX
//     étiquettes — le type d'abord, le chemin de montage ensuite — et `options`
//     est un BLOC, pas une affectation. Écrire `audit "file" { … }` avec une
//     seule étiquette fait échouer le démarrage sur « audit type must be
//     specified », constaté en service.
//
//   - LE DESCELlement EST AUTOMATIQUE, par le sceau statique. Voir l'entête du
//     paquet pour le compromis.
func configManifest(domaine string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: openbao-config
  namespace: %[1]s
data:
  openbao.hcl: |
    ui = true

    storage "raft" {
      path    = "%[2]s"
      node_id = "%[6]s"
    }

    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = true
    }

    seal "static" {
      current_key_id = "ceffio-1"
      current_key    = "file://%[3]s"
    }

    audit "file" "fichier" {
      description = "Journal d'audit Ceffio"
      options {
        file_path = "%[4]s"
      }
    }

    api_addr     = "%[7]s"
    cluster_addr = "http://%[5]s.%[1]s.svc:8201"
`, ns, cheminDonnees, cheminCle, cheminAudit, service, pod, adressePublique(domaine))
}

// adressePublique rend l'adresse par laquelle le coffre est joint.
//
// ELLE COMPTE POUR L'OIDC, et pas seulement pour l'affichage : c'est à partir
// d'elle qu'OpenBao construit l'adresse de retour vers laquelle le navigateur
// est redirigé après authentification. Laissée sur le nom de service interne,
// elle produirait une redirection vers un nom que le navigateur ne sait pas
// joindre — et l'échec apparaîtrait côté navigateur, donc loin de la cause.
//
// LE REPLI EST EXPLICITE : sans domaine, on rend l'adresse interne, qui suffit
// aux appels venant du cluster. Le dire plutôt que de rendre une chaîne vide.
func adressePublique(domaine string) string {
	if domaine == "" {
		return "http://" + service + "." + ns + ".svc:8200"
	}
	// L'ingress termine le TLS ; la traversée jusqu'au coffre, à l'intérieur du
	// cluster, reste en clair — c'est le même compromis que pour les autres
	// composants, et il est borné au réseau des pods.
	return "https://bao." + domaine
}

// applyConfig pose la configuration et rend son empreinte.
//
// L'EMPREINTE SERT À REDÉMARRER LE POD QUAND LA CONFIGURATION CHANGE. Kubernetes
// ne redémarre pas un pod parce qu'un ConfigMap a changé : le fichier monté se
// met à jour sur le disque, mais le processus en cours ne relit rien. Un pod en
// marche continuerait donc d'utiliser l'ancienne configuration — et une
// correction resterait sans effet, ce qui fait perdre beaucoup de temps à qui
// croit avoir corrigé.
//
// En reportant l'empreinte dans une annotation du gabarit, toute modification
// devient un changement de pod : le StatefulSet roule, et la nouvelle
// configuration est réellement appliquée.
func applyConfig(ctx context.Context, cli *k8sapi.Client, domaine string) (string, error) {
	manifeste := configManifest(domaine)
	if err := cli.Appliquer(ctx, manifeste); err != nil {
		return "", err
	}
	somme := sha256.Sum256([]byte(manifeste))
	return hex.EncodeToString(somme[:])[:16], nil
}

// ---------------------------------------------------------------------------
// 3. Charge de travail
// ---------------------------------------------------------------------------

// identiteManifest donne au coffre une IDENTITÉ DANS LE CLUSTER, et le droit de
// valider les jetons des autres.
//
// POURQUOI LE COFFRE A BESOIN D'UNE IDENTITÉ : pour authentifier un pod par son
// jeton de ServiceAccount, le coffre doit demander au cluster « ce jeton
// est-il valide, et à qui appartient-il ? ». Cette question s'appelle un
// TokenReview, et l'API du cluster n'y répond qu'à qui en a le droit. Le rôle
// `system:auth-delegator` est précisément ce droit — il est livré par Kubernetes
// et n'a pas à être redéfini.
//
// POURQUOI LE RÔLE EST UN ClusterRoleBinding : le droit de valider un jeton ne
// se limite pas à un namespace. C'est un pouvoir vis-à-vis de l'API du cluster
// entier. D'où un objet de portée globale — et c'est bien pour cela qu'il est
// nommé, et lié à UN ServiceAccount précis plutôt qu'à un groupe.
func identiteManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openbao-auth-delegator
subjects:
  - kind: ServiceAccount
    name: %[1]s
    namespace: %[2]s
roleRef:
  kind: ClusterRole
  name: system:auth-delegator
  apiGroup: rbac.authorization.k8s.io
`, service, ns)
}

// workloadManifest pose le StatefulSet, le Service et le volume.
//
// UN SEUL NŒUD, ET C'EST UN CHOIX : le stockage raft sait faire un cluster, mais
// une PME n'a pas besoin de trois coffres pour trois secrets. Le jour où il en
// faudra un, c'est le nombre de réplicas qui changera — pas la conception.
//
// L'EMPREINTE DE CONFIGURATION EST REPORTÉE DANS LE GABARIT : c'est elle qui fait
// qu'une modification de la configuration redémarre réellement le pod, au lieu
// de laisser tourner l'ancienne.
func workloadManifest(empreinte string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  type: NodePort
  selector:
    app: %[1]s
  ports:
    - name: api
      port: 8200
      targetPort: 8200
    - name: cluster
      port: 8201
      targetPort: 8201
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  serviceName: %[1]s
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
        ceffio.fr/empreinte-config: "%[5]s"
    spec:
      # LE COFFRE TOURNE SOUS SON PROPRE ServiceAccount, et non sous celui par
      # défaut : c'est lui qui porte le droit de valider les jetons des autres
      # pods. Sans cette ligne, l'authentification Kubernetes ne peut pas
      # fonctionner, et l'échec apparaîtrait plus tard, au moment de la première
      # connexion — loin de la cause.
      serviceAccountName: %[1]s
      securityContext:
        runAsUser: 100
        runAsGroup: 1000
        fsGroup: 1000
      containers:
        - name: openbao
          image: %[3]s
          command: ["bao", "server", "-config=/openbao/config/openbao.hcl"]
          env:
            - name: BAO_ADDR
              value: "http://127.0.0.1:8200"
          ports:
            - name: api
              containerPort: 8200
            - name: cluster
              containerPort: 8201
          volumeMounts:
            - name: config
              mountPath: /openbao/config
              readOnly: true
            - name: unseal
              mountPath: /openbao/secrets
              readOnly: true
            - name: data
              mountPath: %[4]s
            - name: audit
              mountPath: /openbao/audit
          readinessProbe:
            # SONDE QUI ACCEPTE L'ÉTAT « NON INITIALISÉ ».
            #
            # /v1/sys/health répond 501 tant que le coffre n'est pas initialisé,
            # et 503 tant qu'il est scellé. Une sonde par défaut (200-399) ne
            # passerait donc JAMAIS avant l'initialisation — or c'est
            # l'initialisation qui est censée suivre. Le pod resterait
            # éternellement « non prêt », et le déploiement attendrait un état
            # qui ne peut pas venir.
            #
            # 204 sur ces deux états dit la vérité : le serveur est vivant et
            # répond, il attend juste sa mise en service.
            httpGet:
              path: /v1/sys/health?standbyok=true&sealedcode=204&uninitcode=204
              port: 8200
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: openbao-config
        - name: unseal
          secret:
            secretName: openbao-unseal-key
        - name: audit
          emptyDir: {}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
`, service, ns, openbaoImage, cheminDonnees, empreinte)
}

// waitReady attend que le coffre réponde à une commande d'état.
//
// Le pod est déjà connu comme installé (AttendrePodInstalle s'en est chargé) :
// il ne reste qu'à attendre que le serveur soit assez vivant pour répondre.
func waitReady(ctx context.Context, cli *k8sapi.Client) error {
	limite := time.Now().Add(180 * time.Second)
	var dernier string
	for time.Now().Before(limite) {
		etat, err := etatCoffre(ctx, cli)
		if err == nil && etat != "" {
			fmt.Printf("  ∙ coffre joignable (état : %s)\n", etat)
			return nil
		}
		dernier = fmt.Sprintf("%v", err)
		time.Sleep(4 * time.Second)
	}
	return fmt.Errorf("le coffre n'a pas répondu en 180 s (dernier état : %s)", dernier)
}

// ---------------------------------------------------------------------------
// 4. Initialisation
// ---------------------------------------------------------------------------

// initialiser initialise le coffre s'il ne l'est pas, et range les clés de
// récupération.
//
// AVEC UN SCEAU AUTOMATIQUE, `operator init` rend des clés de RÉCUPÉRATION, pas
// des clés de descellement : le coffre reste descellé une fois initialisé. Ces
// clés servent uniquement à régénérer un jeton racine perdu — d'où leur
// conservation, et d'où le fait qu'elles ne soient PAS la clé quotidienne.
func initialiser(ctx context.Context, cli *k8sapi.Client) error {
	initie, err := dejaInitialise(ctx, cli)
	if err != nil {
		return err
	}
	if initie {
		fmt.Println("  ∙ coffre déjà initialisé")
		return nil
	}

	// Le réessai n'est pas décoratif : `operator init` monte la barrière de
	// sécurité du coffre, ce qui provoque un bref redémarrage du cœur. Sans lui,
	// l'étape suivante échouait sur « connection refused » — une course avec le
	// redémarrage que la commande venait elle-même de déclencher.
	sortie, err := baoReessai(ctx, cli, "operator", "init",
		"-recovery-shares=1", "-recovery-threshold=1", "-format=json")
	if err != nil {
		return fmt.Errorf("operator init : %w", err)
	}
	var res struct {
		RecoveryKeys []string `json:"recovery_keys_b64"`
		RootToken    string   `json:"root_token"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &res); err != nil {
		return fmt.Errorf("réponse d'initialisation illisible : %w", err)
	}
	// On contrôle que la réponse est COMPLÈTE avant de l'utiliser : un
	// initialisation à demi lue produirait un coffre sans jeton racine, donc
	// impossible à administrer.
	if res.RootToken == "" {
		return fmt.Errorf("réponse d'initialisation sans jeton racine : %.120s", strings.TrimSpace(sortie))
	}
	if len(res.RecoveryKeys) == 0 {
		return fmt.Errorf("réponse d'initialisation sans clé de récupération : %.120s", strings.TrimSpace(sortie))
	}

	// Les clés sont rangées dans un Secret, JAMAIS imprimées.
	donnees := map[string][]byte{"root-token": []byte(res.RootToken)}
	for i, k := range res.RecoveryKeys {
		donnees[fmt.Sprintf("recovery-%d", i)] = []byte(k)
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-recovery", donnees); err != nil {
		return fmt.Errorf("rangement des clés de récupération : %w", err)
	}
	fmt.Println("  ∙ coffre initialisé (clés rangées dans openbao-recovery, non affichées)")
	return nil
}

// dejaInitialise dit si le stockage du coffre a déjà été préparé.
//
// UNE SEULE SOURCE DE VÉRITÉ, et c'est l'état du serveur. Il y en avait deux
// auparavant — le code de `/v1/sys/health` et la sortie de `bao status` — et
// elles se contredisaient : la première annonçait « déjà initialisé » sur un
// coffre qui ne l'était pas, parce que l'image OpenBao ne contient PAS `curl`.
// L'appel échouait, et le code « inconnu » était interprété comme
// « initialisé ». Un échec silencieux, dans la fonction qui décide s'il faut
// initialiser.
func dejaInitialise(ctx context.Context, cli *k8sapi.Client) (bool, error) {
	etat, err := etatCoffre(ctx, cli)
	if err != nil {
		return false, err
	}
	return etat != "non initialisé", nil
}

// ---------------------------------------------------------------------------
// 5. Moteur KV
// ---------------------------------------------------------------------------

// monterMoteurKV monte un KV versionné au chemin « kv », la convention que
// internal/secrets attend par défaut (BAO_MOTEUR).
//
// IL PASSE PAR L'ADMINISTRATION, ET C'EST NÉCESSAIRE : monter un moteur est une
// opération d'administration du coffre, hors de portée du jeton applicatif — par
// conception. Le jeton d'installation existe précisément pour ça.
func monterMoteurKV(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	sortie, err := baoAvecJeton(ctx, cli, adm, "secrets", "list")
	if err != nil {
		return err
	}
	if strings.Contains(sortie, "kv/") {
		fmt.Println("  ∙ moteur KV déjà monté")
		return nil
	}
	if _, err := baoAvecJeton(ctx, cli, adm, "secrets", "enable", "-path=kv", "-version=2", "kv"); err != nil {
		return fmt.Errorf("montage du moteur KV : %w", err)
	}
	fmt.Println("  ∙ moteur KV versionné monté sur « kv »")
	return nil
}

// jetonAdministration rend un jeton capable d'administrer le coffre :
// le jeton d'installation s'il est valide, sinon le jeton racine — c'est-à-dire
// le premier passage, avant la révocation.
//
// L'ORDRE COMPTE, et il a une raison : après la mise en place, le jeton racine
// n'existe plus. Chercher le racine en premier échouerait à chaque
// redéploiement, alors que le coffre se porte parfaitement bien.
func jetonAdministration(ctx context.Context, cli *k8sapi.Client) (string, error) {
	if j, _ := cli.LireSecret(ctx, ns, "openbao-installation", "token"); j != "" {
		// `token lookup` sans argument interroge le jeton courant — voir la note
		// détaillée dans poserPolitiquesEtJetons : « lookup-self » n'existe pas.
		if _, err := baoAvecJeton(ctx, cli, j, "token", "lookup"); err == nil {
			return j, nil
		}
	}
	if j, _ := cli.LireSecret(ctx, ns, "openbao-recovery", "root-token"); j != "" {
		return j, nil
	}
	return "", fmt.Errorf("aucun jeton d'administration : ni jeton d'installation valide, ni jeton racine (régénérer un jeton racine avec une clé de récupération)")
}

// ---------------------------------------------------------------------------
// 6. Politique et jeton d'administration, puis révocation du racine
// ---------------------------------------------------------------------------

// poserPolitiquesEtJetons crée DEUX politiques et DEUX jetons, aux périmètres
// distincts, et rend le jeton applicatif.
//
// POURQUOI DEUX, ET PAS UN SEUL — c'est la correction d'une contradiction que le
// terrain a révélée. Le code précédent révoquait le jeton racine (bien) après
// avoir tout fait avec lui (mal) : au second passage, le montage du moteur KV et
// la réécriture des politiques exigeaient des droits racine qui n'existaient
// plus. Le coffre devenait non redéployable — précisément au moment où l'on en a
// le plus besoin, après une mise à niveau.
//
// La réponse n'est pas de garder le jeton racine, mais de fabriquer DEUX jetons
// AVANT de le révoquer :
//
//   - le jeton d'INSTALLATION porte les droits d'administration du coffre
//     (monter un moteur, écrire une politique, créer un jeton). Il sert aux
//     passages suivants de `ceffio vault`, et il est rangé à part ;
//   - le jeton APPLICATIF ne porte que la lecture et l'écriture des secrets de
//     la suite, sous `kv/data/ceffio/*`. C'est celui que la suite reçoit
//     (BAO_TOKEN).
//
// AINSI LE JETON QUE LA SUITE UTILISE NE PEUT PAS ADMINISTRER LE COFFRE. Un
// service compromis ne peut pas monter de moteur, ni élargir sa propre
// politique, ni fabriquer de jeton. C'est ce que veut dire « moindre privilège »,
// et un seul jeton n'aurait pas pu le faire.
func poserPolitiquesEtJetons(ctx context.Context, cli *k8sapi.Client) (string, error) {
	// ON RÉUTILISE LE JETON D'INSTALLATION S'IL FONCTIONNE ENCORE. Le coffre a
	// certainement déjà été mis en place : sans cela, il faudrait le jeton racine,
	// qui a été révoqué — et un coffre qu'on ne peut pas redéployer est un coffre
	// qu'on n'ose pas toucher.
	inst := ""
	if j, _ := cli.LireSecret(ctx, ns, "openbao-installation", "token"); j != "" {
		// On ne se fie pas à sa seule présence : un jeton expiré laissé dans un
		// Secret donnerait l'illusion d'un coffre administrable.
		//
		// LA FORME EXACTE COMPTE : `bao token lookup` SANS argument interroge le
		// jeton courant. Les sous-commandes réelles sont capabilities, create,
		// lookup, renew et revoke — il n'existe pas de « lookup-self ». Écrire ce
		// nom affiche l'aide et sort en erreur, ce qui faisait déclarer INVALIDE un
		// jeton parfaitement valide, et le coffre passait pour ingérable.
		// (Vérifié : `bao token --help`.)
		if _, err := baoAvecJeton(ctx, cli, j, "token", "lookup"); err == nil {
			fmt.Println("  ∙ jeton d'installation déjà en place (réutilisé)")
			inst = j
		}
	}
	if inst == "" {
		inst, _ = cli.LireSecret(ctx, ns, "openbao-recovery", "root-token")
		if inst == "" {
			return "", fmt.Errorf("aucun jeton d'administration valide : le jeton racine a été révoqué et le jeton d'installation est absent — régénérer un jeton racine avec une clé de récupération (openbao-recovery)")
		}
	}

	// LES DEUX POLITIQUES SONT ÉCRITES PAR FICHIER, et non en argument : `policy
	// write` attend un chemin ou `-` pour l'entrée standard, et une politique
	// tenant sur une ligne de commande serait tronquée au premier retour à la
	// ligne.
	politiques := []struct{ nom, regle string }{
		// APPLICATIVE : les secrets de la suite, et rien d'autre. Noter qu'il n'y
		// a AUCUNE capacité d'administration ici — ni montage de moteur, ni
		// politique, ni création de jeton.
		{"ceffio-admin", `path "kv/data/ceffio/*" { capabilities = ["create","read","update","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list","delete"] }
path "kv/delete/ceffio/*" { capabilities = ["update"] }
path "kv/undelete/ceffio/*" { capabilities = ["update"] }
# L'OUTIL EN LIGNE DE COMMANDE INTERROGE CE CHEMIN AVANT TOUTE ÉCRITURE.
#
# « bao kv put » commence par demander où le moteur est monté, pour savoir s'il
# doit viser l'API KV version 1 ou version 2. Sans cette autorisation, la
# commande échoue sur un 403 portant sur « sys/internal/ui/mounts/... » — un
# message qui ne parle PAS du secret qu'on voulait écrire, et qui envoie donc
# chercher l'erreur au mauvais endroit. Constaté en service.
#
# L'autorisation est en LECTURE SEULE : elle ne révèle que l'emplacement des
# moteurs et la version de leur API, jamais un contenu.
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// CONSOLE : c'est le SEUL rôle qui écrit. Les humains passent par la
		// console, qui détient ce droit ; un service compromis ne l'a pas. C'est
		// cette séparation qui limite les dégâts, pas le namespace.
		//
		// Elle s'obtient par l'authentification Kubernetes — voir
		// configurerAuthKubernetes — donc sans qu'aucun secret ne soit rangé dans
		// la console.
		{"ceffio-console", `path "kv/data/ceffio/*" { capabilities = ["create","read","update","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list","delete"] }
path "kv/delete/ceffio/*" { capabilities = ["update"] }
path "kv/undelete/ceffio/*" { capabilities = ["update"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// LECTURE SEULE : ce que reçoivent les composants de la suite qui n'ont
		// qu'à lire leurs propres secrets. Le « metadata » donne la liste des
		// versions, jamais les valeurs.
		{"ceffio-lecture", `path "kv/data/ceffio/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// LECTURE PAR COMPOSANT : un service ne lit QUE ce qui le concerne. La
		// politique large ci-dessus existe pour les cas à venir ; un composant
		// précis reçoit la sienne. C'est elle qui borne les dégâts quand un rôle
		// est compromis — pas le namespace, qui ne dit rien des droits.
		{"ceffio-stalwart", `path "kv/data/ceffio/stalwart/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/stalwart/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-onlyoffice", `path "kv/data/ceffio/onlyoffice/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/onlyoffice/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-talk", `path "kv/data/ceffio/talk/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/talk/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-nextcloud", `path "kv/data/ceffio/nextcloud/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/nextcloud/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		{"ceffio-keycloak", `path "kv/data/ceffio/keycloak/*" { capabilities = ["read","list"] }
path "kv/metadata/ceffio/keycloak/*" { capabilities = ["read","list"] }
path "sys/internal/ui/mounts/*" { capabilities = ["read"] }`},
		// ADMINISTRATION : le compte humain unique, celui que l'annuaire désigne
		// comme administrateur. Il a TOUS les droits sur le coffre — c'est le
		// sens d'un compte d'administration, et c'est ce qui rend la rotation
		// centralisée possible depuis un seul endroit.
		//
		// LA SEULE CHOSE QU'IL NE PEUT PAS FAIRE : obtenir le jeton racine. Il
		// ne s'obtient qu'avec les clés de récupération, et c'est délibéré — un
		// jeton qui ne peut rien refuser n'a pas à être accessible depuis un
		// navigateur.
		//
		// LES SERVICES N'ONT PAS CETTE POLITIQUE, et c'est tout l'intérêt : un
		// service compromis ne peut ni monter de moteur, ni élargir sa propre
		// politique, ni fabriquer de jeton.
		{"ceffio-administration", `path "*" { capabilities = ["create","read","update","delete","list","sudo"] }`},
		// INSTALLATION : ce qu'exige la mise en place et les passages suivants.
		// Le KV y figure aussi, pour que le diagnostic de bout en bout tourne
		// avec ce jeton sans dépendre d'un autre.
		{"ceffio-installation", `# LE CHEMIN EXACT ET LE WILDCARD SONT DEUX AUTORISATIONS DISTINCTES.
# « sys/mounts/* » couvre les moteurs montés, mais PAS « sys/mounts » lui-même,
# qui est le point d'entrée de la LISTE des moteurs. Sans la ligne exacte,
# « bao secrets list » répond 403 — et le message porte sur « /v1/sys/mounts »,
# donc sur un chemin qui n'apparaît nulle part dans la politique : on cherche
# l'erreur ailleurs. Constaté en service.
path "kv/*" { capabilities = ["create","read","update","delete","list"] }
path "sys/mounts" { capabilities = ["read","list"] }
path "sys/mounts/*" { capabilities = ["create","read","update","delete","list","sudo"] }
# MÊME DISTINCTION POUR L'AUTHENTIFICATION que pour les moteurs : « sys/auth »
# est le point d'entrée de la LISTE des méthodes, et « sys/auth/* » celui de leur
# configuration. Il faut les deux — n'avoir que le second répond 403 sur la
# liste, ce qui empêche de savoir si une méthode est déjà branchée. Constaté en
# service, sur cette étape précise.
path "sys/auth" { capabilities = ["read","list"] }
path "sys/auth/*" { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/policies/acl/*" { capabilities = ["create","read","update","delete","list"] }
# TOUTE LA BRANCHE « auth/ », et pas seulement « auth/token/ ».
#
# POURQUOI SI LARGE : configurer une méthode d'authentification s'écrit à
# « auth/<méthode>/config », et poser un rôle à « auth/<méthode>/role/<nom> ».
# Énumérer méthode par méthode obligeait à revenir dans le code à chaque fois —
# et l'échec était un 403 sur un chemin qui ne figure nulle part dans la
# politique. C'est le jeton d'ADMINISTRATION : c'est ici que la largeur est à sa
# place, pas dans la politique applicative, qui n'a aucun droit d'écriture sur
# cette branche.
path "auth/*" { capabilities = ["create","read","update","delete","list"] }
# LA RÈGLE LA PLUS PRÉCISE L'EMPORTE, et c'est indispensable ici : créer un jeton
# ORPHELIN — celui dont dépend la survie du jeton d'installation — exige la
# capacité « sudo » sur ce chemin précis. La ligne générale ci-dessus ne la donne
# pas. Sans celle-ci, le prochain déploiement échouerait à la création des jetons.
path "auth/token/create" { capabilities = ["create","update","sudo"] }
path "sys/health" { capabilities = ["read"] }`},
	}
	for _, p := range politiques {
		script := fmt.Sprintf("cat > /tmp/p.hcl <<'FIN_POLITIQUE'\n%s\nFIN_POLITIQUE\n", p.regle)
		if _, err := cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", script); err != nil {
			return "", fmt.Errorf("écriture de la politique %s : %w", p.nom, err)
		}
		if _, err := baoAvecJeton(ctx, cli, inst, "policy", "write", p.nom, "/tmp/p.hcl"); err != nil {
			return "", fmt.Errorf("politique %s : %w", p.nom, err)
		}
	}

	// Le jeton d'installation est fabriqué EN PREMIER : une fois le jeton racine
	// révoqué, il n'y a plus de quoi en créer un.
	nj, err := creerJeton(ctx, cli, inst, "ceffio-installation", "ceffio-installation")
	if err != nil {
		return "", err
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-installation",
		map[string][]byte{"token": []byte(nj)}); err != nil {
		return "", fmt.Errorf("rangement du jeton d'installation : %w", err)
	}

	ja, err := creerJeton(ctx, cli, inst, "ceffio-admin", "ceffio-suite")
	if err != nil {
		return "", err
	}
	if err := cli.PoserSecret(ctx, ns, "openbao-token",
		map[string][]byte{"token": []byte(ja)}); err != nil {
		return "", fmt.Errorf("rangement du jeton applicatif : %w", err)
	}
	fmt.Println("  ∙ politiques « ceffio-admin » (applicative) et « ceffio-installation » posées")
	fmt.Println("  ∙ deux jetons créés : la suite ne peut PAS administrer le coffre")
	return ja, nil
}

// creerJeton fabrique un jeton portant une politique, sous un nom qui dit son
// usage.
//
// LE JETON EST ORPHELIN, ET C'EST LA CORRECTION D'UN DÉFAUT GRAVE. Dans
// OpenBao comme dans Vault, révoquer un jeton révoque TOUTE SA DESCENDANCE. Les
// deux jetons créés depuis le jeton racine mouraient donc avec lui : au passage
// suivant, le coffre tournait, mais plus personne ne pouvait l'administrer — et
// aucune trace ne disait pourquoi, puisque la révocation du racine avait réussi.
//
// Un jeton orphelin n'a pas de parent : il survit à la révocation du jeton qui
// l'a créé. Le prix est qu'il ne s'efface plus « par ricochet » — il faut le
// révoquer nommément. C'est le bon compromis ici : un jeton d'administration
// qu'on oublie doit rester révocable, pas disparaître silencieusement avec un
// autre.
//
// Le nom compte aussi : dans la liste des jetons d'un coffre, un jeton anonyme
// ne se distingue plus d'un autre, et l'on hésite à révoquer par peur de casser
// quelque chose.
func creerJeton(ctx context.Context, cli *k8sapi.Client, porteur, politique, nom string) (string, error) {
	sortie, err := baoAvecJeton(ctx, cli, porteur, "token", "create",
		"-policy="+politique, "-period=768h", "-orphan", "-format=json", "-display-name="+nom)
	if err != nil {
		return "", fmt.Errorf("création du jeton %s : %w", nom, err)
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &res); err != nil {
		return "", fmt.Errorf("réponse illisible pour %s : %w", nom, err)
	}
	if res.Auth.ClientToken == "" {
		return "", fmt.Errorf("jeton %s vide : %.120s", nom, strings.TrimSpace(sortie))
	}
	return res.Auth.ClientToken, nil
}

// configurerAuthKubernetes branche l'authentification par Kubernetes : un pod
// présente son jeton de ServiceAccount, le coffre le fait valider par l'API du
// cluster, et rend un jeton portant la politique du rôle correspondant.
//
// POURQUOI CE MÉCANISME PLUTÔT QU'UN SECRET PARTAGÉ : un secret partagé, il faut
// le ranger quelque part, donc recréer le problème qu'on résout. Le jeton de
// ServiceAccount, lui, est déjà là, présenté par le pod et renouvelé par le
// cluster. Rien à ranger, rien à faire tourner à la main.
//
// POURQUOI LE RÔLE PRÉCISE LE NAMESPACE ET LE NOM : les deux comptent. Un
// ServiceAccount homonyme créé ailleurs dans le cluster obtiendrait sinon les
// mêmes droits. C'est la combinaison des deux qui identifie un pod.
func configurerAuthKubernetes(ctx context.Context, cli *k8sapi.Client) error {
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}

	// DÉJÀ BRANCHÉE ? On le DEMANDE au coffre plutôt que de le supposer : une
	// seconde activation renvoie une erreur qui ferait échouer tout le
	// déploiement pour rien.
	sortie, err := baoAvecJeton(ctx, cli, adm, "auth", "list")
	if err != nil {
		return fmt.Errorf("lecture des méthodes d'authentification : %w", err)
	}
	if !strings.Contains(sortie, "kubernetes/") {
		if _, err := baoAvecJeton(ctx, cli, adm, "auth", "enable", "kubernetes"); err != nil {
			return fmt.Errorf("activation de l'authentification Kubernetes : %w", err)
		}
		fmt.Println("  ∙ authentification Kubernetes activée")
	}

	// L'ADRESSE DU CLUSTER VUE DE L'INTÉRIEUR : « kubernetes.default.svc » est le
	// nom que tout pod résout, et le certificat de l'API y correspond.
	//
	// LE JETON DE VALIDATION N'EST PAS FOURNI ICI, et c'est volontaire : le coffre
	// utilise le sien, celui de son ServiceAccount — d'où le droit de délégation
	// accordé par identiteManifest, qui n'est donc pas décoratif. C'est aussi ce
	// qui évite d'avoir un jeton de longue durée à ranger dans un fichier de
	// configuration.
	if _, err := baoAvecJeton(ctx, cli, adm, "write", "auth/kubernetes/config",
		"kubernetes_host=https://kubernetes.default.svc:443"); err != nil {
		return fmt.Errorf("configuration de l'authentification Kubernetes : %w", err)
	}

	roles := []struct{ nom, sa, ns, politique string }{
		// La console est aujourd'hui le seul consommateur : c'est elle qui écrit
		// les secrets, et c'est là que les humains agissent. Les composants
		// viendront s'ajouter un par un, en Phase 3, avec la politique de lecture
		// seule.
		{nom: "console", sa: "ceffio-admin", ns: "ceffio-system", politique: "ceffio-console"},
		// LES COMPOSANTS LISENT LEURS PROPRES SECRETS À L'EXÉCUTION. C'est le
		// ServiceAccount DU POD qui s'authentifie, via un init-container : aucun
		// jeton n'est rangé quelque part, et une rotation dans le coffre prend
		// effet au redémarrage suivant du pod — sans redéployer la suite.
		{nom: "stalwart", sa: "stalwart", ns: "ceffio-mail", politique: "ceffio-stalwart"},
		{nom: "onlyoffice", sa: "onlyoffice", ns: "ceffio-office", politique: "ceffio-onlyoffice"},
		{nom: "talk", sa: "talk", ns: "ceffio-video", politique: "ceffio-talk"},
		{nom: "nextcloud", sa: "nextcloud", ns: "ceffio-files", politique: "ceffio-nextcloud"},
		{nom: "keycloak", sa: "keycloak", ns: "ceffio-identity", politique: "ceffio-keycloak"},
	}
	for _, r := range roles {
		if _, err := baoAvecJeton(ctx, cli, adm,
			"write", "auth/kubernetes/role/"+r.nom,
			"bound_service_account_names="+r.sa,
			"bound_service_account_namespaces="+r.ns,
			"policies="+r.politique,
			"ttl=1h"); err != nil {
			return fmt.Errorf("rôle « %s » : %w", r.nom, err)
		}
	}
	fmt.Println("  ∙ authentification Kubernetes configurée (rôle « console », délai 1 h)")
	return nil
}

// ecrirePayloadCoffre écrit une charge JSON dans le conteneur, en 0600, et rend
// son chemin.
//
// POURQUOI UN FICHIER, ET PAS DES ARGUMENTS : la ligne de commande ne sait
// transmettre que du texte. Écrire « bound_claims={"email":[...]} » fait répondre
// au coffre « got unconvertible type 'string' » — le rôle n'est pas créé, et le
// message ne dit pas comment s'y prendre. Un objet transmis en entier, depuis un
// fichier, est analysé correctement : c'est la seule forme qui marche pour un
// champ structuré.
//
// LE UMASK EST POSÉ AVANT L'ÉCRITURE : la charge peut contenir un secret de
// client, et un fichier lisible par tous dans le conteneur serait une trace
// inutile. Le fichier est supprimé après emploi.
func ecrirePayloadCoffre(ctx context.Context, cli *k8sapi.Client, chemin string, charge any) error {
	brut, err := json.MarshalIndent(charge, "", "  ")
	if err != nil {
		return fmt.Errorf("charge illisible : %w", err)
	}
	script := fmt.Sprintf("umask 077; cat > %s <<'FIN_PAYLOAD'\n%s\nFIN_PAYLOAD\n", chemin, brut)
	if _, err := cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", script); err != nil {
		return fmt.Errorf("écriture de la charge %s : %w", chemin, err)
	}
	return nil
}

// retirerPayloadCoffre efface une charge après emploi.
func retirerPayloadCoffre(ctx context.Context, cli *k8sapi.Client, chemin string) {
	_, _ = cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", "rm -f "+chemin)
}

// configurerOIDC branche l'authentification des PERSONNES, sur le Keycloak de la
// suite.
//
// POURQUOI L'OIDC POUR LES GENS ET KUBERNETES POUR LES SERVICES : un pod a un
// jeton que le cluster lui donne. Une personne n'en a pas. Lui en fabriquer un
// reviendrait à tenir une liste de comptes à part, avec leurs mots de passe et
// leurs oublis — exactement la seconde liste qu'on veut éviter. L'OIDC dit
// simplement : « cette personne est celle que Keycloak dit qu'elle est ».
func configurerOIDC(ctx context.Context, cli *k8sapi.Client, domaine string) error {
	if domaine == "" {
		// SANS DOMAINE, PAS D'ADRESSE DE RETOUR : le navigateur n'aurait nulle
		// part où revenir. On l'annonce plutôt que de configurer quelque chose
		// qui ne peut pas fonctionner.
		fmt.Println("  ∙ pas de domaine : authentification des personnes non configurée")
		return nil
	}

	// LE CLIENT ET SON SECRET SONT CRÉÉS PAR LE MODULE SSO, qui possède la
	// connaissance de Keycloak. On les LIT ici plutôt que d'en fabriquer
	// d'autres : deux sources pour un même secret finissent par diverger, et
	// c'est la panne la plus longue à comprendre.
	if err := sso.AssurerClientCoffre(ctx, domaine); err != nil {
		return fmt.Errorf("client OIDC du coffre : %w", err)
	}
	id, _ := cli.LireSecret(ctx, "ceffio-identity", "openbao-oidc", "client-id")
	secret, _ := cli.LireSecret(ctx, "ceffio-identity", "openbao-oidc", "client-secret")
	if id == "" || secret == "" {
		return fmt.Errorf("Secret openbao-oidc absent ou incomplet dans ceffio-identity")
	}

	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return err
	}
	sortie, err := baoAvecJeton(ctx, cli, adm, "auth", "list")
	if err != nil {
		return fmt.Errorf("lecture des méthodes d'authentification : %w", err)
	}
	if !strings.Contains(sortie, "oidc/") {
		if _, err := baoAvecJeton(ctx, cli, adm, "auth", "enable", "oidc"); err != nil {
			return fmt.Errorf("activation de l'authentification OIDC : %w", err)
		}
		fmt.Println("  ∙ authentification OIDC activée")
	}

	// L'ADRESSE DE DÉCOUVERTE EST CELLE QUE VOIT LE NAVIGATEUR, et c'est
	// volontaire : Keycloak signe ses jetons en annonçant SON adresse publique,
	// et le coffre vérifie que l'émetteur correspond. Une adresse interne ferait
	// échouer la vérification, avec un message qui parle d'émetteur et non
	// d'adresse. Vérifié : le coffre joint bien l'adresse publique depuis le
	// cluster.
	emetteur := "https://keycloak." + domaine + "/realms/ceffio"
	cfg := map[string]any{
		"oidc_discovery_url": emetteur,
		"oidc_client_id":     id,
		"oidc_client_secret": secret,
		"default_role":       "adminceffio",
	}
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/oidc-config.json", cfg); err != nil {
		return err
	}
	_, errCfg := baoAvecJeton(ctx, cli, adm, "write", "auth/oidc/config", "@/tmp/oidc-config.json")
	// Le fichier a porté le secret du client : il disparaît dès qu'il a servi,
	// quel que soit le résultat.
	retirerPayloadCoffre(ctx, cli, "/tmp/oidc-config.json")
	if errCfg != nil {
		return fmt.Errorf("configuration OIDC : %w", errCfg)
	}

	// LE RÔLE EST LIÉ SUR L'ADRESSE ÉLECTRONIQUE, jamais sur le « sub ».
	//
	// « sub » est un identifiant interne à Keycloak : il change si le compte est
	// recréé, et le rôle cesserait alors d'accepter la bonne personne sans que
	// rien ne le signale. L'adresse est ce que la personne connaît, ce qu'elle
	// tape pour se connecter, et ce qu'on veut lire dans la définition du rôle.
	//
	// POURQUOI LES CONDITIONS PASSENT PAR UN FICHIER : « bound_claims » attend un
	// OBJET, et la ligne de commande ne sait transmettre que du texte. Écrire
	// « bound_claims={"email":[...]} » fait répondre « got unconvertible type
	// 'string' » — le rôle n'est pas créé, et le message ne dit pas comment s'y
	// prendre. Une charge JSON complète, lue depuis un fichier, est analysée
	// correctement. Constaté en service, aide de la commande à l'appui.
	retours := []string{
		"https://bao." + domaine + "/ui/vault/auth/oidc/oidc/callback",
		"https://bao." + domaine + "/vault/auth/oidc/oidc/callback",
		"http://localhost:8250/oidc/callback",
	}
	role := map[string]any{
		"role_type":             "oidc",
		"user_claim":            "email",
		"bound_claims":          map[string]any{"email": []string{"adminceffio@ceffio.local"}},
		"policies":              "ceffio-administration",
		"allowed_redirect_uris": retours,
		"oidc_scopes":           []string{"email", "profile"},
		"ttl":                   "2h",
	}
	if err := ecrirePayloadCoffre(ctx, cli, "/tmp/oidc-role.json", role); err != nil {
		return err
	}
	_, errRole := baoAvecJeton(ctx, cli, adm, "write", "auth/oidc/role/adminceffio", "@/tmp/oidc-role.json")
	retirerPayloadCoffre(ctx, cli, "/tmp/oidc-role.json")
	if errRole != nil {
		return fmt.Errorf("rôle OIDC « adminceffio » : %w", errRole)
	}
	fmt.Println("  ∙ authentification des personnes configurée (adminceffio@ceffio.local)")
	return nil
}

// retirerJetonRacine révoque le jeton racine dès que le jeton dérivé existe.
//
// Un jeton maître qui survit à la mise en place est un défaut, pas une
// commodité. Les clés de récupération permettent d'en régénérer un si besoin.
//
// SI LE JETON RACINE N'EST DÉJÀ PLUS LÀ, ce n'est pas une erreur : c'est le cas
// nominal d'un redéploiement, où la révocation a déjà eu lieu. Le dire comme un
// avertissement ferait croire à un incident à chaque relance.
func retirerJetonRacine(ctx context.Context, cli *k8sapi.Client) error {
	racine, err := cli.LireSecret(ctx, ns, "openbao-recovery", "root-token")
	if err != nil {
		return fmt.Errorf("jeton racine illisible : %w", err)
	}
	if racine == "" {
		fmt.Println("  ∙ jeton racine déjà révoqué (rien à faire)")
		return nil
	}
	// La syntaxe compte : `-self` est une OPTION de `token revoke`, pas une
	// sous-commande. Écrire `token revoke-self` affiche l'aide du groupe et sort
	// en erreur — constaté en service, et le jeton racine restait alors vivant.
	if _, err := baoAvecJeton(ctx, cli, racine, "token", "revoke", "-self"); err != nil {
		return err
	}
	// On retire aussi la copie locale : un jeton révoqué n'a plus à traîner.
	if err := cli.SupprimerSecret(ctx, ns, "openbao-recovery"); err != nil {
		return err
	}
	fmt.Println("  ∙ jeton racine révoqué (les clés de récupération permettent d'en régénérer un)")
	return nil
}

// ---------------------------------------------------------------------------
// 7. Vérification de bout en bout
// ---------------------------------------------------------------------------

// verifierAllerRetour écrit un secret, le relit, et vérifie que le REFUS
// fonctionne aussi.
//
// POURQUOI LES DEUX : un coffre dont on n'a prouvé que les autorisations n'a rien
// prouvé. La moitié d'un contrôle d'accès, c'est ce qu'il refuse.
func verifierAllerRetour(ctx context.Context, cli *k8sapi.Client, jeton string) error {
	const (
		// LA VÉRIFICATION ÉCRIT DANS LE PÉRIMÈTRE DE LA POLITIQUE, et pas
		// ailleurs. C'est une leçon mesurée : la première version écrivait dans
		// `kv/diagnostic/…`, hors de `kv/data/ceffio/*` — le jeton dérivé
		// répondait donc 403, à juste titre, et le déploiement échouait sur un
		// refus qui était en réalité le comportement CORRECT du contrôle d'accès.
		composant = "ceffio/diagnostic"
		nom       = "aller-retour"
		valeur    = "verification-ceffio"
		// Le chemin de refus doit être HORS du périmètre : c'est ce qui prouve
		// que la politique n'est pas trop large.
		cheminInterdit = "kv/hors-perimetre/x"
	)
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "put", "kv/"+composant+"/"+nom, nom+"="+valeur); err != nil {
		return fmt.Errorf("écriture : %w", err)
	}
	sortie, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", "-field="+nom, "kv/"+composant+"/"+nom)
	if err != nil {
		return fmt.Errorf("relecture : %w", err)
	}
	if !strings.Contains(sortie, valeur) {
		return fmt.Errorf("la valeur relue ne correspond pas (le coffre répond mais ne rend pas ce qu'on a écrit)")
	}

	// Le refus : un chemin HORS du périmètre de la politique doit être rejeté.
	// Sans ce contrôle, une politique trop large passerait inaperçue.
	if _, err := baoAvecJeton(ctx, cli, jeton, "kv", "get", cheminInterdit); err == nil {
		return fmt.Errorf("le jeton dérivé lit un chemin qu'il ne devrait pas — politique trop large")
	}

	// On nettoie la trace du diagnostic.
	_, _ = baoAvecJeton(ctx, cli, jeton, "kv", "delete", "kv/"+composant+"/"+nom)
	fmt.Println("  ∙ aller-retour vérifié (écriture, relecture, ET refus d'un chemin hors périmètre)")
	return nil
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

// extraitJSON isole l'objet JSON d'une sortie qui peut porter des avertissements
// avant ou après. Sans cela, un avertissement ferait échouer la lecture.
func extraitJSON(s string) string {
	debut := strings.Index(s, "{")
	fin := strings.LastIndex(s, "}")
	if debut < 0 || fin <= debut {
		return "{}"
	}
	return s[debut : fin+1]
}

// baoReessai exécute une commande du coffre en RÉESSAYANT sur les échecs
// transitoires.
//
// POURQUOI C'EST NÉCESSAIRE, ET MESURÉ : `operator init` monte la barrière de
// sécurité du coffre, ce qui provoque un bref redémarrage du cœur. Pendant ces
// quelques secondes, le port répond « connection refused ». Ce n'est pas une
// panne : c'est une course entre une commande et le redémarrage qu'elle vient de
// déclencher. Sans réessai, le déploiement échouait exactement là — sur l'étape
// qui venait de réussir.
func baoReessai(ctx context.Context, cli *k8sapi.Client, args ...string) (string, error) {
	var sortie string
	var err error
	for i := 0; i < 6; i++ {
		sortie, err = cli.Executer(ctx, ns, pod, "openbao", append([]string{"bao"}, args...)...)
		if err == nil {
			return sortie, nil
		}
		if !transitoire(err) {
			return sortie, err
		}
		// Attente croissante : un redémarrage de cœur prend quelques secondes.
		time.Sleep(time.Duration(3*(i+1)) * time.Second)
	}
	return sortie, err
}

// transitoire dit si l'erreur peut disparaître en réessayant.
//
// On ne réessaie QUE ce qui est transitoire : insister sur une erreur de
// configuration ne ferait que retarder l'aveu d'échec, et masquerait la cause.
func transitoire(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	for _, motif := range []string{
		"connection refused",
		"connection reset",
		"i/o timeout",
		"unexpected eof",
		"unable to upgrade connection",
		"server is starting",
		"is the server running",
	} {
		if strings.Contains(m, motif) {
			return true
		}
	}
	return false
}

// etatCoffre rend l'état lisible du coffre, ou "" s'il n'a pas pu être lu.
//
// ON NE SE FIE PAS AU CODE DE SORTIE DE `bao status`. Cet outil sort en erreur
// quand le coffre est scellé ou non initialisé : c'est un choix de conception,
// pensé pour les scripts qui testent « est-ce prêt ? ». Ici, ces états sont
// précisément ce qu'on veut LIRE.
//
// LES DEUX SORTES D'ÉCHEC SONT SÉPARÉES, et c'est le cœur de ce module :
//
//   - l'EXÉCUTION A ÉCHOUÉ (pod absent, connexion refusée) : la sortie est un
//     message d'erreur, pas du JSON. La traiter comme un état faisait croire à un
//     coffre « non initialisé » qui n'avait jamais été interrogé — et le
//     déploiement poursuivait sur un serveur injoignable ;
//   - la COMMANDE A RENDU UN VERDICT (code non nul, sortie JSON valide) : c'est
//     un état, et on le lit.
//
// Le contrôle `"initialized"` dans la sortie est le garde-fou : sans lui, une
// réponse inattendue redevient un objet vide, et l'objet vide redevient un état
// plausible.
func etatCoffre(ctx context.Context, cli *k8sapi.Client) (string, error) {
	sortie, errExec := cli.Executer(ctx, ns, pod, "openbao", "bao", "status", "-format=json")
	brut := extraitJSON(sortie)
	if !strings.Contains(brut, `"initialized"`) {
		if errExec != nil {
			return "", fmt.Errorf("le coffre n'a pas pu être interrogé : %w", errExec)
		}
		return "", fmt.Errorf("réponse inattendue du coffre : %.100s", strings.TrimSpace(sortie))
	}
	var st struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(brut), &st); err != nil {
		return "", fmt.Errorf("état illisible : %w", err)
	}
	switch {
	case !st.Initialized:
		return "non initialisé", nil
	case st.Sealed:
		return "SCELLÉ", nil
	default:
		return "descellé", nil
	}
}

// baoAvecReessai a été retiré avec baoRacine : les deux ne servaient qu'à
// joindre le jeton racine, et l'administration passe désormais par
// jetonAdministration, qui essaie le jeton d'installation AVANT le racine. Du
// code d'administration qui ne cherche que le racine ne fonctionne plus après la
// mise en place ; le garder aurait été un piège pour la prochaine lecture.

// commandeBao assemble la ligne de commande, en PROTÉGEANT chaque argument.
//
// POURQUOI PROTÉGER : les valeurs passées au coffre contiennent parfois des
// caractères que le shell interprète — accolades, guillemets, virgules. Sans
// protection, le shell retire les guillemets et le coffre reçoit une valeur
// DIFFÉRENTE de celle qu'on croit avoir écrite, sans que rien ne le signale.
//
// POURQUOI LA PROTECTION NE SUFFIT PAS POUR UN OBJET : un champ structuré ne peut
// pas passer par la ligne de commande du tout, même correctement protégé. Ces
// charges passent par un fichier — voir ecrirePayloadCoffre.
func commandeBao(args []string) string {
	proteges := make([]string, 0, len(args))
	for _, a := range args {
		// Guillemets simples : à l'intérieur, le shell n'interprète plus rien.
		// L'apostrophe elle-même se referme et s'échappe.
		proteges = append(proteges, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return strings.Join(proteges, " ")
}

// baoAvecJeton exécute une commande avec un jeton explicite, transmis par
// l'ENTRÉE STANDARD — jamais en argument.
//
// POURQUOI C'EST IMPORTANT : un jeton passé en argument apparaît dans la table
// des processus du pod, lisible par tout ce qui peut observer la machine.
// L'entrée standard ne laisse aucune trace de ce genre, et le jeton n'est pas non
// plus écrit sur le disque du conteneur.
func baoAvecJeton(ctx context.Context, cli *k8sapi.Client, jeton string, args ...string) (string, error) {
	// Le shell lit le jeton sur son entrée standard et le pose dans
	// l'environnement de la commande bao. Il n'apparaît donc nulle part ailleurs.
	script := fmt.Sprintf("IFS= read -r TOK; BAO_TOKEN=\"$TOK\" exec bao %s", commandeBao(args))

	var sortie string
	var err error
	for i := 0; i < 6; i++ {
		sortie, err = cli.ExecuterAvecEntree(ctx, ns, pod, "openbao", jeton, "sh", "-c", script)
		if err == nil {
			return sortie, nil
		}
		if !transitoire(err) {
			return sortie, err
		}
		time.Sleep(time.Duration(3*(i+1)) * time.Second)
	}
	return sortie, err
}
