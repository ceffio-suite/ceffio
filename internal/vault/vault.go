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
// LE SECRET-ZÉRO, ET POURQUOI IL EST ICI : pour que le coffre soit utilisable
// sans intervention humaine, il se descelle tout seul, grâce au sceau
// « static » d'OpenBao : une clé de 32 octets lue depuis un fichier. Cette clé
// vit dans un Secret Kubernetes, sur la même machine que le coffre.
//
//	C'est un compromis assumé, pas un oubli.
//
// Qui obtient la machine obtient le coffre. C'était déjà vrai avant : les
// secrets étaient dans des Secrets Kubernetes, sur cette même machine. La
// différence est qu'à partir d'ici ils sont centralisés, traçables et
// rotables — trois propriétés qu'on n'avait pas. Déplacer le coffre sur une
// autre machine ne supprimerait pas ce point faible, cela ajouterait un
// composant à administrer.
//
// POURQUOI PAS DE DESCELlement MANUEL : demander une intervention humaine à
// chaque redémarrage ferait d'un redémarrage une panne, dans un produit dont
// l'argument est « une commande et ça tourne ». Le choix est fait en connaissance
// de cause.
//
// LE COFFRE EST OPTIONNEL (voir internal/secrets) : si ce module échoue, le
// déploiement continue et les secrets restent dans Kubernetes. Une panne du
// coffre ne doit jamais empêcher la suite de tourner — c'est ce qui sépare
// « centraliser pour la robustesse » de « ajouter un point de panne ».
package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

const (
	// Version réelle constatée sur Docker Hub (pas inventée) : 2.7.1, publiée
	// le 2026-10-01.
	openbaoImage = "docker.io/openbao/openbao:2.7.1"

	ns      = "ceffio-vault"
	service = "openbao"

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
//  7. un aller-retour réel : écrire, relire, et prouver que ça se lit.
//
// Ne rend JAMAIS d'erreur fatale pour la suite : en cas d'échec, un
// avertissement est imprimé et Resultat{Pret:false} est rendu, pour que le
// déploiement se poursuive avec les Secrets Kubernetes.
//
// PAS DE PARAMÈTRE DE DOMAINE, VOLONTAIREMENT : le coffre n'en a pas besoin
// aujourd'hui. Le jour où il sera exposé en https://bao.<domaine>, l'entrée
// publique demandera le domaine — et c'est à ce moment-là qu'il faudra ajouter
// le paramètre, pas avant. Un paramètre que rien n'utilise finit par être
// rempli au hasard, puis lu par erreur.
func Deploy(ctx context.Context) *Resultat {
	fmt.Println("\nDéploiement du coffre de secrets (OpenBao)...")

	if err := ensureNamespace(ctx); err != nil {
		fmt.Printf("  ∙ coffre non déployé (namespace) : %v\n", err)
		return &Resultat{}
	}
	if err := ensureCleDescellement(ctx); err != nil {
		fmt.Printf("  ∙ coffre non déployé (clé de descellement) : %v\n", err)
		return &Resultat{}
	}
	if err := applyConfig(ctx); err != nil {
		fmt.Printf("  ∙ coffre non déployé (configuration) : %v\n", err)
		return &Resultat{}
	}
	if err := applyWorkload(ctx); err != nil {
		fmt.Printf("  ∙ coffre non déployé (charge de travail) : %v\n", err)
		return &Resultat{}
	}
	if err := waitReady(ctx); err != nil {
		fmt.Printf("  ∙ coffre injoignable : %v\n", err)
		return &Resultat{}
	}
	if err := initialiser(ctx); err != nil {
		fmt.Printf("  ∙ initialisation impossible : %v\n", err)
		return &Resultat{}
	}
	if err := monterMoteurKV(ctx); err != nil {
		fmt.Printf("  ∙ moteur KV non monté : %v\n", err)
		return &Resultat{}
	}
	jeton, err := poserPolitiqueEtJeton(ctx)
	if err != nil {
		fmt.Printf("  ∙ jeton d'administration non créé : %v\n", err)
		return &Resultat{}
	}
	if err := retirerJetonRacine(ctx); err != nil {
		// Non bloquant : le jeton racine reste, et on le DIT. Un jeton maître
		// qui survit sans le dire est un défaut ; qui survit en le signalant est
		// un incident à traiter.
		fmt.Printf("  ∙ ATTENTION : jeton racine non révoqué (%v) — à traiter\n", err)
	}
	if err := verifierAllerRetour(ctx, jeton); err != nil {
		fmt.Printf("  ∙ vérification de bout en bout échouée : %v\n", err)
		return &Resultat{}
	}

	fmt.Printf("✓ Coffre OpenBao déployé (%s, %s)\n", openbaoImage, ns)
	// L'adresse rendue est celle du NodePort, et non le nom de service interne.
	//
	// POURQUOI : l'installation tourne SUR LA MACHINE, pas dans le cluster. Le
	// nom openbao.ceffio-vault.svc n'y résout pas — un coffre que l'installation
	// ne peut pas atteindre ne sert à rien. Le NodePort est joignable depuis la
	// machine ET depuis les pods, ce qui donne une seule adresse aux deux.
	//
	// CE QU'ON ASSUME ICI, ET QU'IL FAUT DIRE : ce NodePort parle en clair sur le
	// réseau de la machine. C'est un point à corriger quand l'ingress TLS de la
	// suite sera en place — le coffre y gagnera une adresse https://bao.<domaine>.
	// Tant que ce n'est pas fait, le trafic du coffre n'est pas chiffré.
	noeud := os.Getenv("CEFFIO_NOEUD")
	if noeud == "" {
		noeud = "127.0.0.1"
	}
	return &Resultat{
		Adresse: fmt.Sprintf("http://%s:32000", noeud),
		Jeton:   jeton,
		Pret:    true,
	}
}

// ---------------------------------------------------------------------------
// 1. Namespace et clé de descellement
// ---------------------------------------------------------------------------

func ensureNamespace(ctx context.Context) error {
	_, err := kube(ctx, "create", "namespace", ns)
	return err
}

// ensureCleDescellement crée la clé de 32 octets du sceau « static », si elle
// n'existe pas. On ne la régénère JAMAIS : la régénérer rendrait le coffre
// illisible, puisque les données existantes sont chiffrées avec elle.
func ensureCleDescellement(ctx context.Context) error {
	if _, err := kube(ctx, "get", "secret", "openbao-unseal-key", "-n", ns); err == nil {
		return nil
	}
	// 32 octets aléatoires, exactement ce qu'exige le sceau statique
	// (AES-256-GCM). Une valeur plus courte fait échouer le démarrage du
	// serveur, une valeur plus longue aussi.
	cle, err := kube(ctx, "run", "gen-cle", "--rm", "-i", "--restart=Never",
		"--image="+openbaoImage, "-n", ns, "--command", "--",
		"sh", "-c", "head -c 32 /dev/urandom | base64 -w0")
	if err != nil {
		return fmt.Errorf("génération de la clé : %w", err)
	}
	cle = strings.TrimSpace(cle)
	if cle == "" {
		return fmt.Errorf("clé vide")
	}
	_, err = kube(ctx, "create", "secret", "generic", "openbao-unseal-key",
		"-n", ns, "--from-literal=unseal.key="+cle)
	if err != nil {
		return fmt.Errorf("pose de la clé : %w", err)
	}
	fmt.Println("  ∙ clé de descellement créée (32 octets, le secret-zéro)")
	return nil
}

// ---------------------------------------------------------------------------
// 2. Configuration : stockage, écoute, sceau, AUDIT
// ---------------------------------------------------------------------------

// ConfigMap de configuration.
//
// TROIS CHOIX À EXPLIQUER :
//
//   - L'ÉCOUTE SE FAIT SANS TLS À L'INTÉRIEUR DU CLUSTER. Le trafic ne quitte
//     pas le réseau des pods. Le dire explicitement plutôt que de le laisser
//     deviner : un serveur TLS qui reçoit du clair répond 400, donc un code
//     d'erreur ne prouve pas qu'on parle à un serveur en clair.
//
//   - LE JOURNAL D'AUDIT EST DÉCLARÉ ICI, dans le fichier de configuration, et
//     non activé par une commande : c'est la forme que la version actuelle
//     d'OpenBao attend, et elle survit aux redémarrages. Retirer ce bloc
//     supprimerait le journal.
//
//   - LE DESCELlement EST AUTOMATIQUE, par le sceau statique. Voir l'entête du
//     paquet pour le compromis.
func configManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: openbao-config
  namespace: %[1]s
data:
  openbao.hcl: |
    ui = true
    disable_mlock = true

    storage "raft" {
      path    = "%[2]s"
      node_id = "openbao-0"
    }

    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = true
    }

    seal "static" {
      current_key_id = "ceffio-1"
      current_key    = "file://%[3]s"
    }

    audit "file" {
      path        = "fichier"
      description = "Journal d'audit Ceffio"
      options = {
        file_path = "%[4]s"
      }
    }

    api_addr     = "http://%[5]s.%[1]s.svc:8200"
    cluster_addr = "http://%[5]s.%[1]s.svc:8201"
`, ns, cheminDonnees, cheminCle, cheminAudit, service)
}

func applyConfig(ctx context.Context) error {
	return appliquer(ctx, configManifest())
}

// ---------------------------------------------------------------------------
// 3. Charge de travail
// ---------------------------------------------------------------------------

// applyWorkload pose le StatefulSet, le Service et le PVC.
//
// UN SEUL NŒUD, ET C'EST UN CHOIX : le stockage raft sait faire un cluster, mais
// une PME n'a pas besoin de trois coffres pour trois secrets. Le jour où il en
// faudra un, c'est le nombre de réplicas qui changera — pas la conception.
func applyWorkload(ctx context.Context) error {
	return appliquer(ctx, workloadManifest())
}

func workloadManifest() string {
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
      nodePort: 32000
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
    spec:
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
            httpGet:
              path: /v1/sys/health?standbyok=true
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
`, service, ns, openbaoImage, cheminDonnees)
}

// waitReady attend que le serveur réponde. Il peut répondre 501 (non
// initialisé) : c'est un état valide, pas une erreur.
func waitReady(ctx context.Context) error {
	limite := time.Now().Add(180 * time.Second)
	for time.Now().Before(limite) {
		etat, _ := etatCoffre(ctx)
		if etat != "" {
			fmt.Printf("  ∙ coffre joignable (état : %s)\n", etat)
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("le coffre n'a pas répondu en 180 s")
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
func initialiser(ctx context.Context) error {
	initie, err := dejaInitialise(ctx)
	if err != nil {
		return err
	}
	if initie {
		fmt.Println("  ∙ coffre déjà initialisé")
		return nil
	}

	sortie, err := bao(ctx, "operator", "init",
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

	// Les clés sont rangées dans un Secret, JAMAIS imprimées.
	args := []string{"create", "secret", "generic", "openbao-recovery", "-n", ns,
		"--from-literal=root-token=" + res.RootToken}
	for i, k := range res.RecoveryKeys {
		args = append(args, fmt.Sprintf("--from-literal=recovery-%d=%s", i, k))
	}
	if _, err := kube(ctx, args...); err != nil {
		return fmt.Errorf("rangement des clés de récupération : %w", err)
	}
	fmt.Println("  ∙ coffre initialisé (clés rangées dans openbao-recovery, non affichées)")
	return nil
}

// dejaInitialise interroge l'état : 501 signifie « pas initialisé », 200 ou 429
// « déjà initialisé ». On ne déduit pas d'un code d'erreur générique.
func dejaInitialise(ctx context.Context) (bool, error) {
	code, err := codeHTTP(ctx, "/v1/sys/health")
	if err != nil {
		return false, err
	}
	switch code {
	case "200", "429", "472", "473":
		return true, nil
	case "501":
		return false, nil
	}
	// Un 5xx après initialisation (coffre scellé, par exemple) compte comme
	// initialisé : c'est l'état du serveur, pas celui du stockage.
	return true, nil
}

// ---------------------------------------------------------------------------
// 5. Moteur KV
// ---------------------------------------------------------------------------

// monterMoteurKV monte un KV versionné au chemin « kv », la convention que
// internal/secrets attend par défaut (BAO_MOTEUR).
func monterMoteurKV(ctx context.Context) error {
	sortie, err := baoRacine(ctx, "secrets", "list")
	if err != nil {
		return err
	}
	if strings.Contains(sortie, "kv/") {
		fmt.Println("  ∙ moteur KV déjà monté")
		return nil
	}
	if _, err := baoRacine(ctx, "secrets", "enable", "-path=kv", "-version=2", "kv"); err != nil {
		return fmt.Errorf("montage du moteur KV : %w", err)
	}
	fmt.Println("  ∙ moteur KV versionné monté sur « kv »")
	return nil
}

// ---------------------------------------------------------------------------
// 6. Politique et jeton d'administration, puis révocation du racine
// ---------------------------------------------------------------------------

// poserPolitiqueEtJeton crée une politique d'administration, en dérive un jeton,
// et rend ce jeton.
//
// POURQUOI PAS GARDER LE JETON RACINE : il ne peut rien refuser. Le garder pour
// « simplifier » revient à laisser une clé passe-partout dans un tiroir. Le
// jeton dérivé porte exactement les droits listés ci-dessous, et se révoque.
func poserPolitiqueEtJeton(ctx context.Context) (string, error) {
	// La politique couvre les besoins RÉELS de Ceffio : lire et écrire les
	// secrets de la suite, lire les métadonnées, et rien d'autre. Les actions
	// d'administration du coffre lui-même (montage de moteurs, politiques,
	// authentification) restent hors de portée d'un jeton quotidien — c'est le
	// sens de la dernière vérification de verifierAllerRetour.
	//
	// ELLE EST ÉCRITE PAR HEREDOC, et non passée en argument : `bao policy write`
	// attend un chemin de fichier ou `-` pour stdin, et une politique tenant sur
	// une ligne de commande serait tronquée au premier retour à la ligne.
	regle := `path "kv/data/ceffio/*" { capabilities = ["create","read","update","list"] }
path "kv/metadata/ceffio/*" { capabilities = ["read","list"] }
path "kv/delete/ceffio/*" { capabilities = ["update"] }
path "kv/list/ceffio" { capabilities = ["list"] }`
	script := fmt.Sprintf("cat > /tmp/politique.hcl <<'FIN_POLITIQUE'\n%s\nFIN_POLITIQUE\n", regle)
	if _, err := execPod(ctx, "sh", "-c", script); err != nil {
		return "", fmt.Errorf("écriture de la politique : %w", err)
	}
	if _, err := baoRacine(ctx, "policy", "write", "ceffio-admin", "/tmp/politique.hcl"); err != nil {
		return "", fmt.Errorf("politique : %w", err)
	}
	sortie, err := baoRacine(ctx, "token", "create", "-policy=ceffio-admin",
		"-period=768h", "-format=json", "-display-name=ceffio-installation")
	if err != nil {
		return "", fmt.Errorf("création du jeton : %w", err)
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &res); err != nil {
		return "", fmt.Errorf("réponse illisible : %w", err)
	}
	if res.Auth.ClientToken == "" {
		return "", fmt.Errorf("jeton vide")
	}
	// Le jeton est rangé pour que les redéploiements le réutilisent, plutôt que
	// d'en fabriquer un nouveau à chaque fois — un jeton qui s'accumule est un
	// jeton qu'on oublie de révoquer.
	_, _ = kube(ctx, "delete", "secret", "openbao-token", "-n", ns)
	if _, err := kube(ctx, "create", "secret", "generic", "openbao-token", "-n", ns,
		"--from-literal=token="+res.Auth.ClientToken); err != nil {
		return "", fmt.Errorf("rangement du jeton : %w", err)
	}
	fmt.Println("  ∙ politique « ceffio-admin » et jeton dérivé posés")
	return res.Auth.ClientToken, nil
}

// retirerJetonRacine révoque le jeton racine dès que le jeton dérivé existe.
//
// Un jeton maître qui survit à la mise en place est un défaut, pas une
// commodité. Les clés de récupération permettent d'en régénérer un si besoin.
func retirerJetonRacine(ctx context.Context) error {
	racine, err := lireSecret(ctx, "openbao-recovery", "root-token")
	if err != nil || racine == "" {
		return fmt.Errorf("jeton racine illisible : %v", err)
	}
	if _, err := baoAvecJeton(ctx, racine, "token", "revoke-self"); err != nil {
		return err
	}
	// On retire aussi la copie locale : un jeton révoqué n'a plus à traîner.
	_, _ = kube(ctx, "delete", "secret", "openbao-recovery", "-n", ns)
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
func verifierAllerRetour(ctx context.Context, jeton string) error {
	const (
		composant = "diagnostic"
		nom       = "aller-retour"
		valeur    = "verification-ceffio"
	)
	if _, err := baoAvecJeton(ctx, jeton, "kv", "put", "kv/"+composant+"/"+nom, nom+"="+valeur); err != nil {
		return fmt.Errorf("écriture : %w", err)
	}
	sortie, err := baoAvecJeton(ctx, jeton, "kv", "get", "-field="+nom, "kv/"+composant+"/"+nom)
	if err != nil {
		return fmt.Errorf("relecture : %w", err)
	}
	if !strings.Contains(sortie, valeur) {
		return fmt.Errorf("la valeur relue ne correspond pas (le coffre répond mais ne rend pas ce qu'on a écrit)")
	}

	// Le refus : un chemin HORS du périmètre de la politique doit être rejeté.
	// Sans ce contrôle, une politique trop large passerait inaperçue.
	if _, err := baoAvecJeton(ctx, jeton, "kv", "get", "kv/ceffio-interdit/x"); err == nil {
		return fmt.Errorf("le jeton dérivé lit un chemin qu'il ne devrait pas — politique trop large")
	}

	// On nettoie la trace du diagnostic.
	_, _ = baoAvecJeton(ctx, jeton, "kv", "delete", "kv/"+composant+"/"+nom)
	fmt.Println("  ∙ aller-retour vérifié (écriture, relecture, ET refus d'un chemin hors périmètre)")
	return nil
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

// appliquer pose un manifeste multi-documents via `kubectl apply -f -`.
func appliquer(ctx context.Context, manifeste string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(manifeste)
	sortie, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %.200s", err, string(sortie))
	}
	return nil
}

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

// bao exécute une commande `bao` DANS le pod, en tant que racine.
//
// POURQUOI PAR EXEC ET PAS PAR HTTP : l'installation tourne sur la machine, et
// le service du coffre est interne au cluster. Passer par exec évite d'exposer
// le coffre avant que l'ingress n'existe — et évite de faire transiter un jeton
// racine sur le réseau. C'est le motif déjà utilisé pour `occ` (Nextcloud).
func bao(ctx context.Context, args ...string) (string, error) {
	return execPod(ctx, args...)
}

// baoRacine exécute une commande d'administration avec le jeton racine.
func baoRacine(ctx context.Context, args ...string) (string, error) {
	racine, err := lireSecret(ctx, "openbao-recovery", "root-token")
	if err != nil || racine == "" {
		return "", fmt.Errorf("jeton racine indisponible : %v", err)
	}
	return baoAvecJeton(ctx, racine, args...)
}

// baoAvecJeton exécute une commande avec un jeton explicite, transmis par
// l'ENTRÉE STANDARD — jamais en argument.
//
// POURQUOI C'EST IMPORTANT ICI : un jeton passé en argument apparaît dans la
// table des processus du pod, lisible par tout ce qui peut observer la machine.
// L'entrée standard ne laisse aucune trace de ce genre, et le jeton n'est pas
// non plus écrit sur le disque du conteneur.
func baoAvecJeton(ctx context.Context, jeton string, args ...string) (string, error) {
	script := fmt.Sprintf("IFS= read -r TOK; BAO_TOKEN=\"$TOK\" bao %s", strings.Join(args, " "))
	return execPodAvecEntree(ctx, jeton, "sh", "-c", script)
}

// execPod lance une commande dans le conteneur du coffre.
func execPod(ctx context.Context, args ...string) (string, error) {
	return execPodAvecEntree(ctx, "", args...)
}

// execPodAvecEntree lance une commande dans le conteneur du coffre, en
// alimentant éventuellement son entrée standard.
func execPodAvecEntree(ctx context.Context, entree string, args ...string) (string, error) {
	base := []string{"exec", "statefulset/openbao", "-n", ns, "-c", "openbao"}
	if entree != "" {
		// -i est nécessaire pour que l'entrée standard soit transmise.
		base = append(base, "-i")
	}
	base = append(base, "--")
	cmd := k8s.Command(ctx, "kubectl", append(base, args...)...)
	cmd.Env = k8s.Env()
	if entree != "" {
		cmd.Stdin = strings.NewReader(entree + "\n")
	}
	sortie, err := cmd.CombinedOutput()
	retour := strings.TrimSpace(string(sortie))
	if err != nil {
		return retour, fmt.Errorf("%v: %.200s", err, retour)
	}
	return retour, nil
}

// etatCoffre rend l'état lisible du coffre, ou "" s'il ne répond pas.
func etatCoffre(ctx context.Context) (string, error) {
	sortie, err := bao(ctx, "status", "-format=json")
	if err != nil {
		return "", err
	}
	var st struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.Unmarshal([]byte(extraitJSON(sortie)), &st); err != nil {
		return "", err
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

// codeHTTP rend le code de la réponse d'un point d'API, sans interpréter.
func codeHTTP(ctx context.Context, chemin string) (string, error) {
	sortie, _ := execPod(ctx, "sh", "-c",
		fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' http://127.0.0.1:8200%s", chemin))
	c := strings.TrimSpace(sortie)
	if c == "" {
		return "", fmt.Errorf("aucune réponse du coffre")
	}
	return c, nil
}

// lireSecret lit une clé d'un Secret Kubernetes. Rend "" sans erreur si la clé
// est absente du Secret.
func lireSecret(ctx context.Context, nom, cle string) (string, error) {
	sortie, err := kube(ctx, "get", "secret", nom, "-n", ns, "-o",
		fmt.Sprintf("jsonpath={.data.%s}", cle))
	if err != nil {
		return "", err
	}
	if sortie == "" {
		return "", nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sortie))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func kube(ctx context.Context, args ...string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", args...)
	cmd.Env = k8s.Env()
	sortie, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(sortie)), err
}
