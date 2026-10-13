// Package sso orchestre l'authentification unique (SSO) via Keycloak sur les
// applications de la suite : création idempotente des clients OIDC (Nextcloud,
// Synapse) dans le realm ceffio et stockage de leurs secrets en Kubernetes.
//
// Secrets générés au runtime, jamais en Git. Réutilisables à volonté
// (idempotence : si le secret k8s existe, on ne touche à rien).
package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	ns           = "ceffio-identity"
	realm        = "ceffio"
	keycloakDepl = "deploy/keycloak"
)

type client struct {
	app       string
	id        string
	redirects string
}

// clientsOIDC construit la liste des clients avec le domaine COURANT.
//
// Une redirect_uri doit être joignable par le NAVIGATEUR : les adresses
// internes du cluster (svc.cluster.local) et les anciens domaines de démo
// (demo.local) n'ont rien à y faire. Elles traînaient pourtant ici, figées —
// un vestige de l'installation d'origine.
//
// Chaque application reçoit son adresse publique, plus localhost pour le
// développement local.
func clientsOIDC(domain string) []client {
	return []client{
		{
			app:       "nextcloud",
			id:        "nextcloud",
			redirects: fmt.Sprintf("https://cloud.%s/apps/user_oidc/code,http://localhost/*", domain),
		},
		{
			// LE COFFRE A UN CLIENT À LUI, et deux adresses de retour : celle de
			// l'interface web, et celle de la ligne de commande. Ce ne sont pas
			// les mêmes chemins — la ligne de commande ouvre un petit serveur
			// local (8250) pour recevoir la réponse, puisqu'elle n'est pas un
			// navigateur.
			app: "openbao",
			id:  "openbao",
			redirects: fmt.Sprintf(
				"https://bao.%s/ui/vault/auth/oidc/oidc/callback,https://bao.%s/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback",
				domain, domain),
		},
		// NB : pas de client « jitsi » — Jitsi est en accès libre (SSO retiré
		// le 2026-10-09, voir internal/media/sans_sso.go). Les installations
		// existantes le voient supprimé par SupprimerClientOIDC.
	}
}

// EnsureOIDCClients garantit l'existence des clients OIDC Keycloak (nextcloud,
// synapse) avec un secret généré stocké en secret Kubernetes. Idempotent et
// auto-réparant : recrée un client absent (en réutilisant le secret stocké),
// et (re)pose le secret si manquant.
func EnsureOIDCClients(ctx context.Context, domain string) error {
	fmt.Println("Déploiement du SSO Keycloak (Phase 8)...")
	if domain == "" {
		return fmt.Errorf("domaine requis pour construire les redirect_uri OIDC")
	}
	for _, c := range clientsOIDC(domain) {
		existant := secretExists(ctx, c.app+"-oidc")
		if err := assurerUnClient(ctx, c); err != nil {
			return err
		}
		if !existant {
			fmt.Printf("∙ client OIDC %s créé (secret → %s-oidc)\n", c.id, c.app)
		} else {
			fmt.Printf("∙ client OIDC %s réconcilié (secret → %s-oidc)\n", c.id, c.app)
		}
	}
	fmt.Println("✓ Clients OIDC Keycloak prêts")
	return nil
}

// assurerUnClient crée le client s'il manque, (re)pose son secret dans Keycloak,
// et range le tout dans un Secret Kubernetes.
//
// FACTORISÉ PARCE QU'IL SERT DEUX FOIS : à l'installation complète, et au
// déploiement du coffre seul. Recopier ces quatre étapes aurait suffi à ce que
// les deux chemins divergent à la première correction.
func assurerUnClient(ctx context.Context, c client) error {
	uuid, err := ensureClient(ctx, c.id, c.redirects)
	if err != nil {
		return fmt.Errorf("client OIDC %s: %w", c.id, err)
	}
	// Réutilise le secret existant (les apps pointent dessus), sinon génère.
	//
	// LA VALEUR EST REPRISE DU COFFRE, ET ELLE NE CHANGE PAS : ce secret est connu de
	// Keycloak ET de l'application qui s'y connecte. En régénérer un casserait
	// l'authentification entre les deux, et le symptôme serait un échec de connexion
	// parfaitement muet sur la cause.
	//
	// L'ORDRE DES SOURCES COMPTE, et il n'est pas arbitraire : le coffre d'abord,
	// puis KEYCLOAK LUI-MÊME — c'est lui qui fait autorité sur le secret de son
	// propre client, et le relire là évite d'en inventer un nouveau alors que
	// l'application se connecte encore avec l'ancien. Générer n'est que le dernier
	// recours, quand ni le coffre ni Keycloak ne savent.
	secretVal, ok := lireClientOIDC(ctx, c.app)
	if !ok {
		if depuisKeycloak, errKC := lireSecretClientKeycloak(ctx, uuid); errKC == nil && depuisKeycloak != "" {
			secretVal, ok = depuisKeycloak, true
			fmt.Printf("∙ client OIDC %s : secret repris depuis Keycloak (absent du coffre)\n", c.id)
		}
	}
	if !ok {
		secretVal, err = genSecret(24)
		if err != nil {
			return err
		}
	}
	if err := setClientSecret(ctx, uuid, secretVal); err != nil {
		return fmt.Errorf("secret client %s: %w", c.id, err)
	}
	return ecrireClientOIDC(ctx, c.app, c.id, secretVal)
}

// lireClientOIDC lit le client OIDC dans le COFFRE.
func lireClientOIDC(ctx context.Context, app string) (string, bool) {
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), app, "oidc")
	if err != nil {
		return "", false
	}
	v := entree["client-secret"]
	return v, v != ""
}

// lireSecretClientKeycloak relit le secret d'un client AUPRÈS DE KEYCLOAK.
//
// POURQUOI CETTE SOURCE EXISTE : le coffre peut être en retard sur Keycloak — il est
// une copie de référence, pas le registre d'authentification. Quand les deux ont
// divergé, c'est Keycloak qui dit juste, puisque c'est avec lui que les applications
// s'authentifient.
func lireSecretClientKeycloak(ctx context.Context, uuid string) (string, error) {
	out, err := runKcadm(ctx, "get", "clients/"+uuid+"/client-secret")
	if err != nil {
		return "", err
	}
	var reponse struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &reponse); err != nil {
		return "", fmt.Errorf("réponse de Keycloak illisible : %w", err)
	}
	return reponse.Value, nil
}

// ecrireClientOIDC range le client OIDC au coffre, à l'emplacement du composant.
func ecrireClientOIDC(ctx context.Context, app, id, secret string) error {
	return secrets.EcrireDansCoffre(ctx, secrets.DepuisEnvironnement(), app, "oidc",
		map[string]string{"client-id": id, "client-secret": secret})
}

// AssurerClientCoffre garantit le client OIDC du coffre, et lui seul.
//
// EXPORTÉE PARCE QUE LE COFFRE EN A BESOIN À SON PROPRE DÉPLOIEMENT : `ceffio
// vault` doit pouvoir être relancé seul, sans rejouer toute la pile — c'est même
// sa raison d'être. La connaissance de Keycloak reste dans ce paquet ; le module
// du coffre demande le client et lit le Secret qui en résulte, plutôt que de
// parler à Keycloak lui-même.
func AssurerClientCoffre(ctx context.Context, domain string) error {
	for _, c := range clientsOIDC(domain) {
		if c.id == "openbao" {
			return assurerUnClient(ctx, c)
		}
	}
	return fmt.Errorf("client OIDC « openbao » absent de la liste : le coffre ne peut pas s'authentifier")
}

func ensureClient(ctx context.Context, clientID, redirects string) (string, error) {
	uuid, err := clientUUID(ctx, clientID)
	if err == nil && uuid != "" {
		return uuid, nil
	}
	out, err := runKcadm(ctx, "create", "clients",
		"-s", "clientId="+clientID,
		"-s", "enabled=true",
		"-s", "protocol=openid-connect",
		"-s", "publicClient=false",
		"-s", `redirectUris=["`+strings.ReplaceAll(redirects, ",", `","`)+`"]`)
	if err != nil {
		return "", err
	}
	id := parseID(out)
	if id == "" {
		return "", fmt.Errorf("création client %s sans id: %s", clientID, out)
	}
	return id, nil
}

func clientUUID(ctx context.Context, clientID string) (string, error) {
	out, err := runKcadm(ctx, "get", "clients", "-q", "clientId="+clientID, "--fields", "id")
	if err != nil {
		return "", err
	}
	var arr []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		return "", fmt.Errorf("parse clients: %w", err)
	}
	if len(arr) == 0 {
		return "", nil
	}
	return arr[0].ID, nil
}

func setClientSecret(ctx context.Context, uuid, secret string) error {
	out, err := runKcadm(ctx, "update", "clients/"+uuid, "-s", "secret="+secret)
	if err != nil {
		return fmt.Errorf("update secret: %w: %s", err, out)
	}
	return nil
}

func parseID(out string) string {
	re := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	return re.FindString(out)
}

// runKcadm exécute kcadm.sh dans le pod Keycloak et renvoie la sortie combinée.
//
// LES IDENTIFIANTS D'ADMINISTRATION VIENNENT DU COFFRE, plus de l'environnement du
// pod. La migration de Keycloak vers l'injecteur d'OpenBao a retiré KC_BOOTSTRAP_ADMIN_*
// du déploiement : ils ne vivent plus que dans le fichier rendu, que seule la commande
// de démarrage source. TOUT CE QUI S'EXÉCUTE ENSUITE dans le conteneur ne les voit
// donc plus — kcadm compris. La connexion partait avec un utilisateur VIDE et
// répondait « Invalid user credentials », un message qui ne dit rien de la cause.
//
// LE MOT DE PASSE PASSE PAR L'ENTRÉE STANDARD, jamais par la ligne de commande : un
// argument se lit dans /proc/<pid>/cmdline, et inspecter un processus ne doit pas
// suffire à révéler un secret.
func runKcadm(ctx context.Context, args ...string) (string, error) {
	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(), "keycloak", "admin")
	if err != nil {
		return "", fmt.Errorf("identifiants d'administration Keycloak illisibles au coffre : %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return "", fmt.Errorf("entrée keycloak/admin incomplète au coffre (username et password requis)")
	}
	// Injecte -r <realm> après le verbe : les clients OIDC vivent dans le realm
	// applicatif (ceffio), PAS master (realm admin de config credentials).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'"+realm+"'")
		}
	}
	script := `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + utilisateur + `' --password "$motdepasse" >/dev/null 2>&1 && ` +
		`/opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")

	cmd := exec.CommandContext(ctx, "kubectl", "exec", "-i", "-n", ns, keycloakDepl, "-c", "keycloak", "--", "sh", "-c", script)
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// L'ERREUR DOIT PORTER CE QUE LA COMMANDE A DIT. Un « exit status 1 » seul
		// ne dit rien : kcadm écrit la cause dans sa sortie, et la jeter oblige à
		// reproduire la commande à la main pour la lire — ce qui a coûté une heure.
		return strings.TrimSpace(string(out)),
			fmt.Errorf("kcadm %s : %w — %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func secretExists(ctx context.Context, name string) bool {
	err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns).Run()
	return err == nil
}

func readSecretVal(ctx context.Context, name, key string) (string, bool) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", name, "-n", ns, "-o", "jsonpath={.data."+key+"}").Output()
	if err != nil {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(b) == 0 {
		return "", false
	}
	return string(b), true
}

func createSecretS(ctx context.Context, name string, data map[string]string) error {
	args := []string{"kubectl", "create", "secret", "generic", name, "-n", ns, "--dry-run=client", "-o", "yaml"}
	for k, v := range data {
		args = append(args, "--from-literal="+k+"="+v)
	}
	args = append(args, "|", "kubectl", "apply", "-f", "-")
	cmd := k8s.Command(ctx, "sh", "-c", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SupprimerClientOIDC supprime un client OIDC du realm applicatif et son
// secret Kubernetes associé. Idempotent : un client ou un secret absent
// n'est pas une erreur.
//
// Utilisé par le retrait du SSO Jitsi : le client « jitsi » servait à
// l'adaptateur OIDC, supprimé avec lui.
func SupprimerClientOIDC(ctx context.Context, clientID string) error {
	uuid, err := clientUUID(ctx, clientID)
	if err != nil {
		// clientUUID échoue aussi quand le client n'existe pas : dans ce cas
		// il n'y a rien à supprimer.
		return nil
	}
	if uuid != "" {
		if out, err := runKcadm(ctx, "delete", "clients/"+uuid); err != nil {
			return fmt.Errorf("suppression client %s: %w: %s", clientID, err, out)
		}
	}
	// PLUS DE SECRET KUBERNETES À RETIRER : le client vit au coffre, à
	// kv/ceffio/<composant>/oidc. Rien à effacer ici — et surtout pas le coffre,
	// qui doit survivre à la suppression d'un client qu'on recréera peut-être.
	return nil
}
