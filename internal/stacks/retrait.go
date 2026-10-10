// Package stacks gère le retrait des piles applicatives remplacées.
//
// Décision du 2026-10-09 : Ceffio devient un produit Nextcloud. Talk (app
// Nextcloud) remplace le chat ET la visio — donc Matrix (Synapse + Element) et
// Jitsi sont retirés, ainsi que tout ce qui les accompagnait.
//
// POURQUOI CE PAQUET EXISTE : sur un cluster DÉJÀ installé, retirer du code
// ne suffit pas. Un `kubectl apply` ne supprime jamais un objet qu'il ne
// connaît plus, et les variables d'environnement posées par un patch
// survivent aux redéploiements. Sans nettoyage explicite, les anciens
// conteneurs continuent de tourner indéfiniment. C'est la leçon du retrait du
// SSO Jitsi (internal/media/sans_sso.go), généralisée ici.
//
// Tout est idempotent : chaque suppression tolère l'absence. Ce code peut donc
// tourner à chaque `install` / `redeploy` sans effet sur une installation neuve.
package stacks

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// nsChat et nsVideo sont les namespaces des piles retirées. Ils sont gardés le
// temps du nettoyage, puis supprimés s'ils sont vides.
const (
	nsChat  = "ceffio-chat"
	nsVideo = "ceffio-video"
)

// RetirerMatrixEtJitsi supprime du cluster tout ce qui appartenait à la pile
// Matrix (Synapse + Element) et à la pile visio Jitsi.
//
// Ordre volontaire : on coupe d'abord les charges de travail (elles
// consomment), puis les objets qui les alimentaient, puis les données. Les
// bases restent supprimées en dernier — c'est irréversible.
func RetirerMatrixEtJitsi(ctx context.Context, domain string) error {
	_ = domain

	restait := false

	// ------------------------------------------------------------------
	// 1. Jitsi — charges de travail
	// ------------------------------------------------------------------
	for _, d := range []string{"web", "prosody", "jicofo", "jvb"} {
		restait = supprimer(ctx, "deployment", d, nsVideo) || restait
		restait = supprimer(ctx, "service", d, nsVideo) || restait
	}

	// Le Service jvb portait le LoadBalancer : UDP 10000 + TCP 4443.
	// Le supprimer libère ces ports côté nœud (mais PAS la règle NAT OPNsense,
	// qui doit être retirée séparément — voir `ceffio expose`).

	restait = supprimer(ctx, "ingress", "meet", nsVideo) || restait

	// ------------------------------------------------------------------
	// 2. Matrix — charges de travail (Element puis Synapse)
	// ------------------------------------------------------------------
	restait = supprimer(ctx, "deployment", "element", nsChat) || restait
	restait = supprimer(ctx, "service", "element", nsChat) || restait
	restait = supprimer(ctx, "configmap", "element-config", nsChat) || restait

	restait = supprimer(ctx, "deployment", "synapse", nsChat) || restait
	restait = supprimer(ctx, "service", "synapse", nsChat) || restait
	restait = supprimer(ctx, "configmap", "synapse-config", nsChat) || restait

	restait = supprimer(ctx, "ingress", "chat", nsChat) || restait
	restait = supprimer(ctx, "ingress", "matrix", nsChat) || restait

	// ------------------------------------------------------------------
	// 3. Secrets et PVC
	// ------------------------------------------------------------------
	for _, s := range []string{"jitsi-secrets", "jitsi-jwt", "meet-tls"} {
		restait = supprimer(ctx, "secret", s, nsVideo) || restait
	}
	restait = supprimer(ctx, "pvc", "jitsi-config", nsVideo) || restait

	for _, s := range []string{"synapse-db", "synapse-secrets", "synapse-oidc", "chat-tls", "matrix-tls"} {
		restait = supprimer(ctx, "secret", s, nsChat) || restait
	}
	restait = supprimer(ctx, "pvc", "synapse-media", nsChat) || restait

	// ------------------------------------------------------------------
	// 4. Données : base PostgreSQL `synapse` + rôle
	//    IRRÉVERSIBLE — d'où l'ordre (après tout le reste).
	// ------------------------------------------------------------------
	if err := supprimerBaseSynapse(ctx); err != nil {
		fmt.Printf("  ! suppression de la base « synapse » : %v\n", err)
	}

	// ------------------------------------------------------------------
	// 5. Client OIDC « synapse » dans Keycloak
	//    « jitsi » a déjà été retiré avec le SSO Jitsi.
	// ------------------------------------------------------------------
	if err := supprimerClientKeycloak(ctx, "synapse"); err != nil {
		fmt.Printf("  ! client OIDC « synapse » non supprimé : %v\n", err)
	}

	if restait {
		fmt.Println("∙ ancienne pile Matrix/Jitsi retirée du cluster")
	}
	return nil
}

// supprimer supprime une ressource en tolérant l'absence. Renvoie true si
// quelque chose a effectivement été supprimé (pour ne pas afficher de message
// sur une installation neuve).
func supprimer(ctx context.Context, ressource, nom, namespace string) bool {
	cmd := k8s.Command(ctx, "kubectl", "delete", ressource, nom, "-n", namespace, "--ignore-not-found")
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  ! %s/%s (%s) : %s\n", ressource, nom, namespace, premiereLigne(string(out)))
		return false
	}
	s := strings.TrimSpace(string(out))
	if s == "" || strings.Contains(s, "No resources found") {
		return false
	}
	// Une suppression réussie affiche « <ressource> "<nom>" deleted from … ».
	return strings.Contains(s, " deleted ")
}

// supprimerBaseSynapse supprime la base et le rôle PostgreSQL de Synapse.
//
// Idempotent : IF EXISTS. Utilise WITH (FORCE) pour couper les connexions
// résiduelles (sans quoi un pod Synapse en cours de terminaison bloquerait la
// suppression).
func supprimerBaseSynapse(ctx context.Context) error {
	// La base existe-t-elle ? On évite d'agir sur une installation neuve.
	existe, err := execPsql(ctx, "SELECT 1 FROM pg_database WHERE datname='synapse'")
	if err != nil {
		return nil // base injoignable : rien à faire ici, signalé ailleurs
	}
	if strings.TrimSpace(existe) == "" {
		return nil // déjà absente
	}
	if _, err := execPsql(ctx, "DROP DATABASE IF EXISTS synapse WITH (FORCE)"); err != nil {
		return err
	}
	if _, err := execPsql(ctx, "DROP ROLE IF EXISTS synapse"); err != nil {
		// Le rôle peut être retenu par des droits résiduels : non bloquant.
		fmt.Printf("  ! rôle PostgreSQL « synapse » non supprimé : %v\n", err)
	}
	fmt.Println("∙ base PostgreSQL « synapse » supprimée")
	return nil
}

// execPsql exécute un SQL sur la base postgres (administration cluster).
func execPsql(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", "ceffio-data", "ceffio-pg-1", "--",
		"psql", "-U", "postgres", "-tAc", sql)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	return string(out), nil
}

// supprimerClientKeycloak retire un client OIDC du realm applicatif, avec son
// secret Kubernetes associé. Idempotent.
func supprimerClientKeycloak(ctx context.Context, clientID string) error {
	pod, err := podKeycloak(ctx)
	if err != nil || pod == "" {
		return nil // Keycloak absent : rien à faire
	}
	script := fmt.Sprintf(`
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 || exit 0
UUID=$(/opt/keycloak/bin/kcadm.sh get clients -r ceffio -q clientId=%s --fields id 2>/dev/null \
  | grep -o '"id" : "[^"]*"' | head -1 | sed 's/.*: "//;s/"//')
if [ -n "$UUID" ]; then
  /opt/keycloak/bin/kcadm.sh delete clients/"$UUID" -r ceffio >/dev/null 2>&1 && echo "supprime" || echo "echec"
fi`, clientID)

	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", "ceffio-identity", pod, "--", "sh", "-c", script)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	if strings.Contains(string(out), "supprime") {
		fmt.Printf("∙ client OIDC « %s » supprimé de Keycloak\n", clientID)
	}
	// Secret Kubernetes éventuel.
	supprimer(ctx, "secret", clientID+"-oidc", nsChat)
	return nil
}

// podKeycloak renvoie le nom du pod Keycloak en cours d'exécution.
func podKeycloak(ctx context.Context) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "get", "pods", "-n", "ceffio-identity",
		"-l", "app=keycloak", "--field-selector=status.phase=Running",
		"-o", `jsonpath={.items[0].metadata.name}`)
	cmd.Env = k8s.Env()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func premiereLigne(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 180 {
		return s[:180] + "…"
	}
	return s
}
