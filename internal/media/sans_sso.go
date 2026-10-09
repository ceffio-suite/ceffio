package media

// Retrait complet du SSO de Jitsi (décision du 2026-10-09).
//
// HISTORIQUE : deux mécanismes d'authentification avaient été ajoutés —
// un SSO Keycloak via l'adaptateur OIDC pour l'accès direct, et un jeton
// Matrix (UVS) pour le widget d'Element. Le widget relançait malgré tout le
// SSO dans l'iframe (cookies tiers bloqués), et la chaîne de découverte
// d'Element s'est révélée fragile en pratique. Plutôt qu'un troisième
// correctif, décision de retirer TOUTE authentification : Jitsi repasse en
// accès libre (`ENABLE_AUTH=0`), le comportement standard d'un Jitsi
// auto-hébergé.
//
// CONSÉQUENCE ACCEPTÉE : toute personne connaissant le nom d'un salon peut y
// entrer. La confidentialité repose sur l'imprévisibilité du nom (les widgets
// d'Element utilisent base32(room_id)) et sur le lobby Jitsi.
//
// Ce fichier ne configure rien : il NETTOIE. Il est appelé par `install` et
// `redeploy` pour que le cluster converge vers l'état voulu même s'il porte
// encore les objets des versions précédentes (un `kubectl apply` ne supprime
// jamais ce qu'il ne connaît pas, et les variables d'environnement ajoutées
// par un patch survivent aux déploiements suivants).
//
// Tout est idempotent : chaque suppression tolère l'absence.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// varsAPurger liste les variables d'environnement posées par les SSO supprimés.
// Les retirer une par une ne suffit pas : un patch stratégique fusionne les
// listes par `name` et ne supprime jamais une entrée absente du patch. On
// remplace donc la liste entière (JSON Patch RFC 6902).
var varsAPurger = map[string]bool{
	"AUTH_TYPE":                      true,
	"ENABLE_AUTH":                    true, // reposé explicitement à "0"
	"ENABLE_GUESTS":                  true,
	"JWT_APP_ID":                     true,
	"JWT_APP_SECRET":                 true,
	"JWT_ACCEPTED_ISSUERS":           true,
	"JWT_ACCEPTED_AUDIENCES":         true,
	"JWT_ACCEPTED_ALLOWNER_ISSUERS":  true,
	"JWT_ALLOW_EMPTY":                true,
	"JWT_ENABLE_DOMAIN_VERIFICATION": true,
	"JWT_SIGN_TYPE":                  true,
	"JWT_TOKEN_AUTH_MODULE":          true,
	"JWT_ASAP_KEYSERVER":             true,
	"PROSODY_AUTH_TYPE":              true,
	"MATRIX_UVS_URL":                 true,
	"MATRIX_UVS_ISSUER":              true,
	"MATRIX_UVS_AUTH_TOKEN":          true,
	"MATRIX_UVS_SYNC_POWER_LEVELS":   true,
	"MATRIX_LOBBY_BYPASS":            true,
	"TOKEN_AUTH_URL":                 true,
	"TOKEN_AUTH_URL_BASE":            true,
	"TOKEN_LOGOUT_URL":               true,
}

// volumesAPurger liste les volumes/montages posés par les SSO supprimés.
var volumesAPurger = map[string]bool{
	"jitsi-oidc-static":     true,
	"prosody-plugins":       true,
	"jitsi-prosody-plugins": true,
}

// RetirerSSO supprime tout ce que les SSO Jitsi ont laissé dans le cluster :
// déploiements (adaptateur OIDC, UVS), ConfigMaps, secrets, variables
// d'environnement, montages de volumes et fichiers dans le PVC partagé du
// namespace ceffio-video. Le client OIDC Keycloak (« jitsi ») et le compte
// Synapse (« uvs ») sont nettoyés par leurs paquets respectifs (internal/sso,
// internal/chat) : chacun retire ce qui lui appartient.
//
// `domain` est conservé dans la signature pour l'appelant (install/redeploy)
// même si ce nettoyage-ci n'en a pas besoin.
func RetirerSSO(ctx context.Context, domain string) error {
	_ = domain
	fmt.Println("∙ Jitsi en accès libre (suppression des vestiges du SSO)...")

	// 1. Charges de travail : adaptateur OIDC et UVS.
	supprimer(ctx, "deployment", "jitsi-keycloak-adapter")
	supprimer(ctx, "service", "jitsi-keycloak-adapter")
	supprimer(ctx, "deployment", "uvs")
	supprimer(ctx, "service", "uvs")

	// 2. ConfigMaps et secrets propres au SSO.
	supprimer(ctx, "configmap", "jitsi-oidc-static")
	supprimer(ctx, "configmap", "jitsi-prosody-plugins")
	for _, s := range []string{"jitsi-oidc", "uvs-auth", "uvs-synapse-token"} {
		supprimer(ctx, "secret", s)
	}

	// 3. Variables d'environnement + montages sur web et prosody. Les fichiers
	//    du SSO (body.html, oidc.conf, plugins Prosody) étaient montés depuis
	//    des ConfigMaps : retirer les montages suffit, rien n'a été écrit dans
	//    le PVC partagé.
	for _, d := range []string{"web", "prosody"} {
		if err := purgerEnvironnement(ctx, d); err != nil {
			return fmt.Errorf("purge env %s: %w", d, err)
		}
	}

	// 4. Redémarrer pour que Prosody régénère sa config sans authentification.
	for _, d := range []string{"prosody", "web", "jicofo"} {
		if err := relancer(ctx, d); err != nil {
			return fmt.Errorf("redémarrage %s: %w", d, err)
		}
	}

	fmt.Println("✓ Jitsi en accès libre (aucune authentification, SSO retiré)")
	return nil
}

// supprimer supprime une ressource en tolérant son absence.
func supprimer(ctx context.Context, ressource, nom string) {
	cmd := k8s.Command(ctx, "kubectl", "delete", ressource, nom, "-n", ns, "--ignore-not-found")
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("  ! %s/%s : %s\n", ressource, nom, premiereLigne(string(out)))
	} else if s := strings.TrimSpace(string(out)); s != "" && !strings.Contains(s, "No resources found") {
		fmt.Println("  " + premiereLigne(s))
	}
}

// purgerEnvironnement retire les variables et montages du SSO d'un Deployment,
// et garantit ENABLE_AUTH=0 (accès libre).
//
// Méthode : JSON Patch RFC 6902 qui REMPLACE les listes env/volumeMounts/
// volumes entières. Un patch stratégique fusionnerait par `name` et ne
// supprimerait jamais une variable absente du patch — c'est exactement comme
// ça que TOKEN_AUTH_URL avait survécu à un premier correctif.
func purgerEnvironnement(ctx context.Context, deploiement string) error {
	out, err := k8s.Command(ctx, "kubectl", "get", "deploy", deploiement, "-n", ns, "-o", "json").Output()
	if err != nil {
		return err
	}
	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		return err
	}
	spec, ok := d["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("spec absent")
	}
	tpl, _ := spec["template"].(map[string]any)
	podSpec, _ := tpl["spec"].(map[string]any)
	if podSpec == nil {
		return fmt.Errorf("pod spec absent")
	}

	ops := []map[string]any{}

	// --- env du premier conteneur (web/prosody n'en ont qu'un d'applicatif) ---
	conteneurs, _ := podSpec["containers"].([]any)
	if len(conteneurs) == 0 {
		return fmt.Errorf("aucun conteneur")
	}
	var indice int
	for i, c := range conteneurs {
		cm, _ := c.(map[string]any)
		if cm != nil && cm["name"] == deploiement {
			indice = i
		}
	}
	cible, _ := conteneurs[indice].(map[string]any)

	var nouvelles []map[string]any
	if envs, ok := cible["env"].([]any); ok {
		for _, e := range envs {
			em, _ := e.(map[string]any)
			if em == nil {
				continue
			}
			nom, _ := em["name"].(string)
			if varsAPurger[nom] {
				continue
			}
			nouvelles = append(nouvelles, em)
		}
	}
	// Accès libre : ENABLE_AUTH=0 explicite (le template Prosody traite
	// l'absence comme « 0 », mais une valeur explicite évite toute ambiguïté
	// et rend l'intention lisible dans `kubectl get -o yaml`).
	nouvelles = append(nouvelles, map[string]any{"name": "ENABLE_AUTH", "value": "0"})

	ops = append(ops, map[string]any{
		"op":    "replace",
		"path":  fmt.Sprintf("/spec/template/spec/containers/%d/env", indice),
		"value": nouvelles,
	})

	// --- volumeMounts : retirer ceux du SSO ---
	if mounts, ok := cible["volumeMounts"].([]any); ok {
		var gardes []map[string]any
		change := false
		for _, m := range mounts {
			mm, _ := m.(map[string]any)
			if mm == nil {
				continue
			}
			if nom, _ := mm["name"].(string); volumesAPurger[nom] {
				change = true
				continue
			}
			gardes = append(gardes, mm)
		}
		if change {
			ops = append(ops, map[string]any{
				"op":    "replace",
				"path":  fmt.Sprintf("/spec/template/spec/containers/%d/volumeMounts", indice),
				"value": gardes,
			})
		}
	}

	// --- volumes : retirer ceux du SSO ---
	if vols, ok := podSpec["volumes"].([]any); ok {
		var gardes []map[string]any
		change := false
		for _, v := range vols {
			vm, _ := v.(map[string]any)
			if vm == nil {
				continue
			}
			if nom, _ := vm["name"].(string); volumesAPurger[nom] {
				change = true
				continue
			}
			gardes = append(gardes, vm)
		}
		if change {
			ops = append(ops, map[string]any{
				"op": "replace", "path": "/spec/template/spec/volumes", "value": gardes,
			})
		}
	}

	b, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "patch", "deploy", deploiement, "-n", ns,
		"--type=json", "-p", string(b))
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	return nil
}

// relancer redémarre un Deployment et attend qu'il soit prêt.
func relancer(ctx context.Context, nom string) error {
	cmd := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/"+nom, "-n", ns)
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		// Absent (jamais déployé) : rien à redémarrer.
		if strings.Contains(string(out), "not found") {
			return nil
		}
		return fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	status := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nom, "-n", ns, "--timeout=240s")
	status.Env = k8s.Env()
	if out, err := status.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, premiereLigne(string(out)))
	}
	return nil
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
