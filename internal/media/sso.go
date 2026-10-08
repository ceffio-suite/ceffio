package media

// SSO Jitsi via Keycloak — adaptateur nordeck/jitsi-keycloak-adapter (v1).
//
// Jitsi ne sait pas parler OIDC. Il sait vérifier des JETONS signés (AUTH_TYPE=jwt).
// L'adaptateur fait le pont : le navigateur arrive sans jeton, est renvoyé vers
// Keycloak, et revient avec un jeton Jitsi signé du secret partagé.
//
// INTÉGRATION RÉELLE (doc setup-docker.md de l'adaptateur, vérifiée contre
// l'image ghcr.io/jitsi/web:stable-11146-2) :
//
//  1. Trois fichiers statiques doivent être présents dans le conteneur web :
//     /usr/share/jitsi-meet/body.html              (intercepte le bouton login)
//     /usr/share/jitsi-meet/static/oidc-redirect.html
//     /usr/share/jitsi-meet/static/oidc-adapter.html
//     L'image livre body.html VIDE (0 octet) et index.html fait un
//     `include virtual="body.html"` en SSI — il suffit de remplacer ce fichier.
//
//  2. Les routes /oidc/auth, /oidc/redirect, /oidc/tokenize doivent être
//     PROXYFIÉES vers l'adaptateur par le nginx du conteneur web. Le meet.conf
//     de l'image contient `include /run/web/config/nginx-custom/*.conf;` DANS
//     le bloc server : on monte un ConfigMap avec notre oidc.conf.
//     (TOKEN_AUTH_URL ne sert à RIEN avec cet adaptateur — son README le dit
//     explicitement : « Not based on tokenAuthUrl ».)
//
//  3. Côté Keycloak : client confidentiel « jitsi », redirectUris
//     https://meet.<domaine>/* (créé par la phase SSO).
//
// Le secret JWT partagé est créé une seule fois (ensureSecretSiAbsent) : le
// régénérer invaliderait les jetons des participants connectés.

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

const (
	adaptateurImage = "ghcr.io/nordeck/jitsi-keycloak-adapter:v20240109"
	// NE PAS monter sur /run/web/config/nginx-custom : kubelet pré-crée
	// /run/web/config en root:755 et le script s6 de l'image (utilisateur
	// non-root) échoue alors en Permission denied sur TOUTE la génération de
	// config (nginx.conf jamais écrit → nginx en boucle [emerg] → 502).
	// On monte dans le PVC /config : le script d'amorçage fait
	// « cp -r /config/. /run/web/config », donc oidc.conf se retrouve copié
	// dans /run/web/config/nginx-custom, que meet.conf inclut dans son bloc
	// server. Les fichiers .html en trop sont inoffensifs (seuls *.conf sont
	// inclus).
	nginxCustomMount = "/config/nginx-custom"
)

//go:embed static/body.html static/oidc-adapter.html static/oidc-redirect.html
var fichiersOIDC embed.FS

// oidcConf proxifie /oidc/* vers l'adaptateur. Elle est incluse dans le bloc
// server du meet.conf généré par l'image Jitsi.
//
// ^~ est OBLIGATOIRE : meet.conf contient des locations regex (le bloc
// ENABLE_SUBDOMAINS, `location ~ ^/([^/?&:'"]+)/(.*)$`) qui capturent
// /oidc/auth et le réécrivent en /auth — la SPA répondait 200 au lieu du 302
// de l'adaptateur. En nginx, une regex gagne sur un préfixe simple ; ^~
// bloque la recherche de regex pour ce préfixe.
const oidcConf = `location ^~ /oidc/ {
    proxy_pass http://jitsi-keycloak-adapter:80;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $http_host;
}
`

// ConfigureSSO branche Jitsi sur Keycloak. Idempotent.
func ConfigureSSO(ctx context.Context, domain string) error {
	fmt.Println("SSO Jitsi ← Keycloak (adaptateur OIDC → jeton Jitsi)...")

	// 1. Secret partagé Jitsi ↔ adaptateur (jamais régénéré s'il existe).
	if err := ensureSecretSiAbsent(ctx, "jitsi-jwt", "app-secret", 32); err != nil {
		return err
	}
	// Échouer TÔT si la phase SSO n'a pas réconcilié le client « jitsi » :
	// le manifeste le référence par secretKeyRef, un secret manquant laisserait
	// un pod en CreateContainerConfigError difficile à diagnostiquer.
	if _, err := lireSecretValue(ctx, "ceffio-identity", "jitsi-oidc", "client-secret"); err != nil {
		return fmt.Errorf("secret jitsi-oidc: %w (la phase SSO doit réconcilier le client « jitsi »)", err)
	}
	// 2. Le client OIDC vit dans ceffio-identity ; un secretKeyRef ne traverse
	//    PAS les namespaces → copie locale.
	if err := copierSecretVers(ctx, "ceffio-identity", "jitsi-oidc", ns); err != nil {
		return err
	}
	// 3. Fichiers statiques + conf nginx /oidc/ dans un ConfigMap dédié.
	if err := creerConfigMapOIDC(ctx); err != nil {
		return err
	}

	// 4. Déploiement de l'adaptateur.
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: jitsi-keycloak-adapter
  namespace: %[1]s
  labels: {app: jitsi-keycloak-adapter}
spec:
  replicas: 1
  selector: {matchLabels: {app: jitsi-keycloak-adapter}}
  template:
    metadata: {labels: {app: jitsi-keycloak-adapter}}
    spec:
      containers:
      - name: adaptateur
        image: %[2]s
        env:
        - {name: KEYCLOAK_ORIGIN, value: "https://keycloak.%[3]s"}
        - {name: KEYCLOAK_REALM, value: ceffio}
        - {name: KEYCLOAK_CLIENT_ID, value: jitsi}
        - {name: KEYCLOAK_ORIGIN_INTERNAL, value: "http://keycloak.ceffio-identity.svc:8080"}
        - {name: KEYCLOAK_CLIENT_SECRET, valueFrom: {secretKeyRef: {name: jitsi-oidc, key: client-secret}}}
        - {name: JWT_APP_ID, value: jitsi}
        - {name: JWT_APP_SECRET, valueFrom: {secretKeyRef: {name: jitsi-jwt, key: app-secret}}}
        - {name: ALLOW_UNSECURE_CERT, value: "false"}
        ports:
        - {name: http, containerPort: 9000}
        resources: {limits: {memory: 256Mi}}
---
apiVersion: v1
kind: Service
metadata:
  name: jitsi-keycloak-adapter
  namespace: %[1]s
spec:
  selector: {app: jitsi-keycloak-adapter}
  ports:
  - {name: http, port: 80, targetPort: 9000}
`, ns, adaptateurImage, domain)
	if err := apply(ctx, manifeste); err != nil {
		return fmt.Errorf("manifeste adaptateur SSO: %w", err)
	}

	// 5. Frontend web : mode jeton + montage des fichiers OIDC.
	//    TOKEN_AUTH_URL est volontairement ABSENT (et retiré s'il existe) :
	//    l'adaptateur v1 ne l'utilise pas, c'est body.html qui déclenche
	//    /oidc/auth quand l'utilisateur clique « login ».
	envWeb := []map[string]any{
		{"name": "ENABLE_AUTH", "value": "1"},
		{"name": "AUTH_TYPE", "value": "jwt"},
		{"name": "JWT_APP_ID", "value": "jitsi"},
		{"name": "JWT_APP_SECRET", "valueFrom": map[string]any{
			"secretKeyRef": map[string]string{"name": "jitsi-jwt", "key": "app-secret"}}},
		{"name": "JWT_ACCEPTED_ISSUERS", "value": "jitsi"},
		{"name": "JWT_ACCEPTED_AUDIENCES", "value": "jitsi"},
		{"name": "ENABLE_GUESTS", "value": "1"},
		{"name": "ENABLE_AUTO_LOGIN", "value": "0"},
	}
	if err := patcherWebOIDC(ctx, envWeb); err != nil {
		return fmt.Errorf("patch frontend Jitsi: %w", err)
	}

	// 6. Prosody vérifie les jetons ; jicofo reste en interne (doc 2.3).
	envProsody := []map[string]any{
		{"name": "ENABLE_AUTH", "value": "1"},
		{"name": "AUTH_TYPE", "value": "jwt"},
		{"name": "JWT_APP_ID", "value": "jitsi"},
		{"name": "JWT_APP_SECRET", "valueFrom": map[string]any{
			"secretKeyRef": map[string]string{"name": "jitsi-jwt", "key": "app-secret"}}},
		{"name": "JWT_ACCEPTED_ISSUERS", "value": "jitsi"},
		{"name": "JWT_ACCEPTED_AUDIENCES", "value": "jitsi"},
		{"name": "PROSODY_AUTH_TYPE", "value": "jwt"},
	}
	if err := patcherEnvConteneur(ctx, "prosody", "prosody", envProsody); err != nil {
		return fmt.Errorf("patch prosody: %w", err)
	}
	envJicofo := []map[string]any{
		{"name": "JICOFO_AUTH_TYPE", "value": "internal"},
	}
	if err := patcherEnvConteneur(ctx, "jicofo", "jicofo", envJicofo); err != nil {
		return fmt.Errorf("patch jicofo: %w", err)
	}

	for _, cible := range []string{"web", "prosody", "jicofo"} {
		if err := relancerDeploiement(ctx, cible); err != nil {
			return err
		}
	}

	fmt.Println("✓ SSO Jitsi configuré (login Keycloak sur https://meet." + domain + ")")
	return nil
}

// creerConfigMapOIDC crée le ConfigMap portant les fichiers statiques de
// l'adaptateur et la conf nginx /oidc/. Contenu EMBARQUÉ dans le binaire
// (go:embed) : la source de vérité est le dépôt, aucun téléchargement runtime.
func creerConfigMapOIDC(ctx context.Context) error {
	donnees := map[string]string{"oidc.conf": oidcConf}
	for _, nom := range []string{"body.html", "oidc-adapter.html", "oidc-redirect.html"} {
		b, err := fichiersOIDC.ReadFile("static/" + nom)
		if err != nil {
			return err
		}
		donnees[nom] = string(b)
	}
	return creerConfigMapDepuisDonnees(ctx, "jitsi-oidc-static", donnees)
}

// creerConfigMapDepuisDonnees crée/remplace un ConfigMap de texte.
// apply direct (pas create|apply) : idempotent, sans dépendre de l'annotation
// last-applied.
func creerConfigMapDepuisDonnees(ctx context.Context, nom string, donnees map[string]string) error {
	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": nom, "namespace": ns},
		"data":       donnees,
	}
	b, err := json.Marshal(cm)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configmap %s: %w: %s", nom, err, oneLine(string(out)))
	}
	return nil
}

// patcherWebOIDC pose les variables ET les montages des fichiers OIDC sur le
// conteneur web. Contrairement à patcherEnvConteneur, il préserve mounts et
// volumes existants et ajoute ceux de l'adaptateur :
//   - body.html / oidc-adapter.html / oidc-redirect.html en subPath (fichier par
//     fichier : le reste de /usr/share/jitsi-meet vient toujours de l'image) ;
//   - nginx-custom monté dans le PVC (/config/nginx-custom) : le script s6 le
//     copie vers /run/web/config/nginx-custom, que meet.conf inclut. Monter
//     directement sous /run casserait le script (répertoires pré-créés par
//     kubelet en root, script non-root → Permission denied → nginx sans conf).
func patcherWebOIDC(ctx context.Context, env []map[string]any) error {
	out, err := k8s.Command(ctx, "kubectl", "get", "deploy", "web", "-n", ns, "-o", "json").Output()
	if err != nil {
		return err
	}
	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		return err
	}
	spec := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)

	var web map[string]any
	for _, c := range spec["containers"].([]any) {
		if cm, ok := c.(map[string]any); ok && cm["name"] == "web" {
			web = cm
		}
	}
	if web == nil {
		return fmt.Errorf("conteneur « web » introuvable dans deploy/web")
	}

	// Volume du ConfigMap OIDC (ajouté s'il manque).
	volumes, _ := spec["volumes"].([]any)
	aDeja := false
	for _, v := range volumes {
		if vm, ok := v.(map[string]any); ok && vm["name"] == "jitsi-oidc-static" {
			aDeja = true
		}
	}
	if !aDeja {
		volumes = append(volumes, map[string]any{
			"name":      "jitsi-oidc-static",
			"configMap": map[string]any{"name": "jitsi-oidc-static"},
		})
		spec["volumes"] = volumes
	}

	// Mounts : mêmes règles (idempotent par mountPath). On PURGE aussi
	// l'ancien montage fautif sous /run (voir la note sur nginxCustomMount).
	mountsBruts, _ := web["volumeMounts"].([]any)
	var mounts []any
	for _, m := range mountsBruts {
		if mm, ok := m.(map[string]any); ok && mm["mountPath"] == "/run/web/config/nginx-custom" {
			continue
		}
		mounts = append(mounts, m)
	}
	mountsVoulus := []map[string]any{
		{"name": "jitsi-oidc-static", "mountPath": "/usr/share/jitsi-meet/body.html", "subPath": "body.html"},
		{"name": "jitsi-oidc-static", "mountPath": "/usr/share/jitsi-meet/static/oidc-adapter.html", "subPath": "oidc-adapter.html"},
		{"name": "jitsi-oidc-static", "mountPath": "/usr/share/jitsi-meet/static/oidc-redirect.html", "subPath": "oidc-redirect.html"},
		{"name": "jitsi-oidc-static", "mountPath": nginxCustomMount},
	}
	for _, voulu := range mountsVoulus {
		present := false
		for _, m := range mounts {
			if mm, ok := m.(map[string]any); ok && mm["mountPath"] == voulu["mountPath"] {
				present = true
			}
		}
		if !present {
			mounts = append(mounts, voulu)
		}
	}
	web["volumeMounts"] = mounts

	// Env : remplacer les variables d'auth, conserver les autres, et PURGER
	// TOKEN_AUTH_URL (posé par une première version erronée de ce code).
	envExistantes, _ := web["env"].([]any)
	remplaces := map[string]bool{}
	for _, e := range env {
		remplaces[e["name"].(string)] = true
	}
	var gardees []map[string]any
	for _, e := range envExistantes {
		em, _ := e.(map[string]any)
		if nom, _ := em["name"].(string); !remplaces[nom] && nom != "TOKEN_AUTH_URL" {
			gardees = append(gardees, em)
		}
	}
	web["env"] = append(gardees, env...)

	patch := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": spec}}}
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "patch", "deploy", "web", "-n", ns, "--type=strategic", "-p", string(b))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// patcherEnvConteneur remplace les variables d'un conteneur en préservant les
// autres. Patch ASSEMBLÉ par json.Marshal : un littéral JSON écrit à la main se
// déséquilibre facilement (« unexpected end of JSON input ») sans dire où.
func patcherEnvConteneur(ctx context.Context, deploiement, conteneur string, env []map[string]any) error {
	existantes := []map[string]any{}
	out, err := k8s.Command(ctx, "kubectl", "get", "deploy", deploiement, "-n", ns, "-o", "json").Output()
	if err == nil {
		var d map[string]any
		if json.Unmarshal(out, &d) == nil {
			spec, _ := d["spec"].(map[string]any)
			tpl, _ := spec["template"].(map[string]any)
			pspec, _ := tpl["spec"].(map[string]any)
			conteneurs, _ := pspec["containers"].([]any)
			for _, c := range conteneurs {
				cm, _ := c.(map[string]any)
				if cm["name"] == conteneur {
					if e, ok := cm["env"].([]any); ok {
						remplaces := map[string]bool{}
						for _, nv := range env {
							remplaces[nv["name"].(string)] = true
						}
						for _, item := range e {
							im, _ := item.(map[string]any)
							if nom, _ := im["name"].(string); !remplaces[nom] && nom != "TOKEN_AUTH_URL" {
								existantes = append(existantes, im)
							}
						}
					}
				}
			}
		}
	}
	env = append(existantes, env...)

	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": conteneur, "env": env},
					},
				},
			},
		},
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "patch", "deploy", deploiement, "-n", ns,
		"--type=strategic", "-p", string(b))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// relancerDeploiement redémarre un Deployment et attend qu'il soit prêt.
func relancerDeploiement(ctx context.Context, nom string) error {
	if err := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/"+nom, "-n", ns).Run(); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nom, "-n", ns, "--timeout=240s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// copierSecretVers recopie un secret d'un namespace à un autre : un secretKeyRef
// ne traverse PAS les namespaces (piège rencontré deux fois : console d'admin,
// adaptateur SSO).
func copierSecretVers(ctx context.Context, nsSource, nom, nsCible string) error {
	if nsSource == nsCible {
		return nil
	}
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", nsSource, "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("lecture du secret %s/%s : %w", nsSource, nom, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		return err
	}
	data, _ := doc["data"].(map[string]any)
	nouveau := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": nom, "namespace": nsCible},
		"type":       doc["type"],
		"data":       data,
	}
	b, err := json.Marshal(nouveau)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copie du secret vers %s : %w : %s", nsCible, err, oneLine(string(out)))
	}
	fmt.Printf("✓ Secret %s copié dans %s (les références ne traversent pas les namespaces)\n", nom, nsCible)
	return nil
}

// ensureSecretSiAbsent crée un secret aléatoire SEULEMENT s'il manque.
// Pour un secret de signature, régénérer = invalider les jetons des participants
// connectés : un déploiement deviendrait une coupure.
func ensureSecretSiAbsent(ctx context.Context, nom, cle string, taille int) error {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns,
		"-o", "jsonpath={.data."+cle+"}").Output()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return nil
	}
	valeur, err := genSecret(taille)
	if err != nil {
		return err
	}
	return createSecret(ctx, nom, map[string]string{cle: valeur})
}

// lireSecretValue lit une clé d'un Secret (base64 décodé) dans un namespace.
func lireSecretValue(ctx context.Context, namespace, nom, cle string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", namespace,
		"-o", "jsonpath={.data."+cle+"}").Output()
	if err != nil {
		return "", fmt.Errorf("secret %s/%s: %w", namespace, nom, err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// oneLine compacte une sortie pour un message d'erreur lisible.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.TrimSpace(s)
}
