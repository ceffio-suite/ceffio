package media

// SSO Matrix pour le widget Jitsi d'Element (« openidtoken-jwt »).
//
// POURQUOI : dans l'iframe d'Element, rejouer un SSO OIDC interactif boucle —
// Keycloak est appelé avec prompt=login et les cookies tiers sont bloqués dans
// les iframes : l'utilisateur s'authentifie, revient, et le SSO se relance.
// Le mécanisme standard prévu par Element pour ce cas est un JETON :
//
//   1. Element demande à Synapse un token OpenID Matrix pour l'utilisateur
//      (déjà connecté à Element — aucun login supplémentaire).
//   2. Element fabrique un JWT dont le payload porte ce token Matrix et
//      l'ID de salle, et le passe à Jitsi (auth=openidtoken-jwt, annoncé par
//      /.well-known/element/jitsi).
//   3. Prosody (module hybrid_matrix_token) fait vérifier le token par UVS
//      (Matrix User Verification Service) auprès de Synapse : utilisateur
//      existant + membre de la salle.
//
// Le mode « hybride » accepte les DEUX types de jeton simultanément :
//   - widget Element  → jeton Matrix (vérifié via UVS)     → pas de SSO iframe
//   - accès direct    → jeton JWT signé par l'adaptateur OIDC (SSO Keycloak)
//
// Pièces ajoutées :
//   - UVS (matrixdotorg/matrix-user-verification-service) dans ceffio-video ;
//   - plugins Prosody (jitsi-contrib/prosody-plugins, Apache-2.0) embarqués
//     dans le binaire et montés dans /config/prosody-plugins-custom ;
//   - PROSODY_AUTH_TYPE=hybrid_matrix_token + variables MATRIX_UVS_* ;
//   - /.well-known/element/jitsi servi par le nginx du frontend ;
//   - utilisateur Synapse « uvs » (admin) dont le token permet à UVS de
//     vérifier l'appartenance aux salles ;
//   - serve_server_wellknown côté Synapse (résolution du nom par UVS).

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

const (
	uvsImage   = "matrixdotorg/matrix-user-verification-service:v3.0.0"
	uvsUser    = "uvs"
	chatNS     = "ceffio-chat"
	synapseSvc = "http://synapse.ceffio-chat.svc:8008"
	pluginsDir = "/config/prosody-plugins-custom"
	// CORS OBLIGATOIRE : c'est le navigateur d'Element (origine chat.<dom>) qui
	// fetch() ce fichier cross-origin. Sans Access-Control-Allow-Origin, le
	// fetch est bloqué, getJitsiAuth() retourne null en silence, le widget est
	// créé SANS jeton Matrix et l'auth retombe sur tokenAuthUrl → boucle SSO.
	// Vérifié en vrai navigateur : sans ces en-têtes, « TypeError: Failed to
	// fetch » ; avec, Element lit {"auth":"openidtoken-jwt"}.
	wellKnownJS = `location = /.well-known/element/jitsi {
    default_type application/json;
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type" always;
    add_header Cache-Control "no-store" always;
    if ($request_method = OPTIONS) { return 204; }
    return 200 '{"auth": "openidtoken-jwt"}';
}
`
)

//go:embed static/mod_auth_hybrid_matrix_token.lua static/mod_matrix_affiliation.lua static/mod_matrix_lobby_bypass.lua
var pluginsProsody embed.FS

// ConfigurerMatrixSSO déploie UVS et bascule Prosody en mode hybride.
// Idempotent : secrets réutilisés s'ils existent, manifests appliqués.
func ConfigurerMatrixSSO(ctx context.Context, domain string) error {
	fmt.Println("SSO Matrix (widget Element) : UVS + Prosody hybride...")

	meet := "meet." + domain
	matrixServer := "matrix." + domain

	// 1. Secrets : token d'API UVS (protège /verify) + token Synapse d'admin.
	if err := ensureSecretSiAbsent(ctx, "uvs-auth", "token", 24); err != nil {
		return err
	}
	if err := ensureUVSSynapseToken(ctx); err != nil {
		return err
	}

	// 2. Autorité interne dans ceffio-video (UVS parle HTTPS à matrix.<domaine>
	//    via Traefik : Node.js doit faire confiance à notre CA).
	if err := creerConfigMapCA(ctx); err != nil {
		return err
	}

	// 3. UVS : Deployment + Service. hostAliases vers Traefik pour résoudre
	//    matrix.<domaine> dans le cluster (sinon la requête sortirait vers
	//    l'IP WAN et dépendrait du NAT hairpin).
	traefikIP, err := clusterIPService(ctx, "traefik", "kube-system")
	if err != nil {
		return fmt.Errorf("IP Traefik: %w", err)
	}
	manifeste := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: uvs
  namespace: %[1]s
  labels: {app: uvs}
spec:
  replicas: 1
  selector: {matchLabels: {app: uvs}}
  template:
    metadata: {labels: {app: uvs}}
    spec:
      hostAliases:
      - ip: %[2]s
        hostnames: ["%[3]s"]
      containers:
      - name: uvs
        image: %[4]s
        env:
        - {name: UVS_ACCESS_TOKEN, valueFrom: {secretKeyRef: {name: uvs-synapse-token, key: access-token}}}
        - {name: UVS_HOMESERVER_URL, value: "%[5]s"}
        - {name: UVS_DISABLE_IP_BLACKLIST, value: "true"}
        - {name: UVS_AUTH_TOKEN, valueFrom: {secretKeyRef: {name: uvs-auth, key: token}}}
        - {name: UVS_OPENID_VERIFY_SERVER_NAME, value: "%[3]s"}
        - {name: UVS_LISTEN_ADDRESS, value: "0.0.0.0"}
        - {name: UVS_LOG_LEVEL, value: "debug"}
        - {name: UVS_PORT, value: "3000"}
        - {name: NODE_EXTRA_CA_CERTS, value: /etc/ceffio-ca/ceffio-ca.crt}
        ports:
        - {name: http, containerPort: 3000}
        volumeMounts:
        - {name: ceffio-ca, mountPath: /etc/ceffio-ca}
        resources: {limits: {memory: 256Mi}}
      volumes:
      - {name: ceffio-ca, configMap: {name: ceffio-ca-cm}}
---
apiVersion: v1
kind: Service
metadata:
  name: uvs
  namespace: %[1]s
spec:
  selector: {app: uvs}
  ports:
  - {name: http, port: 3000, targetPort: 3000}
`, ns, traefikIP, matrixServer, uvsImage, synapseSvc)
	if err := apply(ctx, manifeste); err != nil {
		return fmt.Errorf("manifeste UVS: %w", err)
	}

	// 4. Plugins Prosody (embarqués, Apache-2.0) via ConfigMap monté dans le
	//    dossier custom que plugin_paths de l'image inclut déjà.
	if err := creerConfigMapPlugins(ctx); err != nil {
		return err
	}
	if err := monterPluginsProsody(ctx); err != nil {
		return err
	}

	// 4b. Synapse doit annoncer son nom PUBLIC dans /.well-known/matrix/server :
	//     UVS résout ce fichier pour savoir où vérifier les tokens OpenID
	//     (federation userinfo). L'hôte interne en http ne marcherait pas :
	//     la découverte Matrix construit https://<hôte>.
	if err := assurerWellKnownSynapse(ctx, matrixServer); err != nil {
		return err
	}

	// 5. Prosody en mode hybride : Matrix (widget) ET JWT (accès direct).
	uvsToken, err := lireSecretValue(ctx, ns, "uvs-auth", "token")
	if err != nil {
		return err
	}
	_ = uvsToken // passé par secretKeyRef, lu ici pour échouer tôt s'il manque
	envProsody := []map[string]any{
		{"name": "PROSODY_AUTH_TYPE", "value": "hybrid_matrix_token"},
		// Filtres globaux vidés EXPRESSION : le jeton du widget Element porte
		// iss=meet.<domaine> et aud=https://meet.<domaine> (vu dans le source
		// element-web, createJWTToken) — les filtres « jitsi » posés pour
		// l'accès direct les rejetteraient. Le module hybride construit sa
		// propre liste d'issuers : {JWT_APP_ID, MATRIX_UVS_ISSUER}, donc les
		// deux types de jeton restent vérifiés. Valeur vide = bloc du template
		// non rendu = pas de filtre aud (la signature HMAC reste vérifiée).
		{"name": "JWT_ACCEPTED_ISSUERS", "value": ""},
		{"name": "JWT_ACCEPTED_AUDIENCES", "value": ""},
		// FQDN obligatoire : le resolver interne de Prosody ne résout pas les
		// noms courts (même piège que xmpp.meet.jitsi — voir media.go). Sans
		// ça, la vérification Matrix échoue en silence (« user not found »).
		{"name": "MATRIX_UVS_URL", "value": "http://uvs.ceffio-video.svc.cluster.local:3000"},
		// iss du JWT fabriqué par le widget Element = le domaine Jitsi.
		{"name": "MATRIX_UVS_ISSUER", "value": meet},
		{"name": "MATRIX_UVS_AUTH_TOKEN", "valueFrom": map[string]any{
			"secretKeyRef": map[string]string{"name": "uvs-auth", "key": "token"}}},
		// Les modérateurs de la salle Matrix deviennent propriétaires Jitsi.
		{"name": "MATRIX_UVS_SYNC_POWER_LEVELS", "value": "1"},
	}
	if err := patcherEnvConteneur(ctx, "prosody", "prosody", envProsody); err != nil {
		return fmt.Errorf("patch prosody (hybride): %w", err)
	}

	// 6. /.well-known/element/jitsi : annonce au widget Element que ce domaine
	//    accepte l'auth « openidtoken-jwt ». Servi par le nginx du frontend via
	//    le ConfigMap jitsi-oidc-static (nginx-custom, déjà monté).
	if err := ajouterWellKnownJitsi(ctx); err != nil {
		return err
	}

	if err := relancerDeploiement(ctx, "prosody"); err != nil {
		return err
	}
	if err := relancerDeploiement(ctx, "web"); err != nil {
		return err
	}

	fmt.Println("✓ SSO Matrix configuré (widget Element sans re-login, accès direct toujours via Keycloak)")
	return nil
}

// ensureUVSSynapseToken garantit un utilisateur Synapse « uvs » (admin) et
// stocke son access_token dans le secret uvs-synapse-token. UVS s'en sert pour
// vérifier l'appartenance aux salles via l'API admin Synapse
// (/_synapse/admin/v1/rooms/{id}/members) — UVS ne rejoint PAS les salles.
//
// Idempotence, dans l'ordre le moins invasif :
//  1. login direct avec le mot de passe du secret (le cas courant : rien à faire) ;
//  2. sinon, admin registration (/_synapse/admin/v1/register) : crée le compte
//     et renvoie le token (premier déploiement) ;
//  3. sinon (M_USER_IN_USE : compte existant au mot de passe inconnu, p. ex.
//     créé à la main), réinitialisation du hash bcrypt en base + redémarrage
//     Synapse (cache mot de passe en mémoire) + login.
//
// Le mot de passe ne passe JAMAIS en argument de commande (injection shell +
// visible dans /proc) : toujours via stdin.
func ensureUVSSynapseToken(ctx context.Context) error {
	// Mot de passe : réutilisé depuis le secret s'il existe, sinon généré.
	mdp, err := lireSecretValue(ctx, ns, "uvs-synapse-token", "password")
	if err != nil || mdp == "" {
		if mdp, err = genSecret(18); err != nil {
			return err
		}
	}

	// 1. Login direct : si le secret est déjà valide, on ne touche à rien.
	if rep, err := loginUVS(ctx, mdp); err == nil && rep.AccessToken != "" {
		return sauverSecretUVS(ctx, mdp, rep)
	}

	// 2. Admin registration (crée le compte au premier déploiement).
	rep, err := registerAdminUVS(ctx, mdp)
	if err != nil {
		return err
	}
	if rep.AccessToken != "" {
		return sauverSecretUVS(ctx, mdp, rep)
	}

	// 3. Le compte existe déjà avec un autre mot de passe : reset bcrypt en
	//    base + restart Synapse (il cache les hash en mémoire) + login.
	if rep.ErrCode != "M_USER_IN_USE" {
		return fmt.Errorf("registration admin uvs refusé : %s %s", rep.ErrCode, first200(rep.Error))
	}
	fmt.Println("∙ compte « uvs » existant au mot de passe inconnu : réinitialisation en base")
	if err := resetPasswordUVS(ctx, mdp); err != nil {
		return err
	}
	rep, err = loginUVS(ctx, mdp)
	if err != nil {
		return err
	}
	if rep.AccessToken == "" {
		return fmt.Errorf("login uvs après reset refusé : %s", first200(rep.Error))
	}
	return sauverSecretUVS(ctx, mdp, rep)
}

// repLogin est la réponse commune aux endpoints login/register de Synapse.
type repLogin struct {
	AccessToken string `json:"access_token"`
	UserID      string `json:"user_id"`
	ErrCode     string `json:"errcode"`
	Error       string `json:"error"`
}

// loginUVS s'authentifie sur l'API client Synapse (payload via stdin).
func loginUVS(ctx context.Context, mdp string) (*repLogin, error) {
	payload, err := json.Marshal(map[string]any{
		"type":       "m.login.password",
		"identifier": map[string]any{"type": "m.id.user", "user": uvsUser},
		"password":   mdp,
	})
	if err != nil {
		return nil, err
	}
	body, err := execSynapseStdin(ctx, string(payload),
		`curl -s --max-time 10 -X POST http://localhost:8008/_matrix/client/v3/login -H 'Content-Type: application/json' -d @-`)
	if err != nil {
		return nil, fmt.Errorf("login uvs: %w", err)
	}
	var rep repLogin
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return nil, fmt.Errorf("login uvs : réponse illisible : %s", first200(body))
	}
	return &rep, nil
}

// registerAdminUVS crée le compte admin via l'endpoint d'admin registration
// (nonce + HMAC-SHA1 du shared secret — le schéma documenté de Synapse).
func registerAdminUVS(ctx context.Context, mdp string) (*repLogin, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "configmap", "synapse-config", "-n", chatNS,
		"-o", "jsonpath={.data.homeserver\\.yaml}").Output()
	if err != nil {
		return nil, fmt.Errorf("lecture config Synapse: %w", err)
	}
	shared := ""
	for _, ligne := range strings.Split(string(out), "\n") {
		if strings.Contains(ligne, "registration_shared_secret:") {
			parts := strings.SplitN(ligne, ":", 2)
			shared = strings.Trim(strings.TrimSpace(parts[1]), `"`)
		}
	}
	if shared == "" {
		return nil, fmt.Errorf("registration_shared_secret introuvable dans synapse-config")
	}

	nonceOut, err := execSynapse(ctx,
		`curl -s --max-time 10 http://localhost:8008/_synapse/admin/v1/register`)
	if err != nil {
		return nil, fmt.Errorf("nonce registration: %w", err)
	}
	var nonceRep struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(nonceOut), &nonceRep); err != nil || nonceRep.Nonce == "" {
		return nil, fmt.Errorf("nonce registration illisible : %s", first200(nonceOut))
	}

	// HMAC-SHA1(shared, nonce\x00user\x00pass\x00"admin").
	mac := hmac.New(sha1.New, []byte(shared))
	mac.Write([]byte(nonceRep.Nonce))
	mac.Write([]byte{0})
	mac.Write([]byte(uvsUser))
	mac.Write([]byte{0})
	mac.Write([]byte(mdp))
	mac.Write([]byte{0})
	mac.Write([]byte("admin"))

	payload, err := json.Marshal(map[string]any{
		"nonce":         nonceRep.Nonce,
		"username":      uvsUser,
		"password":      mdp,
		"mac":           hex.EncodeToString(mac.Sum(nil)),
		"admin":         true,
		"inhibit_login": false,
	})
	if err != nil {
		return nil, err
	}
	body, err := execSynapseStdin(ctx, string(payload),
		`curl -s --max-time 10 -X POST http://localhost:8008/_synapse/admin/v1/register -H 'Content-Type: application/json' -d @-`)
	if err != nil {
		return nil, fmt.Errorf("registration admin uvs: %w", err)
	}
	var rep repLogin
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		return nil, fmt.Errorf("registration illisible : %s", first200(body))
	}
	return &rep, nil
}

// resetPasswordUVS réinitialise le mot de passe en base : le hash bcrypt est
// calculé DANS le pod Synapse (bcrypt 5.0.0 y est installé — même lib que
// Synapse), transmis via stdin, écrit dans users.password_hash via psql.
// Synapse garde les hash en cache mémoire → redémarrage obligatoire après.
func resetPasswordUVS(ctx context.Context, mdp string) error {
	serverName := chatServerName(ctx)
	fullUserID := "@" + uvsUser + ":" + serverName

	// 1. Hash bcrypt calculé dans le pod Synapse (mot de passe via stdin).
	hash, err := execSynapseStdin(ctx, mdp,
		`python3 -c "import sys,bcrypt; sys.stdout.write(bcrypt.hashpw(sys.stdin.buffer.read().splitlines()[0], bcrypt.gensalt(12)).decode())"`)
	if err != nil || !strings.HasPrefix(hash, "$2") {
		return fmt.Errorf("calcul du hash bcrypt dans le pod Synapse : %v (%s)", err, first200(hash))
	}

	// 2. Écriture en base + garantie admin (le hash bcrypt ne contient que
	//    [A-Za-z0-9./$] : sûr à interpoler dans le SQL).
	sql := fmt.Sprintf(
		`UPDATE users SET password_hash = '%s', admin = 1, deactivated = 0 WHERE name = '%s';`,
		hash, fullUserID)
	if _, err := execPsqlSynapse(ctx, sql); err != nil {
		return err
	}

	// 3. Redémarrage Synapse (cache de mots de passe en mémoire).
	if err := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/synapse", "-n", chatNS).Run(); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/synapse", "-n", chatNS, "--timeout=420s")
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("redémarrage Synapse après reset: %w: %s", err, first200(string(out)))
	}
	return nil
}

// execPsqlSynapse exécute un SQL sur la base Synapse (pod Postgres ceffio-data).
func execPsqlSynapse(ctx context.Context, sql string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-c", "postgres",
		"-n", "ceffio-data", "ceffio-pg-1", "--",
		"psql", "-U", "postgres", "-d", "synapse", "-v", "ON_ERROR_STOP=1", "-tA")
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql synapse: %w: %s", err, first200(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// chatServerName lit le server_name effectif depuis la config Synapse.
func chatServerName(ctx context.Context) string {
	out, err := k8s.Command(ctx, "kubectl", "get", "configmap", "synapse-config", "-n", chatNS,
		"-o", "jsonpath={.data.homeserver\\.yaml}").Output()
	if err != nil {
		return ""
	}
	for _, ligne := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ligne), "server_name:") {
			return strings.TrimSpace(strings.SplitN(ligne, ":", 2)[1])
		}
	}
	return ""
}

// sauverSecretUVS persiste le token et valide le user_id reçu.
func sauverSecretUVS(ctx context.Context, mdp string, rep *repLogin) error {
	parts := strings.SplitN(rep.UserID, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("user_id Synapse inattendu : %q", rep.UserID)
	}
	if err := createSecret(ctx, "uvs-synapse-token", map[string]string{
		"access-token": rep.AccessToken,
		"password":     mdp,
		"user-id":      rep.UserID,
		"server-name":  parts[1],
	}); err != nil {
		return err
	}
	fmt.Println("∙ utilisateur Synapse « uvs » prêt (token → secret uvs-synapse-token)")
	return nil
}

// execSynapse exécute une commande shell dans le pod Synapse.
func execSynapse(ctx context.Context, sh string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-n", chatNS, "deploy/synapse", "--", "sh", "-c", sh)
	cmd.Env = k8s.Env()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// execSynapseStdin exécute une commande shell dans le pod Synapse en lui
// passant des données sur stdin (pour ne jamais exposer un secret en argv).
func execSynapseStdin(ctx context.Context, entree, sh string) (string, error) {
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", chatNS, "deploy/synapse", "--", "sh", "-c", sh)
	cmd.Env = k8s.Env()
	cmd.Stdin = strings.NewReader(entree)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// creerConfigMapPlugins crée le ConfigMap des plugins Prosody hybrides.
func creerConfigMapPlugins(ctx context.Context) error {
	donnees := map[string]string{}
	for _, nom := range []string{
		"mod_auth_hybrid_matrix_token.lua",
		"mod_matrix_affiliation.lua",
		"mod_matrix_lobby_bypass.lua",
	} {
		b, err := pluginsProsody.ReadFile("static/" + nom)
		if err != nil {
			return err
		}
		donnees[nom] = string(b)
	}
	return creerConfigMapDepuisDonnees(ctx, "jitsi-prosody-plugins", donnees)
}

// monterPluginsProsody monte le ConfigMap des plugins dans le PVC /config de
// prosody (plugin_paths de l'image inclut /prosody-plugins-custom, qui pointe
// vers /config/prosody-plugins-custom).
func monterPluginsProsody(ctx context.Context) error {
	out, err := k8s.Command(ctx, "kubectl", "get", "deploy", "prosody", "-n", ns, "-o", "json").Output()
	if err != nil {
		return err
	}
	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		return err
	}
	spec := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	ops := []map[string]any{}

	volumes, _ := spec["volumes"].([]any)
	aVolume := false
	for _, v := range volumes {
		if vm, ok := v.(map[string]any); ok && vm["name"] == "prosody-plugins" {
			aVolume = true
		}
	}
	if !aVolume {
		ops = append(ops, map[string]any{
			"op": "add", "path": "/spec/template/spec/volumes/-",
			"value": map[string]any{
				"name":      "prosody-plugins",
				"configMap": map[string]any{"name": "jitsi-prosody-plugins"},
			},
		})
	}

	// Mounts du conteneur prosody : ajouter s'il manque (idempotent).
	var idx int
	var prosody map[string]any
	for i, c := range spec["containers"].([]any) {
		if cm, ok := c.(map[string]any); ok && cm["name"] == "prosody" {
			prosody = cm
			idx = i
		}
	}
	if prosody == nil {
		return fmt.Errorf("conteneur prosody introuvable")
	}
	mounts, _ := prosody["volumeMounts"].([]any)
	aMount := false
	for _, m := range mounts {
		if mm, ok := m.(map[string]any); ok && mm["mountPath"] == pluginsDir {
			aMount = true
		}
	}
	if !aMount {
		mounts = append(mounts, map[string]any{"name": "prosody-plugins", "mountPath": pluginsDir})
		ops = append(ops, map[string]any{
			"op":    "replace",
			"path":  fmt.Sprintf("/spec/template/spec/containers/%d/volumeMounts", idx),
			"value": mounts,
		})
	}
	if len(ops) == 0 {
		return nil
	}
	b, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	return appliquerJSONPatch(ctx, "prosody", b)
}

// ajouterWellKnownJitsi ajoute la conf nginx /.well-known/element/jitsi au
// ConfigMap jitsi-oidc-static (déjà monté dans nginx-custom du frontend).
func ajouterWellKnownJitsi(ctx context.Context) error {
	out, err := k8s.Command(ctx, "kubectl", "get", "configmap", "jitsi-oidc-static", "-n", ns, "-o", "json").Output()
	if err != nil {
		return err
	}
	var cm map[string]any
	if err := json.Unmarshal(out, &cm); err != nil {
		return err
	}
	data, _ := cm["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	data["well-known-jitsi.conf"] = wellKnownJS
	cm["data"] = data
	delete(cm, "status")
	if md, ok := cm["metadata"].(map[string]any); ok {
		for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "managedFields"} {
			delete(md, k)
		}
	}
	b, err := json.Marshal(cm)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configmap jitsi-oidc-static: %w: %s", err, first200(string(out)))
	}
	return nil
}

// clusterIPService lit le ClusterIP d'un Service.
func clusterIPService(ctx context.Context, nom, namespace string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "svc", nom, "-n", namespace,
		"-o", "jsonpath={.spec.clusterIP}").Output()
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("ClusterIP vide pour svc/%s dans %s", nom, namespace)
	}
	return ip, nil
}

func first200(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// assurerWellKnownSynapse pose serve_server_wellknown dans la config Synapse :
// /.well-known/matrix/server doit annoncer le domaine PUBLIC (https implicite),
// car UVS construit https://<hôte> pour joindre l'API federation (userinfo).
// Une annonce vers le Service interne en http://…:8008 échouerait en TLS.
//
// Idempotent : ne redémarre Synapse que si la configuration change.
func assurerWellKnownSynapse(ctx context.Context, matrixServer string) error {
	cm, err := k8s.Command(ctx, "kubectl", "get", "configmap", "synapse-config", "-n", chatNS, "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("lecture synapse-config: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(cm, &doc); err != nil {
		return err
	}
	data, _ := doc["data"].(map[string]any)
	yamlData, _ := data["homeserver.yaml"].(string)
	if yamlData == "" {
		return fmt.Errorf("homeserver.yaml introuvable dans synapse-config")
	}

	bloc := "serve_server_wellknown:\n  - host: " + matrixServer + "\n    port: 443\n"
	nouveau := retirerBlocWellKnown(yamlData) + "\n" + bloc
	if nouveau == yamlData {
		return nil
	}
	data["homeserver.yaml"] = nouveau
	for _, k := range []string{"resourceVersion", "uid", "creationTimestamp", "managedFields"} {
		if md, ok := doc["metadata"].(map[string]any); ok {
			delete(md, k)
		}
	}
	delete(doc, "status")
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(b))
	cmd.Env = k8s.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("synapse-config: %w: %s", err, first200(string(out)))
	}
	fmt.Println("∙ serve_server_wellknown → " + matrixServer + " (résolution UVS)")

	// Synapse lit sa config au démarrage : redémarrer pour appliquer.
	return rolloutRestartSynapse(ctx)
}

// retirerBlocWellKnown supprime un bloc serve_server_wellknown existant
// (lignes suivantes indentées comprises) pour le remplacer proprement.
func retirerBlocWellKnown(y string) string {
	lignes := strings.Split(y, "\n")
	var out []string
	skip := false
	for _, l := range lignes {
		if strings.HasPrefix(l, "serve_server_wellknown:") {
			skip = true
			continue
		}
		if skip {
			if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") || l == "" {
				if l == "" {
					skip = false
					out = append(out, l)
				}
				continue
			}
			skip = false
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// rolloutRestartSynapse redémarre Synapse et attend qu'il soit prêt.
func rolloutRestartSynapse(ctx context.Context) error {
	if err := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/synapse", "-n", chatNS).Run(); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/synapse", "-n", chatNS, "--timeout=420s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
