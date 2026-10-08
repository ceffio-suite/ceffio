package media

// SSO Jitsi via Keycloak.
//
// Pourquoi un adaptateur plutôt qu'un branchement direct : Jitsi ne sait pas
// parler OIDC. Il sait déléguer l'authentification à un service qui lui renvoie
// un JETON SIGNÉ (mode « jwt ») :
//
//   ENABLE_AUTH=1 + AUTH_TYPE=jwt  →  Jitsi exige un jeton
//   JWT_APP_SECRET                 →  la clé partagée qui signe ces jetons
//   TOKEN_AUTH_URL                 →  où envoyer un visiteur sans jeton
//
// L'adaptateur (nordeck/jitsi-keycloak-adapter) est la pièce qui fait le pont :
// il reçoit le visiteur, le fait authentifier par Keycloak, puis lui renvoie un
// jeton Jitsi signé avec le secret partagé. Jitsi accepte alors la salle.
//
// Sans l'adaptateur, il faudrait un service maison qui parle OIDC d'un côté et
// signe des jetons Jitsi de l'autre — c'est exactement ce qu'il fait, en éprouvé
// et avec des images signées.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

const (
	adaptateurImage = "ghcr.io/nordeck/jitsi-keycloak-adapter:v20240109"
	// ns : le namespace de la couche visio (défini dans media.go).
)

// ConfigureSSO branche Jitsi sur Keycloak.
//
// Idempotent : les secrets ne sont créés que s'ils manquent (les régénérer
// invaliderait les jetons en cours), et le manifeste est appliqué tel quel.
func ConfigureSSO(ctx context.Context, domain string) error {
	fmt.Println("SSO Jitsi ← Keycloak (adaptateur OIDC → jeton Jitsi)...")

	// 1. Le secret partagé entre Jitsi et l'adaptateur. Il signe les jetons :
	//    le régénérer à chaque déploiement déconnecterait tout le monde, on ne le
	//    crée donc que s'il est absent.
	if err := ensureSecretSiAbsent(ctx, "jitsi-jwt", "app-secret", 32); err != nil {
		return err
	}
	// Le secret du client Keycloak, réconcilié par la phase SSO (même source de
	// vérité que Synapse et Nextcloud).
	// Vérifiés ici pour échouer TÔT si la phase SSO n'a pas réconcilié le client
	// Keycloak : le manifeste les référence par secretKeyRef, donc un secret
	// manquant laisserait un pod en erreur difficile à diagnostiquer.
	if _, err := lireSecretValue(ctx, "ceffio-identity", "jitsi-oidc", "client-secret"); err != nil {
		return fmt.Errorf("secret jitsi-oidc: %w (la phase SSO doit réconcilier le client « jitsi »)", err)
	}
	if _, err := lireSecretValue(ctx, ns, "jitsi-jwt", "app-secret"); err != nil {
		return fmt.Errorf("secret jitsi-jwt: %w", err)
	}

	// 2. Copier le client OIDC dans le namespace de la visio.
	//
	// Le secret vit dans ceffio-identity ; l'adaptateur tourne dans ceffio-video.
	// Un secretKeyRef ne traverse PAS les namespaces — le pod resterait en
	// CreateContainerConfigError « secret jitsi-oidc not found ».
	if err := copierSecretVers(ctx, "ceffio-identity", "jitsi-oidc", ns); err != nil {
		return err
	}

	// 3. L'adaptateur : il reçoit le visiteur, l'envoie sur Keycloak, puis lui
	//    rend un jeton Jitsi signé.
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
        # Keycloak vu par le NAVIGATEUR (c'est lui qui y va) : nom public.
        - {name: KEYCLOAK_ORIGIN, value: "https://keycloak.%[3]s"}
        - {name: KEYCLOAK_REALM, value: ceffio}
        - {name: KEYCLOAK_CLIENT_ID, value: jitsi}
        # Le nom public n'est pas résolvable depuis le conteneur en général : on
        # lui donne l'adresse interne pour ses appels serveur→serveur.
        - {name: KEYCLOAK_ORIGIN_INTERNAL, value: "http://keycloak.ceffio-identity.svc:8080"}
        - {name: KEYCLOAK_CLIENT_SECRET, valueFrom: {secretKeyRef: {name: jitsi-oidc, key: client-secret}}}
        - {name: JWT_APP_ID, value: jitsi}
        - {name: JWT_APP_SECRET, valueFrom: {secretKeyRef: {name: jitsi-jwt, key: app-secret}}}
        # Notre autorité interne n'est pas dans le magasin système de l'image :
        # ses appels vers Keycloak en interne seraient refusés.
        - {name: ALLOW_UNSECURE_CERT, value: "false"}
        - {name: NODE_EXTRA_CA_CERTS, value: /etc/ceffio-ca/paquet-combine.crt}
        ports:
        - {name: http, containerPort: 9000}
        volumeMounts:
        - {name: ceffio-ca, mountPath: /etc/ceffio-ca}
        resources: {limits: {memory: 256Mi}}
      volumes:
      - {name: ceffio-ca, configMap: {name: ceffio-ca-cm}}
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

	// 4. Le frontend Jitsi : basculer l'authentification en mode jeton.
	//
	// Les patches sont ASSEMBLÉS par json.Marshal plutôt qu'écrits à la main :
	// un littéral JSON écrit à la main se déséquilibre facilement (constaté :
	// « unexpected end of JSON input ») et l'erreur ne dit pas où.
	envFrontend := []map[string]any{
		{"name": "ENABLE_AUTH", "value": "1"},
		{"name": "AUTH_TYPE", "value": "jwt"},
		{"name": "JWT_APP_ID", "value": "jitsi"},
		{"name": "JWT_APP_SECRET", "valueFrom": map[string]any{
			"secretKeyRef": map[string]string{"name": "jitsi-jwt", "key": "app-secret"}}},
		{"name": "JWT_ACCEPTED_ISSUERS", "value": "jitsi"},
		{"name": "JWT_ACCEPTED_AUDIENCES", "value": "jitsi"},
		{"name": "TOKEN_AUTH_URL", "value": "https://meet." + domain + "/auth/{room}"},
		{"name": "ENABLE_GUESTS", "value": "1"},
	}
	if err := patcherEnvConteneur(ctx, "web", "web", envFrontend); err != nil {
		return fmt.Errorf("patch frontend Jitsi: %w", err)
	}

	// Prosody doit accepter ces jetons : sans cela il refuse les visiteurs que le
	// frontend vient d'accepter.
	envProsody := []map[string]any{
		{"name": "ENABLE_AUTH", "value": "1"},
		{"name": "AUTH_TYPE", "value": "jwt"},
		{"name": "JWT_APP_ID", "value": "jitsi"},
		{"name": "JWT_APP_SECRET", "valueFrom": map[string]any{
			"secretKeyRef": map[string]string{"name": "jitsi-jwt", "key": "app-secret"}}},
		{"name": "JWT_ACCEPTED_ISSUERS", "value": "jitsi"},
		{"name": "JWT_ACCEPTED_AUDIENCES", "value": "jitsi"},
		{"name": "PROSODY_AUTH_TYPE", "value": "jwt"},
		{"name": "JICOFO_AUTH_TYPE", "value": "internal"},
	}
	if err := patcherEnvConteneur(ctx, "prosody", "prosody", envProsody); err != nil {
		return fmt.Errorf("patch prosody: %w", err)
	}

	// 5. Redémarrer : les pods prennent les nouvelles variables.
	for _, cible := range []string{"prosody", "web", "jicofo"} {
		if err := relancerDeploiement(ctx, cible); err != nil {
			return err
		}
	}

	fmt.Println("✓ SSO Jitsi configuré (login Keycloak sur https://meet." + domain + ")")
	return nil
}

// ensureSecretSiAbsent crée un secret avec une valeur ALÉATOIRE seulement s'il
// n'existe pas.
//
// Pourquoi ne pas le régénérer : ce secret signe les jetons. Le recréer à chaque
// déploiement invaliderait tous les jetons en cours et déconnecterait les
// participants — un déploiement deviendrait une interruption de service.
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

// patcherEnvConteneur remplace les variables d'environnement d'un conteneur.
//
// Le patch est CONSTRUIT par json.Marshal : un littéral JSON écrit à la main se
// déséquilibre facilement et l'erreur renvoyée (« unexpected end of JSON
// input ») ne dit pas où — perte de temps garantie.
//
// Le patch remplace la liste `env` en entier : c'est ce qu'on veut ici, les
// variables d'authentification se posant en bloc.
func patcherEnvConteneur(ctx context.Context, deploiement, conteneur string, env []map[string]any) error {
	// On lit les variables existantes pour ne pas écraser celles qui ne
	// concernent pas l'authentification (XMPP_*, TZ, ...).
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
							nom, _ := im["name"].(string)
							if !remplaces[nom] {
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

// copierSecretVers recopie un secret d'un namespace à un autre.
//
// Indispensable : un secretKeyRef ne traverse PAS les namespaces. L'adaptateur
// SSO tourne dans le namespace de la visio et a besoin du client OIDC créé par
// la phase SSO (qui vit dans ceffio-identity).
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
	// Les métadonnées de la source (uid, resourceVersion) seraient refusées à la
	// création : on les remplace entièrement.
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
		return fmt.Errorf("copie du secret vers %s : %w : %s", nsCible, err, string(out))
	}
	fmt.Printf("✓ Secret %s copié dans %s (les références ne traversent pas les namespaces)\n", nom, nsCible)
	return nil
}

// relancerDeploiement redémarre un Deployment et attend qu'il soit prêt.
func relancerDeploiement(ctx context.Context, nom string) error {
	if err := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/"+nom, "-n", ns).Run(); err != nil {
		return err
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+nom, "-n", ns, "--timeout=200s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
