// Package ingress rend la suite joignable depuis un navigateur : issuers TLS
// cert-manager (CA auto-signée pour les domaines sans ACME public — dev/PME)
// et Ingresses Traefik avec hosts propres (*.<domain>).
//
// Prérequis : cert-manager installé (Phase 2) et un contrôleur Ingress
// "traefik" (natif k3s ; sur k3d, prévoir un contrôleur compatible).
package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Deploy applique de façon idempotente la CA + les Ingresses pour le domaine.
// domain : domaine de base, ex. "company.fr" → cloud.company.fr, chat.company.fr...
func Deploy(ctx context.Context, domain string) error {
	fmt.Printf("\nIngress / TLS (Phase 9) pour domain=%s...\n", domain)
	if err := apply(ctx, caManifest()); err != nil {
		return err
	}
	if err := apply(ctx, ingressesManifest(domain)); err != nil {
		return err
	}
	fmt.Println("✓ Ingress / TLS configuré (Traefik + ClusterIssuer CA + hosts *." + domain + ")")
	return nil
}

// AdoptURLs rend les apps pleinement utilisables via les URLs publiques de
// l'ingress : homeserver réel pour Element, public_baseurl Synapse, protocole
// https Nextcloud, redirect URIs SSO et URL du connecteur ONLYOFFICE.
func AdoptURLs(ctx context.Context, domain string) error {
	fmt.Printf("\nAdoption des URLs publiques *.%s...\n", domain)
	matrix := "matrix." + domain
	cloud := "cloud." + domain
	office := "office." + domain

	// 1) Element → homeserver public (base_url) pour que le navigateur joigne Synapse.
	if err := rewriteConfig(ctx, "ceffio-chat", "element-config", "config.json",
		`"http://synapse.ceffio-chat.svc:8008"`, `"https://`+matrix+`"`,
		"deploy/element"); err != nil {
		return err
	}

	// 2) Synapse → public_baseurl pour les URLs d'auth/fédération générées.
	if err := rewriteConfig(ctx, "ceffio-chat", "synapse-config", "homeserver.yaml",
		"", "", "deploy/synapse"); err != nil {
		return err
	}
	host := "https://" + matrix
	if err := appendNonDuplicate(ctx, "ceffio-chat", "synapse-config", "homeserver.yaml",
		"public_baseurl: "+host+"\n", "public_baseurl:", "deploy/synapse"); err != nil {
		return err
	}
	// 2b) OIDC Synapse → issuer/endpoints publics https (discover:false). Sinon le
	// navigateur est renvoyé vers l'URL interne, et un token_endpoint http est refusé.
	if err := rewriteSynapseOidc(ctx, domain); err != nil {
		return err
	}

	// 3) Nextcloud : protocole https + URL publique + SSRF + proxy derrière Traefik.
	// Le HttpClient de Nextcloud bloque par défaut les adresses privées (SSRF) :
	// or Keycloak/ONLYOFFICE sont en IP de cluster → autoriser les serveurs locaux.
	if err := occSet(ctx, "config:system:set", "allow_local_remote_servers", "--type", "boolean", "--value", "true"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "trusted_proxies", "0", "--value", "10.42.0.0/16"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwritehost", "--value", cloud); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwriteprotocol", "--value", "https"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:system:set", "overwrite.cli.url", "--value", "https://"+cloud); err != nil {
		return err
	}

	// 4) Redirections SSO Keycloak des clients nextcloud + synapse vers le https.
	if err := ssoRedirect(ctx, domain); err != nil {
		return err
	}

	// 5) Connecteur ONLYOFFICE → URL publique. Clés EXACTES (casse CamelCase,
	// sinon "L'application ONLYOFFICE n'est pas configuré").
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerInternalUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "StorageUrl", "--value", "https://"+cloud+"/"); err != nil {
		return err
	}

	// 6) Keycloak : hostname public + URL frontend https + proxy headers — sinon
	// ses redirections navigateur pointent vers l'hostname interne codé en dur.
	if err := adoptKeycloakHost(ctx, domain); err != nil {
		return err
	}

	// 7) Durcissement DEMO uniquement (domaine privé `.local`, TLS auto-signé) :
	// hostAliases→Traefik + injection CA dans les pods. Un vrai domaine public n'en
	// a pas besoin (DNS réel + CA Let's Encrypt).
	if isDemo(domain) {
		if err := HardenDemo(ctx, domain); err != nil {
			return err
		}
	}

	fmt.Println("✓ URLs publiques adoptées dans Element, Synapse, Nextcloud, ONLYOFFICE, Keycloak + redirects SSO")
	return nil
}

// adoptKeycloakHost force l'hostname public de Keycloak (redirections navigateur)
// avec une URL frontend https et les proxy headers de Traefik. Idempotent.
func adoptKeycloakHost(ctx context.Context, domain string) error {
	host := "keycloak." + domain
	url := "https://" + host
	cmd := exec.CommandContext(ctx, "kubectl", "set", "env", "-n", "ceffio-identity", "deploy/keycloak",
		"KC_HOSTNAME="+host, "KC_HOSTNAME_URL="+url,
		"KC_HOSTNAME_STRICT=false", "KC_PROXY_HEADERS=xforwarded")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	rcmd := exec.CommandContext(ctx, "kubectl", "rollout", "status", "deploy/keycloak", "-n", "ceffio-identity", "--timeout=240s")
	rcmd.Stdout = os.Stdout
	rcmd.Stderr = os.Stderr
	return rcmd.Run()
}

// isDemo → domaine privé `.local` : pas de DNS réel ni CA publique → durcissement
// hostAliases + injection CA. Un domaine public n'en a pas besoin.
func isDemo(domain string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(domain)), ".local")
}

// rewriteSynapseOidc bascule le bloc OIDC de Synapse vers issuer + endpoints publics
// https (discover:false). Sinon le navigateur reçoit l'URL interne et un token_endpoint
// http est refusé par Synapse.
func rewriteSynapseOidc(ctx context.Context, domain string) error {
	key := "homeserver.yaml"
	data, err := cmData(ctx, "ceffio-chat", "synapse-config", key)
	if err != nil {
		return err
	}
	oldIssuer := `issuer: "http://keycloak.ceffio-identity.svc:8080/realms/ceffio"`
	if !strings.Contains(data, oldIssuer) {
		return nil // déjà public
	}
	kc := "keycloak." + domain
	newBlock := fmt.Sprintf(`issuer: "https://%s/realms/ceffio"
    discover: false
    authorization_endpoint: "https://%s/realms/ceffio/protocol/openid-connect/auth"
    token_endpoint: "https://%s/realms/ceffio/protocol/openid-connect/token"
    userinfo_endpoint: "https://%s/realms/ceffio/protocol/openid-connect/userinfo"
    jwks_uri: "https://%s/realms/ceffio/protocol/openid-connect/certs"`, kc, kc, kc, kc, kc)
	data = strings.Replace(data, oldIssuer, newBlock, 1)
	if err := applyCMData(ctx, "ceffio-chat", "synapse-config", key, data); err != nil {
		return err
	}
	return rolloutRestart(ctx, "deploy/synapse")
}

// HardenDemo (déploiements DEMO uniquement) : hostAliases → Traefik + CA ceffio injectée
// pour que les calls serveur→serveur en https public fonctionnent.
func HardenDemo(ctx context.Context, domain string) error {
	fmt.Println("Durcissement DEMO : hostAliases→Traefik + CA ceffio injectée...")
	tip, err := svcIP(ctx, "traefik", "kube-system")
	if err != nil {
		return fmt.Errorf("IP Traefik: %w", err)
	}
	ca, err := caCert(ctx)
	if err != nil {
		return err
	}
	kc := "keycloak." + domain
	cloud := "cloud." + domain
	office := "office." + domain

	// Nextcloud (PHP) : CA via php.ini pointant sur la CA montée (persistant pour PHP).
	if err := createCAConfigs(ctx, "ceffio-files", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-files", "nextcloud", "nextcloud", tip,
		[]string{kc, office}, []envKV{{"SSL_CERT_FILE", "/etc/ceffio-ca/ceffio-ca.crt"}}, true); err != nil {
		return err
	}

	// Synapse (Python) : SSL_CERT_FILE.
	if err := createCAConfigs(ctx, "ceffio-chat", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-chat", "synapse", "synapse", tip,
		[]string{kc}, []envKV{{"SSL_CERT_FILE", "/etc/ceffio-ca/ceffio-ca.crt"}}, false); err != nil {
		return err
	}

	// ONLYOFFICE (Node.js) : NODE_EXTRA_CA_CERTS.
	if err := createCAConfigs(ctx, "ceffio-office", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-office", "onlyoffice", "onlyoffice", tip,
		[]string{cloud, office, kc}, []envKV{{"NODE_EXTRA_CA_CERTS", "/etc/ceffio-ca/ceffio-ca.crt"}}, false); err != nil {
		return err
	}
	fmt.Println("✓ Durcissement DEMO appliqué (hostAliases→" + tip + ")")
	return nil
}

type envKV struct{ name, value string }

// svcIP lit le ClusterIP d'un Service.
func svcIP(ctx context.Context, name, ns string) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "svc", name, "-n", ns, "-o", "jsonpath={.spec.clusterIP}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// caCert lit le certificat CA de la chaîne signée par cert-manager (ceffio-ca-tls).
func caCert(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "secret", "ceffio-ca-tls", "-n", "cert-manager", "-o", "jsonpath={.data.ca\\.crt}").Output()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// createCAConfigs crée les ConfigMaps ceffio-ca-cm (CA) + ceffio-phpini (php.ini) dans le ns.
func createCAConfigs(ctx context.Context, ns, ca string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-ca-cm -n "+ns+" --from-file=ceffio-ca.crt=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -")
	cmd.Stdin = strings.NewReader(ca)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	ini := "openssl.cafile=/etc/ceffio-ca/ceffio-ca.crt\ncurl.cainfo=/etc/ceffio-ca/ceffio-ca.crt\n"
	cmd2 := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-phpini -n "+ns+" --from-file=zz-ceffio.ini=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -")
	cmd2.Stdin = strings.NewReader(ini)
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	return cmd2.Run()
}

// patchApp applique hostAliases + volume CA + env (+ php.ini) via merge patch (idempotent).
func patchApp(ctx context.Context, ns, deploy, container, traefikIP string, hosts []string, envs []envKV, withPHPIni bool) error {
	ha := []map[string]any{{"ip": traefikIP, "hostnames": hosts}}
	vols := []map[string]any{{"name": "ceffio-ca", "configMap": map[string]string{"name": "ceffio-ca-cm"}}}
	env := []map[string]string{}
	for _, e := range envs {
		env = append(env, map[string]string{"name": e.name, "value": e.value})
	}
	mounts := []map[string]string{{"name": "ceffio-ca", "mountPath": "/etc/ceffio-ca"}}
	if withPHPIni {
		vols = append(vols, map[string]any{"name": "ceffio-phpini", "configMap": map[string]string{"name": "ceffio-phpini"}})
		mounts = append(mounts, map[string]string{"name": "ceffio-phpini", "mountPath": "/usr/local/etc/php/conf.d"})
	}
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostAliases": ha,
					"volumes":     vols,
					"containers": []any{
						map[string]any{
							"name":         container,
							"env":          env,
							"volumeMounts": mounts,
						},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(patch)
	cmd := exec.CommandContext(ctx, "kubectl", "patch", "deploy", deploy, "-n", ns, "--type=strategic", "-p", string(b))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	r := exec.CommandContext(ctx, "kubectl", "rollout", "status", "deploy/"+deploy, "-n", ns, "--timeout=200s")
	r.Stdout = os.Stdout
	r.Stderr = os.Stderr
	return r.Run()
}

// rewriteConfig fait une substitution simple dans une valeur de ConfigMap puis redémarre la cible.
func rewriteConfig(ctx context.Context, ns, cm, key, old, repl, target string) error {
	data, err := cmData(ctx, ns, cm, key)
	if err != nil {
		return err
	}
	if old != "" && strings.Contains(data, old) {
		data = strings.ReplaceAll(data, old, repl)
		if err := applyCMData(ctx, ns, cm, key, data); err != nil {
			return err
		}
		if err := rolloutRestart(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

// appendNonDuplicate ajoute une ligne à une ConfigMap si absente (idempotent), puis redémarre.
func appendNonDuplicate(ctx context.Context, ns, cm, key, line, needle, target string) error {
	data, err := cmData(ctx, ns, cm, key)
	if err != nil {
		return err
	}
	if strings.Contains(data, needle) {
		return nil // déjà présent
	}
	if err := applyCMData(ctx, ns, cm, key, data+"\n"+line); err != nil {
		return err
	}
	return rolloutRestart(ctx, target)
}

// ssoRedirect ajoute les redirect URIs https des clients OIDC via kcadm.
func ssoRedirect(ctx context.Context, domain string) error {
	for _, client := range []struct{ id, base string }{
		{id: "nextcloud", base: "cloud." + domain},
		{id: "synapse", base: "matrix." + domain},
	} {
		uri := "https://" + client.base + "/*"
		if err := kcadmRedirect(ctx, client.id, uri); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers ---

func occSet(ctx context.Context, args ...string) error {
	full := append([]string{"exec", "-n", "ceffio-files", "deploy/nextcloud", "--", "php", "occ"}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmData(ctx context.Context, ns, name, key string) (string, error) {
	tpl := "{.data." + strings.ReplaceAll(key, ".", "\\.") + "}"
	out, err := exec.CommandContext(ctx, "kubectl", "get", "cm", name, "-n", ns, "-o", "jsonpath="+tpl).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func applyCMData(ctx context.Context, ns, name, key, data string) error {
	tmp, err := os.CreateTemp("", "cm-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := os.WriteFile(tmp.Name(), []byte(data), 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap "+name+" -n "+ns+" --from-file="+key+"="+tmp.Name()+" --dry-run=client -o yaml | kubectl apply -f -")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func rolloutRestart(ctx context.Context, target string) error {
	deploy := strings.TrimPrefix(target, "deploy/")
	ns := map[string]string{
		"element": "ceffio-chat", "synapse": "ceffio-chat",
		"nextcloud": "ceffio-files", "onlyoffice": "ceffio-office",
		"keycloak": "ceffio-identity",
	}[deploy]
	if ns == "" {
		return fmt.Errorf("namespace inconnu pour %q", target)
	}
	cmd := exec.CommandContext(ctx, "kubectl", "rollout", "restart", "deploy/"+deploy, "-n", ns)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runKcadm(ctx context.Context, args ...string) (string, error) {
	// Injecte -r ceffio après le verbe (les clients SSO vivent dans le realm applicatif).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'ceffio'")
		}
	}
	cmdStr := `/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 && /opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")
	full := []string{"exec", "-n", "ceffio-identity", "deploy/keycloak", "--", "sh", "-c", cmdStr}
	out, err := exec.CommandContext(ctx, "kubectl", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// kcadmRedirect ajoute un redirect URI au client OIDC Keycloak sans écraser les existants.
func kcadmRedirect(ctx context.Context, clientID, uri string) error {
	out, err := runKcadm(ctx, "get", "clients", "-q", "clientId="+clientID, "--fields", "id,redirectUris")
	if err != nil {
		return fmt.Errorf("get client %s: %w (%s)", clientID, err, out)
	}
	var list []struct {
		ID           string   `json:"id"`
		RedirectUris []string `json:"redirectUris"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return fmt.Errorf("parse client %s: %w (%s)", clientID, err, out)
	}
	if len(list) == 0 {
		return fmt.Errorf("client %s introuvable dans le realm ceffio", clientID)
	}
	c := list[0]
	seen := map[string]bool{uri: true}
	uris := []string{uri}
	for _, u := range c.RedirectUris {
		if u != "" && !seen[u] {
			uris = append(uris, u)
			seen[u] = true
		}
	}
	val, _ := json.Marshal(uris)
	_, err = runKcadm(ctx, "update", "clients/"+c.ID, "-s", "redirectUris="+string(val))
	return err
}

func apply(ctx context.Context, manifest string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// caManifest : CA auto-signée (issuer bootstrap → certificat CA → issuer CA)
// pour signer les certificats des Ingresses. Se fait une fois, idempotent.
func caManifest() string {
	return `apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ceffio-selfsigned
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ceffio-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: ceffio-ca
  secretName: ceffio-ca-tls
  duration: 87600h
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: ceffio-selfsigned
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ceffio-ca-issuer
spec:
  ca:
    secretName: ceffio-ca-tls
`
}

// appRoute décrit une route applicative : host "<sub>.<domain>", service cible.
type appRoute struct {
	sub, namespace, service string
	port                    int
}

func ingressesManifest(domain string) string {
	routes := []appRoute{
		{sub: "cloud", namespace: "ceffio-files", service: "nextcloud", port: 80},
		{sub: "chat", namespace: "ceffio-chat", service: "element", port: 8080},
		{sub: "matrix", namespace: "ceffio-chat", service: "synapse", port: 8008},
		{sub: "keycloak", namespace: "ceffio-identity", service: "keycloak", port: 8080},
		{sub: "office", namespace: "ceffio-office", service: "onlyoffice", port: 80},
	}
	var sb strings.Builder
	for _, r := range routes {
		host := r.sub + "." + domain
		fmt.Fprintf(&sb, `---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
  annotations:
    cert-manager.io/cluster-issuer: ceffio-ca-issuer
spec:
  ingressClassName: traefik
  tls:
    - hosts: [%[3]s]
      secretName: %[1]s-tls
  rules:
    - host: %[3]s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %[4]s
                port:
                  number: %[5]d
`, r.sub, r.namespace, host, r.service, r.port)
	}
	return sb.String()
}
