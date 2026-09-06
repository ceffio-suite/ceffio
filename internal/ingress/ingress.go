// Package ingress rend la suite joignable depuis un navigateur : issuers TLS
// cert-manager (CA auto-signée pour les domaines sans ACME public — dev/PME)
// et Ingresses Traefik avec hosts propres (*.<domain>).
//
// Prérequis : cert-manager installé (Phase 2) et un contrôleur Ingress
// "traefik" (natif k3s ; sur k3d, prévoir un contrôleur compatible).
package ingress

import (
	"context"
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

	// 3) Nextcloud : protocole https + URL publique dans la config.
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

	// 5) Connecteur ONLYOFFICE → URL publique.
	if err := occSet(ctx, "config:app:set", "onlyoffice", "documentServerUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}

	fmt.Println("✓ URLs publiques adoptées dans Element, Synapse, Nextcloud, ONLYOFFICE + redirects SSO")
	return nil
}

// rewriteConfig fait une substitution simple dans une valeur de ConfigMap puis redémarre la cible.
// old=="" → ne fait rien (utilisé pour vider le cache de lecture avant appendNonDuplicate).
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
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	cmdStr := `/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1 && /opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ") + ` 2>/dev/null`
	full := []string{"exec", "-n", "ceffio-identity", "deploy/keycloak", "--", "sh", "-c", cmdStr}
	out, err := exec.CommandContext(ctx, "kubectl", full...).Output()
	return strings.TrimSpace(string(out)), err
}

// kcadmRedirect ajoute un redirect URI au client OIDC Keycloak sans écraser les existants.
func kcadmRedirect(ctx context.Context, clientID, uri string) error {
	out, err := runKcadm(ctx, "get", "clients", "-r", "ceffio", "-q", "clientId="+clientID, "--fields", "id,redirectUris")
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
	_, err = runKcadm(ctx, "update", "clients/"+c.ID, "-r", "ceffio", "-s", "redirectUris="+string(val))
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
