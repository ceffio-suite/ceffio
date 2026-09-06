// Package ingress rend la suite joignable depuis un navigateur : issuers TLS
// cert-manager (CA auto-signée pour les domaines sans ACME public — dev/PME)
// et Ingresses Traefik avec hosts propres (*.<domain>).
//
// Prérequis : cert-manager installé (Phase 2) et un contrôleur Ingress
// "traefik" (natif k3s ; sur k3d, prévoir un contrôleur compatible).
package ingress

import (
	"context"
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

// apply applique un manifest (multi-docs) via `kubectl apply -f -`.
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
