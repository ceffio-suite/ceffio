// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"fmt"
	"strings"
)

// nomServiceAccount est celui que le rôle OpenBao désigne.
const nomServiceAccount = nomDeploy

// manifesteProxy builds the oauth2-proxy Deployment.
//
// EVERY OPTION IS HERE FOR A REASON A READER CAN CHECK, and several of them are the
// difference between "it works" and "it silently lets nobody in":
//
//	--provider=keycloak-oidc     the provider that knows Keycloak's specifics, rather
//	                             than plain oidc: it reads the roles claim correctly.
//	--authenticated-emails-file  THE AUTHORIZATION. Only the addresses in this file
//	                             pass. No --email-domain is set, so no whole domain is
//	                             opened by accident -- and without the file the proxy
//	                             would accept anyone Keycloak authenticated.
//	--skip-provider-button       the page Ceffio arrives from has already chosen the
//	                             provider: an intermediate "Sign in with..." screen is
//	                             a step users click through without reading.
//	--code-challenge-method S256 PKCE. Not mandatory for a confidential client, and
//	                             cheap: it stops an intercepted code from being replayed.
//	--cookie-secure / -domain    the cookie must not travel in clear, and must be scoped
//	                             to the host it was issued for.
//	--reverse-proxy=true         Traefik terminates TLS, so the redirect scheme comes
//	                             from X-Forwarded-*; without this the login loop never
//	                             ends, because the proxy builds http:// URLs.
//
// NOT SET, ON PURPOSE: --insecure-oidc-allow-unverified-email. oauth2-proxy refuses an
// account whose e-mail is not verified, and that refusal is right — the authorization
// is the address. The identity layer already creates the administrator with
// emailVerified=true; the answer to a refusal is to verify the account, not to tell the
// proxy to stop checking.
func manifesteProxy(domaine, somme string) string {
	hote := nomHote(domaine)
	issuer := "https://keycloak." + domaine + "/realms/ceffio"

	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
      annotations:
        # THE RESTART MECHANISM FOR THE ADDRESS LIST. oauth2-proxy reads the file at
        # startup, so rewriting the ConfigMap changes nothing until the process
        # restarts; Kubernetes restarts it when this value changes, and only then.
        ceffio.io/acces-somme: "%[3]s"
        %[4]s
    spec:
      serviceAccountName: %[5]s
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy:v7.15.5
          args:
            - --provider=keycloak-oidc
            - --oidc-issuer-url=%[6]s
            - --client-id=%[7]s
            # THE SECRET COMES FROM THE ENVIRONMENT THE AGENT RENDERS, never from an
            # argument: an argument is readable in /proc/<pid>/cmdline.
            - --upstream=http://longhorn-frontend.longhorn-system.svc:80
            # NO --email-domain, ON PURPOSE, and it is the security decision of this
            # module: an e-mail domain and a file of addresses are ALTERNATIVES, and
            # declaring a domain would open the whole domain -- including every account
            # an administrator creates later -- where the file opens exactly what it
            # lists.
            - --authenticated-emails-file=%[8]s
            - --redirect-url=https://%[9]s/oauth2/callback
            - --cookie-secure=true
            - --cookie-domain=%[9]s
            - --cookie-expire=8h
            - --cookie-refresh=1h
            - --reverse-proxy=true
            - --skip-provider-button=true
            - --code-challenge-method=S256
            - --set-xauthrequest=true
            - --pass-access-token=false
            - --http-address=0.0.0.0:4180
            - --metrics-address=0.0.0.0:44180
          env:
            # THE AGENT RENDERS /secrets/env FROM THE VAULT ENTRY; the shell sources it
            # before starting, exactly as Keycloak does. Passing it as a plain env
            # value would put the secret in the pod spec.
            - name: OAUTH2_PROXY_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: %[1]s-vault
                  key: client_secret
                  optional: true
            - name: OAUTH2_PROXY_COOKIE_SECRET
              valueFrom:
                secretKeyRef:
                  name: %[1]s-vault
                  key: cookie_secret
                  optional: true
          ports:
            - name: http
              containerPort: 4180
            - name: metrics
              containerPort: 44180
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            periodSeconds: 10
            failureThreshold: 3
          livenessProbe:
            httpGet:
              path: /ping
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: adresses
              mountPath: /etc/oauth2-proxy
              readOnly: true
          resources:
            requests:
              memory: 64Mi
              cpu: 20m
            limits:
              memory: 256Mi
      volumes:
        - name: adresses
          configMap:
            name: %[10]s
`, nomDeploy, nsSysteme, somme, annotationsVault(), nomServiceAccount,
		issuer, clientOIDC, cheminAdresses, hote, nomConfig)
}

// manifesteServiceEtRoute builds the ClusterIP Service and the Ingress.
//
// THE INGRESS POINTS AT THE PROXY, NEVER AT LONGHORN: the whole point of the module is
// that the interface is unreachable except through the sign-in. A route that pointed at
// longhorn-frontend would expose an unauthenticated interface under a hostname that
// looks protected.
func manifesteServiceEtRoute(domaine string) string {
	hote := nomHote(domaine)
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
spec:
  selector:
    app: %[1]s
  ports:
    - name: http
      port: 80
      targetPort: 4180
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  tls:
    - hosts:
        - %[3]s
      secretName: ceffio-wildcard-tls
  rules:
    - host: %[3]s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %[1]s
                port:
                  number: 80
`, nomService, nsSysteme, hote)
}

// annotationsVault renders the OpenBao agent annotations for the proxy's own entry.
//
// THE TEMPLATE WRITES A KUBERNETES SECRET because the pod reads these two values as
// ENVIRONMENT VARIABLES, which is what oauth2-proxy expects for
// OAUTH2_PROXY_CLIENT_SECRET and OAUTH2_PROXY_COOKIE_SECRET. A file would have needed a
// shell wrapper, and a wrapper is one more place to leak a secret into an argument.
func annotationsVault() string {
	return strings.Join([]string{
		`vault.hashicorp.com/agent-inject: "true"`,
		`vault.hashicorp.com/role: "` + nomDeploy + `"`,
		`vault.hashicorp.com/agent-inject-secret-oauth2: "` + coffreComposant + `/data/` + coffreChemin + `"`,
		`vault.hashicorp.com/agent-inject-template-oauth2: |`,
		`  {{- with secret "` + coffreComposant + `/data/` + coffreChemin + `" -}}`,
		`  {{- range $k, $v := .Data.data }}`,
		`  {{ $k }}={{ $v }}`,
		`  {{- end }}`,
		`  {{- end }}`,
	}, "\n        ")
}
