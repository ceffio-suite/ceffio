// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/vault"
)

// nomServiceAccount est celui que le rôle OpenBao désigne.
const nomServiceAccount = nomDeploy

// THE TWO CREDENTIALS ARRIVE AS FILES, ONE PER VALUE, because oauth2-proxy
// accepts a path for each of them: --client-secret-file and
// --cookie-secret-file (v7.15.5, pkg/apis/options/legacy_options.go for the
// client and pkg/apis/options/cookie.go for the cookie).
//
// WHY NOT ONE FILE OF SHELL ASSIGNMENTS, the form every other workload uses:
// oauth2-proxy has no shell. It would have to source that file through a wrapper,
// and the values would then pass through a shell — the very thing the prefix
// "--client-secret-file" exists to avoid. Each file holds its value and NOTHING
// else, not even a final newline: the program reads the bytes with os.ReadFile
// and does not trim them (vault.GabaritValeur carries the proof).
const (
	cheminSecretClient = "/secrets/client-secret"
	cheminSecretCookie = "/secrets/cookie-secret"
)

// annotationsProxy builds the pod's annotation block: the address list's
// checksum, then the injector's own.
//
// THE RETURNED BLOCK ENDS WITH A NEWLINE, and the manifest relies on it to place
// the next key at its own indentation — the block's lines already carry theirs.
//
// THE ROLE NAMED HERE IS THE MODULE'S ID. The vault layer creates one Kubernetes
// auth role per module, from the registry — that is exactly what A4 added. Any
// other name asks for a role nobody created, and the pod hangs in Init with
// "invalid role name": silent on the application side, since the proxy never
// starts at all.
func annotationsProxy(somme string) (string, error) {
	coffre, err := vault.AnnotationsAgentFichiers(8, idModule, []vault.FichierInjecte{
		{
			Nom:     "client-secret",
			Chemin:  cheminCoffre,
			Gabarit: vault.GabaritValeur(cheminCoffre, "client-secret"),
			Perms:   "0400",
		},
		{
			Nom:     "cookie-secret",
			Chemin:  cheminCoffre,
			Gabarit: vault.GabaritValeur(cheminCoffre, "cookie_secret"),
			Perms:   "0400",
		},
	})
	if err != nil {
		return "", fmt.Errorf("longhorn-ui: the proxy's vault annotations: %w", err)
	}

	return fmt.Sprintf(`        # THE RESTART MECHANISM FOR THE ADDRESS LIST. oauth2-proxy reads the file at
        # startup, so rewriting the ConfigMap changes nothing until the process
        # restarts; Kubernetes restarts it when this value changes, and only then.
        ceffio.io/acces-somme: %q
        # THE AGENT MUST RUN AS THE POD'S USER, and this is not cosmetic: a file
        # in 0400 is readable only by its owner, and the injector's init container
        # creates it. Left to itself the agent runs as its own UID, the file
        # belongs to that UID, and the proxy — 65532 — cannot open it. The pod
        # then loops in Init on "permission denied", naming neither the file nor
        # the mode.
        vault.hashicorp.com/agent-run-as-user: "65532"
        vault.hashicorp.com/agent-run-as-group: "65532"
%s`, somme, coffre), nil
}

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
func manifesteProxy(domaine, annotations string) string {
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
%[3]s    spec:
      serviceAccountName: %[4]s
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        # THE INJECTED VOLUME IS SHARED WITH THE AGENT'S INIT CONTAINER, and
        # fsGroup is what makes it writable on any storage class: without it the
        # volume belongs to root, and the agent fails to create its file before
        # the proxy ever runs.
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy:v7.15.5
          args:
            - --provider=keycloak-oidc
            - --oidc-issuer-url=%[5]s
            - --client-id=%[6]s
            # THE TWO SECRETS ARE FILES THE AGENT RENDERS. Not arguments: a
            # secret on a command line is readable in /proc/<pid>/cmdline. Not
            # environment variables either, and the difference is decisive --
            # when the variable is set, oauth2-proxy NEVER OPENS THE FILE
            # (ProviderData.GetClientSecret returns early), so the injected file
            # would be decorative and a rotation in the vault would go unnoticed.
            - --client-secret-file=%[10]s
            - --cookie-secret-file=%[11]s
            - --upstream=http://longhorn-frontend.longhorn-system.svc:80
            # NO --email-domain, ON PURPOSE, and it is the security decision of this
            # module: an e-mail domain and a file of addresses are ALTERNATIVES, and
            # declaring a domain would open the whole domain -- including every account
            # an administrator creates later -- where the file opens exactly what it
            # lists.
            - --authenticated-emails-file=%[7]s
            - --redirect-url=https://%[8]s/oauth2/callback
            - --cookie-secure=true
            - --cookie-domain=%[8]s
            - --cookie-expire=8h
            - --cookie-refresh=1h
            - --reverse-proxy=true
            - --skip-provider-button=true
            - --code-challenge-method=S256
            - --set-xauthrequest=true
            - --pass-access-token=false
            - --http-address=0.0.0.0:4180
            - --metrics-address=0.0.0.0:44180
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
            name: %[9]s
`, nomDeploy, nsSysteme, annotations, nomServiceAccount,
		issuer, clientOIDC, cheminAdresses, hote, nomConfig,
		cheminSecretClient, cheminSecretCookie)
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

// manifesteServiceAccount renders the ServiceAccount the Deployment runs as.
//
// IT CARRIES NOTHING: no role binding inside the cluster, no token the proxy needs. Its
// purpose is to be a named identity — what the pod refers to — so that a grant can be
// attached to it later without rewriting the pod.
func manifesteServiceAccount() string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
    app.kubernetes.io/part-of: ceffio
`, nomServiceAccount, nsSysteme)
}
