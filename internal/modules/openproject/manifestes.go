// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"fmt"
	"net/url"

	"github.com/ceffio-suite/ceffio/internal/vault"
)

// THE MANIFESTS ARE BUILT HERE, AND ONLY HERE, so manifestes_test.go can parse
// every document they produce. Each builder takes its values as arguments and
// uses explicit %[n]s indexes: mixing indexed and positional verbs silently
// shifts every value that follows (internal/files, manifesteNextcloud, keeps
// the YAML error that taught the suite this).

// Paths inside the containers.
const (
	// cheminAssets is OpenProject's documented data directory; attachments are
	// stored under it unless told otherwise.
	cheminAssets = "/var/openproject/assets"

	// The two proxy credentials, as files the injector renders (see the
	// longhorn-ui module for why oauth2-proxy must read files, not variables).
	cheminSecretClient = "/secrets/client-secret"
	cheminSecretCookie = "/secrets/cookie-secret"

	// enTeteUtilisateur is the header oauth2-proxy sets from the validated
	// token's preferred_username claim, and the one OpenProject trusts.
	//
	// THE USERNAME, NOT THE E-MAIL: OpenProject matches the header against the
	// account LOGIN, and the Users page creates accounts under the Keycloak
	// username (comptes.go). Using the e-mail would log nobody in.
	enTeteUtilisateur = "X-Forwarded-Preferred-Username"

	// uidOpenProject is the user the OpenProject image runs as.
	uidOpenProject = "1000"
	// uidProxy is the distroless oauth2-proxy user.
	uidProxy = "65532"
)

// issuerKeycloak is the realm every component of the suite signs in against.
func issuerKeycloak(domaine string) string {
	return "https://keycloak." + domaine + "/realms/ceffio"
}

// urlDeconnexion is where OpenProject sends a user who signs out.
//
// TWO SESSIONS MUST END, in this order: the proxy's cookie (/oauth2/sign_out),
// then Keycloak's (the realm's logout endpoint). Ending only OpenProject's own
// session is worse than useless — the proxy still holds a valid cookie, sets
// the header on the very next request, and the user is signed straight back in
// while believing they signed out.
func urlDeconnexion(domaine string) string {
	keycloak := issuerKeycloak(domaine) + "/protocol/openid-connect/logout?" + url.Values{
		"client_id":                {clientOIDC},
		"post_logout_redirect_uri": {"https://" + nomHote(domaine) + "/"},
	}.Encode()
	return "https://" + nomHote(domaine) + "/oauth2/sign_out?rd=" + url.QueryEscape(keycloak)
}

// manifesteBase renders the ServiceAccount and the volume.
//
// THE SERVICEACCOUNT EXISTS BEFORE THE PODS: a pod naming a missing account is
// never created at all, and the ReplicaSet's FailedCreate does not say who was
// supposed to create it (longhorn-ui found this by deploying).
func manifesteBase(classe string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[2]s
  namespace: %[1]s
  labels:
    app.kubernetes.io/part-of: ceffio
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %[3]s
  namespace: %[1]s
  labels:
    app.kubernetes.io/part-of: ceffio
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: %[4]s
  resources:
    requests:
      storage: 10Gi
`, nsProjets, nomServiceAccount, nomVolume, classe)
}

// annotationsApp builds the injector annotations of the application pod.
//
// ONE FILE, THREE VAULT ENTRIES: the database URL, the Rails secret and the
// seeded administrator's password are composed into /secrets/env, which every
// container sources before starting.
//
// THE PASSWORD IS SPLICED INTO THE URL here, by the injector, and never by this
// program: the URL is a secret as a whole, and building it in Go would put it
// in a variable, then in a manifest. The password is hexadecimal (see
// genererSecret), so it needs no URL escaping.
//
// agent-init-first IS NOT OPTIONAL: the pod has its own init container (the
// seeder), and the injector APPENDS its agent after existing init containers
// unless told otherwise. The seeder would then run before /secrets/env exists,
// find no DATABASE_URL, and fail with a connection error that names neither the
// vault nor the order.
func annotationsApp() string {
	gabarit := vault.GabaritMulti([]vault.Source{
		{Chemin: cheminCoffre(coffreDB), Paires: [][2]string{
			{"DATABASE_URL", "postgres://" + dbUser + ":" + vault.ChampCoffre("password") +
				"@" + pgService + ":5432/" + dbName + "?pool=20&encoding=unicode"},
		}},
		{Chemin: cheminCoffre(coffreApp), Paires: [][2]string{
			{"SECRET_KEY_BASE", vault.ChampCoffre("secret_key_base")},
			{"OPENPROJECT_SEED__ADMIN__USER__PASSWORD", vault.ChampCoffre("admin_password")},
		}},
	})
	return vault.AnnotationsAgent(8, idModule, cheminCoffre(coffreDB), gabarit) +
		`        vault.hashicorp.com/agent-init-first: "true"
`
}

// commande renders the shell command of one OpenProject process.
//
// THE IMAGE'S OWN SCRIPTS ARE KEPT (/app/docker/prod/web|worker|seeder): they
// are what the upstream Helm chart and docker-compose run. We only source the
// rendered secrets first — the documented way to feed variables to a program
// that reads nothing else.
func commande(processus string) string {
	return fmt.Sprintf(`["bash", "-c", "set -a; . /secrets/env; set +a; exec bash /app/docker/prod/%s"]`, processus)
}

// manifesteApp renders the OpenProject Deployment and its Service.
//
// ONE POD, THREE PROCESSES, and the reason is the volume: the web server and the
// background worker both write attachments under cheminAssets, and Longhorn
// volumes are ReadWriteOnce. Two pods would need ReadWriteMany storage the
// suite does not have.
//
//	seeder (init)  migrations and seed data; idempotent, so it runs on every
//	               start and an upgrade migrates the database before the new
//	               web server serves a single request.
//	web            the Puma server, port 8080.
//	worker         background jobs: e-mails, exports, notifications.
//
// STRATEGY Recreate: a rolling update would start the new pod while the old one
// still holds the ReadWriteOnce volume, and it would wait for an attachment that
// never comes.
//
// THE PROBES ARE EXEC, NOT tcpSocket: the NetworkPolicy lets only the proxy in,
// and whether the kubelet's probes count as "the node" depends on the network
// plugin. A probe from inside the container depends on nothing.
func manifesteApp(domaine, annotations, image string) string {
	sonde := `exec:
              command: ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]`
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
  strategy:
    type: Recreate
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
        runAsUser: %[5]s
        runAsGroup: %[5]s
        # THE VOLUME BELONGS TO ROOT ON A FRESH LONGHORN DISK; fsGroup makes it
        # writable by the image's user, otherwise the first attachment upload
        # fails with "Permission denied" (seen on the upstream forum with the
        # official chart).
        fsGroup: %[5]s
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: seeder
          image: %[6]s
          command: %[7]s
          env:
%[13]s          volumeMounts:
            - name: assets
              mountPath: %[8]s
          securityContext:
%[14]s          resources:
            requests:
              memory: 512Mi
              cpu: 100m
            limits:
              memory: 2Gi
      containers:
        - name: web
          image: %[6]s
          command: %[9]s
          env:
%[13]s          ports:
            - name: http
              containerPort: 8080
          # THE FIRST START MIGRATES THE DATABASE in the seeder, but Puma then
          # precompiles nothing and is up within a minute; ten minutes of
          # startup budget covers a slow disk without masking a crash loop.
          startupProbe:
            %[10]s
            periodSeconds: 10
            failureThreshold: 60
          readinessProbe:
            %[10]s
            periodSeconds: 10
          livenessProbe:
            %[10]s
            periodSeconds: 30
            failureThreshold: 4
          volumeMounts:
            - name: assets
              mountPath: %[8]s
          securityContext:
%[14]s          resources:
            requests:
              memory: 1Gi
              cpu: 250m
            limits:
              memory: 3Gi
        - name: worker
          image: %[6]s
          command: %[11]s
          env:
%[13]s          volumeMounts:
            - name: assets
              mountPath: %[8]s
          securityContext:
%[14]s          resources:
            requests:
              memory: 512Mi
              cpu: 100m
            limits:
              memory: 1536Mi
      volumes:
        - name: assets
          persistentVolumeClaim:
            claimName: %[12]s
---
apiVersion: v1
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
      port: 8080
      targetPort: 8080
`, nomApp, nsProjets, annotations, nomServiceAccount, uidOpenProject, image,
		commande("seeder"),
		cheminAssets, commande("web"), sonde, commande("worker"), nomVolume,
		envApp(domaine), securiteConteneur)
}

// securiteConteneur is the container securityContext shared by the three
// OpenProject processes, at the indentation the Deployment expects.
const securiteConteneur = `            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
`

// envApp renders the environment shared by the seeder, the web server and the
// worker.
//
// RENDERED ONCE AND INSERTED THREE TIMES, rather than a YAML anchor: the three
// processes MUST agree (a worker that believes in another host name sends links
// to it), and an anchor would depend on the decoder of whichever frontend
// applies the manifest — the console decodes YAML itself.
func envApp(domaine string) string {
	return fmt.Sprintf(`            - name: OPENPROJECT_HOST__NAME
              value: %[1]s
            - name: OPENPROJECT_HTTPS
              value: "true"
            # HEADER SSO: the login is read from the header the proxy sets.
            # NOT OPTIONAL: a request without the header can only come from
            # somewhere other than the proxy, and is refused.
            - name: OPENPROJECT_AUTH__SOURCE__SSO_HEADER
              value: %[2]s
            - name: OPENPROJECT_AUTH__SOURCE__SSO_OPTIONAL
              value: "false"
            - name: OPENPROJECT_AUTH__SOURCE__SSO_LOGOUT__URL
              value: %[3]q
            # THE SEEDED "admin" ACCOUNT IS LOCKED. Administration goes through
            # the Ceffio administrator, provisioned by Install; an unlocked
            # local "admin" would be reachable by any Keycloak user who
            # happened to be called "admin".
            - name: OPENPROJECT_SEED__ADMIN__USER__LOCKED
              value: "true"
            - name: OPENPROJECT_ATTACHMENTS__STORAGE__PATH
              value: %[4]s/files
`, nomHote(domaine), enTeteUtilisateur, urlDeconnexion(domaine), cheminAssets)
}

// annotationsProxy builds the injector annotations of the proxy pod: two files,
// each holding one value and nothing else (oauth2-proxy reads the bytes as-is).
func annotationsProxy() (string, error) {
	chemin := cheminCoffre(coffreProxy)
	coffre, err := vault.AnnotationsAgentFichiers(8, idModule, []vault.FichierInjecte{
		{Nom: "client-secret", Chemin: chemin, Gabarit: vault.GabaritValeur(chemin, "client-secret"), Perms: "0400"},
		{Nom: "cookie-secret", Chemin: chemin, Gabarit: vault.GabaritValeur(chemin, "cookie_secret"), Perms: "0400"},
	})
	if err != nil {
		return "", fmt.Errorf("openproject: the proxy's vault annotations: %w", err)
	}
	// THE AGENT RUNS AS THE PROXY'S USER: files in 0400 are readable only by
	// their owner, and the agent creates them (longhorn-ui, annotationsProxy).
	return `        vault.hashicorp.com/agent-run-as-user: "` + uidProxy + `"
        vault.hashicorp.com/agent-run-as-group: "` + uidProxy + `"
` + coffre, nil
}

// manifesteProxy renders oauth2-proxy, in front of OpenProject.
//
// WHAT DIFFERS FROM THE LONGHORN PROXY, and why:
//
//	--email-domain=*        EVERY Keycloak user may pass the proxy. The
//	                        authorization is the OpenProject account itself:
//	                        a user without one reaches OpenProject's SSO
//	                        failure page, not the application.
//	--pass-user-headers     sets X-Forwarded-Preferred-Username (and User,
//	                        Email) from the token — OVERWRITING whatever the
//	                        browser sent. That overwrite is half of what makes
//	                        the header trustworthy; the NetworkPolicy is the
//	                        other half.
//	--whitelist-domain      the sign-out redirects to Keycloak's logout page;
//	                        without the domain listed, oauth2-proxy refuses the
//	                        `rd` and lands the user on its own page, with the
//	                        Keycloak session still open.
//	--insecure-oidc-allow-unverified-email
//	                        SET HERE, unlike for Longhorn, and on purpose: the
//	                        longhorn proxy AUTHORIZES on the e-mail, so an
//	                        unverified address must not pass. This one never
//	                        reads the e-mail — the identity is the username —
//	                        and users created from the console are not always
//	                        marked verified. Refusing them would lock out users
//	                        for a check that protects nothing here.
//	--upstream-timeout=120s exports and large uploads outlast the 30 s default.
func manifesteProxy(domaine, annotations, image string) string {
	hote := nomHote(domaine)
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
        runAsUser: %[5]s
        runAsGroup: %[5]s
        fsGroup: %[5]s
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: oauth2-proxy
          image: %[6]s
          args:
            - --provider=keycloak-oidc
            - --oidc-issuer-url=%[7]s
            - --client-id=%[8]s
            - --client-secret-file=%[9]s
            - --cookie-secret-file=%[10]s
            - --upstream=http://%[11]s.%[2]s.svc:8080
            - --email-domain=*
            - --insecure-oidc-allow-unverified-email=true
            - --pass-user-headers=true
            - --redirect-url=https://%[12]s/oauth2/callback
            - --whitelist-domain=keycloak.%[13]s
            - --cookie-secure=true
            - --cookie-domain=%[12]s
            - --cookie-expire=8h
            - --cookie-refresh=1h
            - --reverse-proxy=true
            - --skip-provider-button=true
            - --code-challenge-method=S256
            - --upstream-timeout=120s
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
          livenessProbe:
            httpGet:
              path: /ping
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              memory: 64Mi
              cpu: 20m
            limits:
              memory: 256Mi
---
apiVersion: v1
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
`, nomProxy, nsProjets, annotations, nomServiceAccount, uidProxy, image,
		issuerKeycloak(domaine), clientOIDC, cheminSecretClient, cheminSecretCookie,
		nomApp, hote, domaine)
}

// manifesteRoute renders the Ingress.
//
// THE INGRESS POINTS AT THE PROXY, NEVER AT OPENPROJECT: a route to the
// application would let a browser set the trusted header itself.
//
// ITS OWN CERTIFICATE (projects-tls), REQUESTED THROUGH THE ANNOTATION, as the
// mail Ingress does: the wildcard Secret exists only under DNS-01, while a
// per-host certificate works under both challenges.
//
// THE HTTPS REDIRECTION IS THE ONE THE INGRESS LAYER ALREADY LAYS DOWN in
// ceffio-system (redirectionManifest in internal/ingress), with the exemption
// that matches the installation's ACME challenge. Traefik resolves
// "<namespace>-<name>@kubernetescrd", so the reference works only because the
// Ingress lives in that same namespace.
func manifesteRoute(domaine, issuer string) string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[2]s
  namespace: %[1]s
  labels:
    app.kubernetes.io/part-of: ceffio
  annotations:
    cert-manager.io/cluster-issuer: %[3]s
    traefik.ingress.kubernetes.io/router.middlewares: %[1]s-ceffio-redirect-https@kubernetescrd
spec:
  ingressClassName: traefik
  tls:
    - hosts: [%[4]s]
      secretName: %[5]s
  rules:
    - host: %[4]s
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: %[6]s
                port:
                  number: 80
`, nsProjets, nomIngress, issuer, nomHote(domaine), nomSecretTLS, nomProxy)
}

// manifestePolitique renders the NetworkPolicy that makes the header
// trustworthy: OpenProject accepts connections from its proxy and nobody else.
//
// WHY IT MATTERS EVEN INSIDE THE CLUSTER: OpenProject trusts whoever sends the
// header. Without this policy, any pod of any namespace could call
// openproject.ceffio-system.svc:8080 with "X-Forwarded-Preferred-Username:
// adminceffio" and act as the administrator. The proxy itself stays open: it
// is what Traefik reaches.
func manifestePolitique() string {
	return fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app.kubernetes.io/part-of: ceffio
spec:
  podSelector:
    matchLabels:
      app: %[3]s
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: %[4]s
      ports:
        - protocol: TCP
          port: 8080
`, nomPolitique, nsProjets, nomApp, nomProxy)
}
