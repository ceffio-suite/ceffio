// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/vault"
)

// DNS-01 WEBHOOK SOLVER — ONE COMPONENT FOR EVERY DNS HOST.
//
// WHY A WEBHOOK AND NOT ONLY THE IN-TREE SOLVERS: cert-manager ships eight
// in-tree solvers (Cloudflare, Route53, Azure, Google, DigitalOcean, Akamai,
// ACMEDNS, RFC2136). Everything else — Scaleway, OVH, Gandi, Hetzner,
// Infomaniak — is served by a webhook. Deploying one generic webhook instead of
// a code path per host is what lets a new provider be a CONFIGURATION value,
// with no Ceffio release and no file edited. Without it, "compatible
// everywhere" would mean "compatible with the eight hosts cert-manager chose".
//
// WHY libdns: it is the DNS interface extracted from Caddy, maintained in the
// Let's Encrypt family. One implementation serves every provider that
// implements it — the upstream compatibility check last reported 68 compatible
// providers. A hand-written solver would mean one more thing to maintain and a
// fifth of the coverage.
//
// WHY THE IMAGE IS PINNED: `latest` would make an installation
// non-reproducible, which version.Registry forbids for every component.

const (
	// webhookImage: the libdns solver, published under a name this project
	// owns (see internal/version).
	webhookImage = "ghcr.io/ceffio-suite/acme-dns-webhook"
	// webhookVersion: pinned, never `latest`.
	webhookVersion = "v0.5.0"
	// webhookName: the Deployment / Service / APIService base name.
	webhookName = "ceffio-acme-dns-webhook"
	// webhookPort: the solver's own port. cert-manager reaches it on 443
	// through the APIService, never directly.
	webhookPort = 8443
	// webhookGroup: the groupName the solver registers under.
	//
	// IT MUST BE A DOMAIN THIS PROJECT OWNS, and it must match what the
	// ClusterIssuer declares (acme.WebhookGroupParDefaut). Two webhooks
	// claiming the same group make cert-manager refuse BOTH, and the failure
	// appears as a certificate that never arrives — with nothing naming the
	// collision.
	webhookGroup = acme.WebhookGroupParDefaut
	// roleOpenBaoDNS: the vault role the solver's ServiceAccount assumes.
	//
	// The policy behind it grants read on ONE path and nothing else: a solver
	// for DNS records has no business reading the database passwords of the
	// suite.
	roleOpenBaoDNS = "ceffio-acme-dns"
	// cheminBaoIdentifiantsDNS: the vault path holding the DNS credentials.
	//
	// ONE PATH FOR EVERY PROVIDER, WITH THE PROVIDER INSIDE: the credential
	// shape differs between hosts (a Cloudflare token is one field, OVH needs
	// four), so the entry holds the fields the chosen provider requires rather
	// than a fixed pair. The provider name travels WITH the credential, so a
	// token stored for Cloudflare cannot be silently used against a Scaleway
	// zone because the two settings drifted apart.
	//
	// THE `kv/data/` PREFIX IS PART OF THE PATH: every other component of the
	// suite uses the full mount+path form (kv/data/ceffio/nextcloud/db), and
	// the injector template addresses the KV v2 engine directly. Writing
	// "ceffio/tls/dns-provider" would resolve against whatever mount the agent
	// defaults to, and the file would come out empty with no error naming the
	// path.
	cheminBaoIdentifiantsDNS = "kv/data/ceffio/tls/dns-provider"
)

// deployerWebhookDNS installs the solver and wires its credentials from OpenBao.
//
// WHY IT IS CALLED FOR EVERY PROVIDER, IN-TREE INCLUDED: the module writes the
// webhook form of the ClusterIssuer solver for every provider (see solveur()),
// because that is what keeps a provider a VALUE. Installing the component only
// for out-of-tree hosts would mean a switch to Scaleway breaks on a cluster
// that took the in-tree shortcut.
//
// Skipped when the challenge is HTTP-01: it would be a pod on a port nothing
// calls.
func deployerWebhookDNS(ctx context.Context, reglages acme.Reglages) error {
	if !reglages.DNS01() {
		return nil
	}

	// 1. The TLS certificate of the solver, from the INTERNAL authority.
	//
	// WHY NOT A CERTIFICATE GENERATED AT STARTUP: the APIService validates it,
	// and every internal call of the suite already trusts ceffio-ca-issuer
	// (InjecterConfianceTLS). A second trust chain would be a second thing to
	// rotate and one more handshake failure nobody can place.
	if err := apply(ctx, webhookCertificatManifest()); err != nil {
		return err
	}

	// 2. ServiceAccount + Role + Deployment + Service.
	if err := apply(ctx, webhookManifests(reglages)); err != nil {
		return err
	}

	// 3. The APIService LAST: its caBundle is injected by cert-manager from the
	//    Certificate created in step 1. Creating it first leaves it with an
	//    empty bundle until cert-manager catches up — a window during which
	//    cert-manager's own calls fail, and the challenge hangs for no visible
	//    reason.
	if err := apply(ctx, webhookAPIServiceManifest()); err != nil {
		return err
	}

	fmt.Printf("∙ DNS-01 solver %s (%s) deployed for provider %s\n",
		webhookName, webhookVersion, reglages.Provider)
	fmt.Printf("  credentials read from OpenBao: %s (role %s)\n",
		cheminBaoIdentifiantsDNS, roleOpenBaoDNS)
	return nil
}

// webhookCertificatManifest: the TLS certificate the APIService and the solver
// share, signed by the internal authority.
func webhookCertificatManifest() string {
	return fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  secretName: %[1]s-tls
  duration: 8760h
  renewBefore: 720h
  issuerRef:
    name: %[3]s
    kind: ClusterIssuer
  dnsNames:
    - %[1]s
    - %[1]s.%[2]s
    - %[1]s.%[2]s.svc
    - %[1]s.%[2]s.svc.cluster.local
`, webhookName, nsCertManager, issuerCA)
}

// champsDuProvider returns the vault fields and the shell variable each one
// feeds, FOR THE PROVIDER ACTUALLY CONFIGURED.
//
// WHY PER PROVIDER AND NOT ONE UNION OF EVERY FIELD: vault.AnnotationsAgent
// sets `error-on-missing-key-env: true`, which is the right default — a render
// that silently produces an empty value is worse than a pod that refuses to
// start. But that flag applies to the WHOLE template: rendering the eleven
// fields of every supported host would make a Cloudflare entry fail, because
// the OVH fields it legitimately does not have would be reported missing. The
// pod would then never start, and the message would name a field for a provider
// the operator never chose.
//
// The variable names are those the libdns provider libraries read from the
// environment (CF_API_TOKEN, OVH_*, AWS_*). They are written here once, next to
// the provider they belong to, so a new host is one entry in this function and
// nothing else.
func champsDuProvider(p acme.Provider) [][2]string {
	// The provider name travels with the credential, always first: it is what
	// lets the solver check that the token it holds was stored for the host it
	// is about to write to. A Cloudflare token used against a Scaleway zone
	// would fail with an authorization error that never mentions the mismatch.
	commun := [][2]string{{"CEFFIO_DNS_PROVIDER_NAME", "{{ .Data.data.provider }}"}}

	switch p {
	case acme.ProviderCloudflare:
		return append(commun, [2]string{"CF_API_TOKEN", vault.ChampCoffre("api_token")})
	case acme.ProviderRoute53:
		return append(commun,
			[2]string{"AWS_ACCESS_KEY_ID", vault.ChampCoffre("access_key_id")},
			[2]string{"AWS_SECRET_ACCESS_KEY", vault.ChampCoffre("secret_access_key")},
			[2]string{"AWS_REGION", vault.ChampCoffre("region")})
	case acme.ProviderRFC2136:
		// RFC 2136 is the in-tree solver that speaks dynamic DNS updates: no
		// API token at all, a TSIG key and a target server. It is the path for
		// an operator running BIND, Knot, PowerDNS or Technitium.
		return append(commun,
			[2]string{"RFC2136_NAMESERVER", vault.ChampCoffre("nameserver")},
			[2]string{"RFC2136_TSIG_KEY", vault.ChampCoffre("tsig_key")},
			[2]string{"RFC2136_TSIG_SECRET", vault.ChampCoffre("tsig_secret")},
			[2]string{"RFC2136_TSIG_ALGORITHM", vault.ChampCoffre("tsig_algorithm")})
	case acme.ProviderACMEDNS:
		// acme-dns: a dedicated server answering only for _acme-challenge,
		// delegated by CNAME. The credential can write ONE record name.
		return append(commun,
			[2]string{"ACMEDNS_API_URL", vault.ChampCoffre("api_url")},
			[2]string{"ACMEDNS_USERNAME", vault.ChampCoffre("username")},
			[2]string{"ACMEDNS_PASSWORD", vault.ChampCoffre("password")},
			[2]string{"ACMEDNS_SUBDOMAIN", vault.ChampCoffre("subdomain")})
	case "ovh":
		return append(commun,
			[2]string{"OVH_ENDPOINT", vault.ChampCoffre("endpoint")},
			[2]string{"OVH_APPLICATION_KEY", vault.ChampCoffre("application_key")},
			[2]string{"OVH_APPLICATION_SECRET", vault.ChampCoffre("application_secret")},
			[2]string{"OVH_CONSUMER_KEY", vault.ChampCoffre("consumer_key")})
	case "scaleway":
		return append(commun,
			[2]string{"SCALEWAY_API_TOKEN", vault.ChampCoffre("api_token")},
			[2]string{"SCALEWAY_PROJECT_ID", vault.ChampCoffre("project_id")})
	case "hetzner":
		return append(commun, [2]string{"HETZNER_API_TOKEN", vault.ChampCoffre("api_token")})
	case "gandi":
		return append(commun, [2]string{"GANDI_API_TOKEN", vault.ChampCoffre("api_token")})
	case "linode":
		return append(commun, [2]string{"LINODE_API_TOKEN", vault.ChampCoffre("api_token")})
	case "desec":
		return append(commun, [2]string{"DESEC_API_TOKEN", vault.ChampCoffre("api_token")})
	default:
		// An unknown-but-valid provider: the libdns implementation exists, and
		// what it expects is its own business. The generic `api_token` field is
		// rendered, plus the provider name — enough for the majority, and the
		// operator can always add the specific variables to the vault entry and
		// read them here. Refusing outright would mean a Ceffio release per DNS
		// host, which is the coupling this design exists to avoid.
		return append(commun,
			[2]string{"API_TOKEN", vault.ChampCoffre("api_token")},
			[2]string{"LIBDNS_API_TOKEN", vault.ChampCoffre("api_token")})
	}
}

// webhookManifests: ServiceAccount, Role, RoleBinding, Deployment, Service.
//
// THE POD CARRIES THE VAULT ANNOTATIONS, NOT THE SECRET OBJECT. OpenBao's
// injector works per POD: it adds an in-memory volume and a pre-populating
// agent. A Secret annotated without a pod to inject into stays empty, and the
// whole chain then looks configured while the solver reads nothing. That is why
// vault.AnnotationsAgent is used here — the same helper the mail and console
// deployments already use, so there is one place that knows the annotation
// syntax.
func webhookManifests(reglages acme.Reglages) string {
	// The rendered file holds the provider credentials as shell assignments,
	// because the libdns webhook reads its provider configuration from the
	// environment. Only the fields of the CONFIGURED provider are rendered:
	// see champsDuProvider for why a union of every host's fields would make
	// the pod refuse to start.
	gabarit := vault.GabaritMulti([]vault.Source{{
		Chemin: cheminBaoIdentifiantsDNS,
		Paires: champsDuProvider(reglages.Provider),
	}})

	annotations := vault.AnnotationsAgent(8, roleOpenBaoDNS, cheminBaoIdentifiantsDNS, gabarit)

	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %[1]s
  namespace: %[2]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %[1]s
  namespace: %[2]s
rules:
  # The solver needs NOTHING from the Kubernetes API. It receives challenge
  # requests over HTTP and answers them; the credentials arrive as a file
  # written by the injector. The Role therefore grants only what the aggregated
  # API machinery requires to route APIService calls to this pod — NOT a
  # right on secrets, which an earlier draft asked for and which the solver
  # never reads: the injector does.
  - apiGroups: [""]
    resources: ["services", "endpoints"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %[1]s
  namespace: %[2]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: %[1]s
subjects:
  - kind: ServiceAccount
    name: %[1]s
    namespace: %[2]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
  labels:
    app: %[1]s
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
%[6]s
    spec:
      serviceAccountName: %[1]s
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: webhook
          image: %[3]s:%[4]s
          # The injector pre-populates its file BEFORE the container starts, so
          # the process only has to source it. Without this line the solver
          # runs with no credentials at all, and every challenge fails with an
          # authentication error that never names the missing variable.
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -a
              . /secrets/env
              set +a
              exec /app/webhook --tls-cert-file=/tls/tls.crt --tls-private-key-file=/tls/tls.key --secure-port=%[5]d
          ports:
            - name: https
              containerPort: %[5]d
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              memory: 128Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: %[1]s-tls
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app: %[1]s
  ports:
    - name: https
      port: 443
      targetPort: %[5]d
`, webhookName, nsCertManager, webhookImage, webhookVersion, webhookPort, annotations)
}

// webhookAPIServiceManifest registers the solver with the aggregator, so
// cert-manager calls it as if it were a built-in API.
//
// WITHOUT THIS OBJECT, cert-manager never sees the solver: the ClusterIssuer's
// `webhook` block resolves to nothing, the challenge stays pending, and no
// error names the cause.
func webhookAPIServiceManifest() string {
	return fmt.Sprintf(`apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.%[1]s
  annotations:
    # The caBundle is injected from the Certificate above. A bundle copied once
    # would silently expire, and the APIService would start refusing calls
    # weeks later — a failure that looks like a cert-manager bug.
    cert-manager.io/inject-ca-from: %[2]s/%[3]s
spec:
  group: %[1]s
  groupPriorityMinimum: 1000
  versionPriority: 15
  version: v1alpha1
  service:
    name: %[3]s
    namespace: %[2]s
    port: 443
  insecureSkipTLSVerify: false
`, webhookGroup, nsCertManager, webhookName)
}
