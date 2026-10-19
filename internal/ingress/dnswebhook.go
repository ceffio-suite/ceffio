// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/secrets"
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
	// webhookVersion: pinned, never `latest`, and the SAME value in
	// internal/version (the coherence test would catch a drift).
	//
	// v1.1.0 is the upstream version this build was made from — checked with
	// `webhook --version` rather than assumed from the repository's README.
	webhookVersion = "v1.1.0"
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
	// the injector template addresses the KV v2 engine directly.
	cheminBaoIdentifiantsDNS = "kv/data/ceffio/tls/dns-provider"
	// cheminCoffreMount / cheminCoffreSousChemin: the same path, split the way
	// secrets.LireEntreeCoffre expects it (mount, sub-path). Written once here
	// so the two forms cannot drift.
	cheminCoffreMount      = "ceffio"
	cheminCoffreSousChemin = "tls/dns-provider"
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
	// NOTHING TO DEPLOY WHEN cert-manager ALREADY KNOWS THE PROVIDER.
	//
	// Cloudflare, Route 53, RFC 2136 and acme-dns have in-tree solvers: the
	// ClusterIssuer references them directly and a Secret with the credential
	// is the only prerequisite. Installing a component there would add an
	// image, a pod and a failure mode for a capability already present in the
	// cert-manager binary — and it is what forces a project to publish an
	// image per release.
	//
	// Skipped under HTTP-01 too: there is nothing for a solver to answer.
	if !reglages.DNS01() {
		return nil
	}

	// THE CREDENTIAL SECRET IS ALWAYS NEEDED, in-tree or not: cert-manager's
	// own solvers name it too. Applied first, so the issuer below never
	// references a Secret that does not exist yet.
	//
	// THE OBJECT AND ITS CONTENT ARE TWO STEPS, and that separation is not
	// cosmetic: the manifest declares the Secret and the keys it must carry,
	// while ecrireSecretDNS reads the vault and fills them. Merging the two
	// would mean putting a credential in a manifest.
	if err := apply(ctx, secretDNSManifests(reglages)); err != nil {
		return err
	}
	if err := ecrireSecretDNS(ctx, reglages); err != nil {
		return err
	}

	// THE COMPONENT, ONLY FOR A PROVIDER cert-manager DOES NOT KNOW.
	if !reglages.EmpreinteWebhook() {
		fmt.Printf("∙ DNS-01 via the cert-manager solver %q — no component to deploy\n",
			reglages.Provider)
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

// secretDNSManifests crée l'objet Secret des identifiants DNS.
//
// WHY THE SECRET IS WRITTEN BY CEFFIO AND NOT BY THE INJECTOR, for the in-tree
// providers: OpenBao's injector is a MUTATING WEBHOOK ON PODS — verified on the
// cluster, its admission rule is `CREATE, UPDATE` on `pods` and nothing else. A
// Secret carrying the injection annotations is therefore left EMPTY: no pod
// exists to be mutated, since cert-manager's own solvers need no component.
//
// The file mode used by every other component cannot apply here either: there
// is no container to read /secrets/env. So the value is read from the vault by
// Ceffio itself and written as a Kubernetes Secret — which is the only shape
// cert-manager's solvers accept (`apiTokenSecretRef`, `tsigSecretSecretRef`…).
//
// THE VAULT REMAINS THE SINGLE SOURCE: nothing is typed in by hand, a rotation
// happens in the vault, and this function is called on every install so the
// Secret follows.
func secretDNSManifests(reglages acme.Reglages) string {
	paires := pairesSecret(reglages.Provider)

	return fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: ceffio-acme-dns
  namespace: %[1]s
---
apiVersion: v1
kind: Secret
metadata:
  name: %[2]s
  namespace: %[1]s
  labels:
    app.kubernetes.io/part-of: ceffio
    app.kubernetes.io/managed-by: ceffio
type: Opaque
stringData:
%[3]s
`, nsCertManager, secretACME, lignesStringData(paires))
}

// lignesStringData renders the `champ: ”` lines of the Secret body.
//
// THE VALUES ARE EMPTY HERE, ON PURPOSE: the real content is written by
// ecrireSecretDNS below, which reads the vault. Declaring the keys in the
// manifest keeps the object readable — an operator sees which fields the
// provider needs — while leaving no credential in a manifest that could be
// committed.
func lignesStringData(paires [][2]string) string {
	var b strings.Builder
	for _, p := range paires {
		fmt.Fprintf(&b, "  %s: \"\"\n", p[0])
	}
	return strings.TrimRight(b.String(), "\n")
}

// ecrireSecretDNS lit le coffre et pose le Secret que le solver lira.
//
// THE TRANSLATION BETWEEN THE TWO NAMES HAPPENS HERE, and it is the trap of
// this whole path: the KEY IN THE SECRET is fixed by cert-manager (`api-token`,
// with a hyphen), while the FIELD IN THE VAULT is the one the operator stored
// (`api_token`, with an underscore — the libdns name the console's TLS page
// writes). Filling one from the other is this function's only job.
func ecrireSecretDNS(ctx context.Context, reglages acme.Reglages) error {
	paires := pairesSecret(reglages.Provider)
	if len(paires) == 0 {
		return nil
	}

	entree, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
		cheminCoffreMount, cheminCoffreSousChemin)
	if err != nil {
		return fmt.Errorf("reading the DNS credential from the vault (%s/%s): %w — "+
			"store it from the console's TLS page before enabling dns01",
			cheminCoffreMount, cheminCoffreSousChemin, err)
	}

	donnees := map[string][]byte{}
	var manquants []string
	for _, p := range paires {
		v := strings.TrimSpace(entree[p[1]])
		if v == "" {
			manquants = append(manquants, p[1])
			continue
		}
		donnees[p[0]] = []byte(v)
	}
	if len(manquants) > 0 {
		// SAY WHICH FIELD IS MISSING rather than writing a Secret with holes:
		// the solver would then fail every challenge with a provider-side
		// authentication error, and nothing would name the absent field.
		return fmt.Errorf("the vault entry %s/%s lacks %v — the %s solver needs "+
			"them and cannot authenticate without (store them from the console's TLS page)",
			cheminCoffreMount, cheminCoffreSousChemin, manquants, reglages.Provider)
	}

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	if err := cli.PoserSecret(ctx, nsCertManager, secretACME, donnees); err != nil {
		return err
	}
	fmt.Printf("∙ DNS-01 credential written to secret %s/%s for %s\n",
		nsCertManager, secretACME, reglages.Provider)
	return nil
}

// pairesSecret associe, pour chaque provider, la clé attendue DANS LE SECRET par
// cert-manager et le champ correspondant DANS LE COFFRE.
//
// WHY TWO NAMES AND NOT ONE: they belong to two different worlds and neither can
// be renamed.
//
//	cert-manager fixes the Secret key: `api-token` for Cloudflare (a hyphen),
//	because its own solver reads exactly that. The ClusterIssuer references it,
//	and a mismatch means the issuer resolves to no credential.
//
//	the vault field is the one the operator STORED. For Cloudflare that is
//	`api_token`, because libdns — the interface the webhook solver marshals to —
//	names its fields with underscores, and the console's TLS page writes what
//	the operator typed.
//
// Writing one name for both produces a render that asks the vault for a field
// nobody stored: it fails with a message naming a field the operator never
// wrote, on a screen that showed a successful save. This table is the only
// place the translation happens.
func pairesSecret(p acme.Provider) [][2]string {
	switch p {
	case acme.ProviderCloudflare:
		return [][2]string{{"api-token", "api_token"}}
	case acme.ProviderRoute53:
		return [][2]string{
			{"access-key-id", "access_key_id"},
			{"secret-access-key", "secret_access_key"},
			{"region", "region"},
		}
	case acme.ProviderRFC2136:
		return [][2]string{
			{"tsig-secret", "tsig_secret"},
			{"tsig-key-name", "tsig_key"},
			{"tsig-algorithm", "tsig_algorithm"},
			{"nameserver", "nameserver"},
		}
	case acme.ProviderACMEDNS:
		return [][2]string{
			{"acmedns-account", "username"},
			{"acmedns-host", "api_url"},
		}
	default:
		// Out-of-tree: the webhook marshals the Secret straight to libdns, so
		// the key in the Secret must BE the vault field name, unchanged.
		var out [][2]string
		for _, c := range clesProvider(p) {
			out = append(out, [2]string{c, c})
		}
		return out
	}
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

// clesProvider returns the CREDENTIAL FIELD NAMES the configured provider's
// libdns implementation reads, taken from the vault entry.
//
// WHY FIELD NAMES AND NOT ENVIRONMENT VARIABLES — this correction matters, and
// getting it wrong produces a failure that names nothing: the solver loads
// EVERY key of the referenced Secret into a map and marshals that map to its
// provider library. The library then looks for ITS OWN JSON field names
// (`api_token`, `endpoint`, `application_key`…). Rendering `CF_API_TOKEN`
// would therefore hand the provider a map it cannot read, and every challenge
// would fail on an empty credential — with no message mentioning the field.
//
// WHY PER PROVIDER AND NOT ONE UNION OF EVERY FIELD: the injection template
// sets `error-on-missing-key-<name>`, which is the right default — a render
// that silently produces an empty value is worse than a pod that refuses to
// start. But that flag applies to the WHOLE template, so rendering OVH's four
// fields for a Cloudflare entry would fail the render on keys that provider
// legitimately does not have. The pod would never start, and the message would
// name a provider the operator never chose.
func clesProvider(p acme.Provider) []string {
	// `provider` travels WITH the credential, always: it is what lets Ceffio
	// and the operator tell which host an entry was stored for. A Cloudflare
	// token used against a Scaleway zone fails with an authorization error
	// that never mentions the mismatch.
	commun := []string{"provider"}

	switch p {
	case acme.ProviderCloudflare:
		return append(commun, "api_token")
	case acme.ProviderRoute53:
		return append(commun, "access_key_id", "secret_access_key", "region")
	case acme.ProviderRFC2136:
		// The dynamic-update path: no token at all, a TSIG key and a server.
		// In-tree in cert-manager, and the reason an operator running BIND,
		// Knot, PowerDNS or Technitium is not left out. Present in the built
		// image (`--list-providers` lists rfc2136).
		return append(commun, "nameserver", "tsig_key", "tsig_secret", "tsig_algorithm")
	case acme.ProviderACMEDNS:
		// acme-dns answers only for _acme-challenge, delegated by CNAME. The
		// credential can write ONE record name — the path for someone with no
		// rights on the main zone.
		return append(commun, "api_url", "username", "password", "subdomain")
	case "ovh":
		return append(commun, "endpoint", "application_key", "application_secret", "consumer_key")
	case "scaleway":
		return append(commun, "api_token", "project_id")
	case "hetzner":
		return append(commun, "api_token")
	case "gandi":
		return append(commun, "api_token")
	case "linode":
		return append(commun, "api_token")
	case "desec":
		return append(commun, "api_token")
	case "bunny":
		return append(commun, "api_key")
	case "ionos":
		return append(commun, "api_key")
	default:
		// An unknown-but-valid provider: its libdns implementation exists, and
		// what it expects is its own business. `api_token` covers the majority
		// of them. Refusing outright would mean one Ceffio release per DNS
		// host — the coupling this whole design exists to avoid — and an
		// operator whose provider wants another field name can store that name
		// in the vault entry and add it here in one line.
		return append(commun, "api_token")
	}
}

// webhookManifests: ServiceAccount, Role, RoleBinding, Secret, Deployment, Service.
//
// THE SOLVER READS A KUBERNETES SECRET, NOT A SHELL FILE — and that detail cost
// a rewrite to discover. Its `config.secretRef` names a Secret, and it loads
// EVERY key of that Secret into a map that it marshals to the provider library.
// A `/secrets/env` full of shell exports would give it nothing usable: the keys
// would be `CF_API_TOKEN` with quotes around a value, and the provider would
// receive no credential at all.
//
// SO THE SECRET IS THE INJECTOR'S OUTPUT, not a hand-written object: the
// annotations below make OpenBao render the Secret, and the solver reads it
// through the Kubernetes API. One source, one rotation, no copy in a file.
//
// THE ROLE THEREFORE NEEDS `secrets`: the earlier draft granted only
// services/endpoints and was wrong — the solver genuinely reads this Secret.
// The right is scoped to ONE namespace (cert-manager) and, in the role defined
// by the vault, to ONE path. That is a narrowing, not a widening.
func webhookManifests(reglages acme.Reglages) string {
	// The solver reads the Secret's keys directly, so the template writes
	// `key: value` pairs — NOT `export key='value'`. See champsDuProvider for
	// why only the configured provider's fields are rendered.
	gabarit := vault.GabaritSecret(cheminBaoIdentifiantsDNS, clesProvider(reglages.Provider))

	annotations := vault.AnnotationsAgentNamed(8, roleOpenBaoDNS, secretACME, cheminBaoIdentifiantsDNS, gabarit)

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
  # The solver reads its provider credential from the Secret the injector
  # rendered, and reports events. Scoped to this namespace only.
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  # What the aggregated API machinery needs to route APIService calls here.
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
          # GROUP_NAME IS MANDATORY, and getting it wrong is not a soft
          # failure: measured on the built image,
          #
          #   F1018 23:04:10 main.go:44] GROUP_NAME environment variable must be
          #   specified
          #
          # The process exits immediately, so a Deployment without it would sit
          # in CrashLoopBackOff and the certificates would simply never be
          # issued. It must equal the groupName the ClusterIssuer declares and
          # the metadata.name of the APIService below — the three are one
          # identity written in three places, which is why the constant is
          # shared rather than repeated.
          env:
            - name: GROUP_NAME
              value: %[7]s
            - name: LOG_LEVEL
              value: "2"
          # The binary is at /usr/local/bin/webhook, NOT the path a from-source
          # build would suggest.
          args:
            - --tls-cert-file=/tls/tls.crt
            - --tls-private-key-file=/tls/tls.key
            - --secure-port=%[5]d
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
`, webhookName, nsCertManager, webhookImage, webhookVersion, webhookPort, annotations, webhookGroup)
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
