// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package mail orchestrates the deployment of the mail layer (Phase 13):
// the Stalwart server, which receives, stores and serves mail over IMAP.
//
// WHY STALWART: Nextcloud provides the interface (Mail app), but NOT the mail
// server. Stalwart fills that role: inbound SMTP, IMAP, Sieve filters,
// antispam — in a single Rust binary. The user reads their messages in
// Nextcloud; Stalwart is the plumbing behind it.
//
// RECEPTION HAPPENS ON PORT 25, ALWAYS. An earlier revision of the mail plan
// assumed outbound 25 was blocked at the hosting provider and that a send relay
// was therefore mandatory; the plan's final version (§4.8) replaced it: the
// public Service publishes 25 for inbound mail, and DELIVERY is a choice —
// direct (Stalwart delivers itself, so reverse DNS, SPF, DKIM and DMARC must be
// right) or through a relay (`envoi = relais`, which carries the reputation).
// Both are supported here, and neither is refused: the checks report what the
// outside world still lacks.
//
// TLS IS THE HOST'S OWN CERTIFICATE. Stalwart serves a built-in self-signed
// one ("CN=rcgen self signed cert", SAN DNS:localhost) until it is told about
// another, and every mail client refuses that. cert-manager issues the right
// certificate into the `mail-tls` Secret (the mail Ingress asks for it); tls.go
// mounts the Secret and declares it to the server, without a restart.
//
// Stalwart administration stays SEPARATE (user instruction): the Ceffio console
// only links to it, and the admin password rotation acts on its REST API (see
// internal/console/admin.go).
package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Actual version observed on Docker Hub (not invented).
const (
	ns = "ceffio-mail"
	// Default domain for the mailboxes. Overridden by the caller.
	domaineDefaut = "example.com"
)

// LES IMAGES VIENNENT DU REGISTRE, pas d'une copie locale : une copie est ce
// qui a laissé le registre avancer pendant que la grappe restait en arrière.
var stalwartImage = version.Image("stalwart")

// Deploy installs the mail layer (Phase 13), idempotently:
//  1. secrets (admin password, storage key)
//  2. the mailbox volume, at the setting's size (never smaller than in place)
//  3. Stalwart + ConfigMap + Service
//  4. waiting for the healthcheck
//  5. outbound routing (direct or through the relay), READ BACK from the server
//
// THE SIGNATURE CHANGED IN PR 1 OF docs/plan-mail.md, and that is the point of
// the change: the relay used to arrive as four arguments, so the only way to
// change it was to reinstall the platform. The configuration now comes from the
// module settings (`mail.server`, `mail.relay`), which the console edits, so
// `install`, `upgrade`, `ceffio mail` and the settings page all apply THE SAME
// stored values instead of each having its own copy.
//
// The domain comes from the deployment: the same code serves a test domain and
// the real domain.
func Deploy(ctx context.Context, domain string) error {
	fmt.Println("\nDeploying the mail layer (Phase 13)...")

	domaine := domaineMail(domain)
	// THE MAIL DOMAIN AND THE MAIL HOST ARE TWO DIFFERENT NAMES, and conflating
	// them is the mistake that makes every record wrong:
	//   - the mail DOMAIN is the platform domain: addresses are user@<domain>;
	//   - the mail HOST is mail.<domain>: MX, PTR, SPF, autoconfig and the
	//     certificate all name THAT one.
	// `domain` is the platform domain; `domaine` is the host. Both are needed
	// here because the Ingress serves four hosts under the platform domain.
	plateforme := domain
	if plateforme == "" {
		plateforme = domaineDefaut
	}
	fmt.Printf("∙ mail domain: %s (host %s)\n", plateforme, domaine)

	cfg, err := LireReglages(ctx)
	if err != nil {
		return err
	}
	// VALIDATED BEFORE ANYTHING IS TOUCHED: a relay without a password, or a
	// quota above the volume, must be refused while the cluster is still intact.
	if err := cfg.Valider(); err != nil {
		return fmt.Errorf("mail settings: %w", err)
	}

	if err := ensureSecrets(ctx); err != nil {
		return err
	}

	taille, err := assurerVolumeConservant(ctx, cfg.VolumeGio)
	if err != nil {
		return err
	}
	// The quota rule is re-checked against the size IN PLACE, not against the
	// stored number: a claim enlarged by hand may allow a quota the settings
	// alone could not check.
	if cfg.QuotaDefautGio > taille {
		return fmt.Errorf("mail settings: the default quota (%d GiB) exceeds the volume in place (%d GiB)",
			cfg.QuotaDefautGio, taille)
	}
	fmt.Printf("∙ mailbox volume: %dGi\n", taille)

	if err := applyWorkload(ctx, domaine, plateforme); err != nil {
		return err
	}
	if err := applyService(ctx, cfg); err != nil {
		return err
	}
	if err := waitReady(ctx); err != nil {
		return err
	}

	// THE CERTIFICATE COMES AFTER THE SERVER ANSWERS, because declaring it is a
	// JMAP call: there is no server to declare it to before this point. It is
	// not a refusal when the Secret does not exist yet (§4.8, external
	// prerequisite) — the message says so and the `tls` check reports it.
	if err := AssurerTLS(ctx, plateforme); err != nil {
		return err
	}

	// THE ROUTING COMES LAST, on a server that answers: a route written into a
	// server that is not ready would be a write whose effect is unknown.
	if err := AppliquerEnvoi(ctx, cfg.Envoi); err != nil {
		return fmt.Errorf("outbound routing: %w", err)
	}

	fmt.Println("✓ Mail layer deployed (Stalwart)")
	return nil
}

// AppliquerServeur applies the settings that do not require redeploying the
// server: the mailbox volume's size and the published ports.
//
// WHY THIS EXISTS SEPARATELY FROM `Deploy`: saving a settings page must not
// replay a Deployment. Stalwart runs with `strategy: Recreate` (a single writer
// on RocksDB), so re-applying the workload means a mail outage — for a value
// that concerns a Service port list. What can be changed in place is changed in
// place, and read back.
//
// CALLED BY BOTH SETTINGS GROUPS, as the plan requires (§4.2 rule 6): changing
// the relay and changing the exposure must both end with the server
// configuration actually re-applied, not merely stored.
func AppliquerServeur(ctx context.Context, cfg Reglages) error {
	if err := cfg.Valider(); err != nil {
		return err
	}
	taille, err := assurerVolume(ctx, cfg.VolumeGio)
	if err != nil {
		return err
	}
	fmt.Printf("  ∙ mailbox volume: %dGi\n", taille)
	if err := applyService(ctx, cfg); err != nil {
		return err
	}
	return AppliquerEnvoi(ctx, cfg.Envoi)
}

// domaineMail decides the domain of the mailboxes.
//
// We use a subdomain of the platform rather than the root domain: touching the
// root domain would mean moving the MX records of the existing mail, hence
// cutting off the current mail. A subdomain allows testing without breaking
// anything.
func domaineMail(domain string) string {
	if d := os.Getenv("CEFFIO_MAIL_DOMAIN"); d != "" {
		return d
	}
	if domain == "" {
		return domaineDefaut
	}
	// mail.<domain>: isolated from the root domain, and already in the wildcard
	// certificate (no extra certificate to request).
	return "mail." + domain
}

// DomaineMessagerie exposes the host chosen for the mail interface, so that the
// installer can refer to it without duplicating the choice rule.
//
// WARNING: this is a HOST NAME ("mail.<domain>"), not the domain of the mail
// addresses — the two are distinct, and conflating them places the MX records
// in the wrong place.
func DomaineMessagerie(domain string) string { return domaineMail(domain) }

// ensureSecrets guarantees Stalwart's admin secret.
//
// THREE SOURCES, IN THIS ORDER: the VAULT, then the Kubernetes Secret, then
// generation. This order is what allows switching without interruption — a
// value that is already live is REUSED, never regenerated. Regenerating it
// would make Stalwart's data unreadable, since "storage" is the encryption key
// of its internal store.
//
// THE VAULT COMES FIRST because it is the source of truth when it is there, and
// because that is what makes rotation possible: rotating a secret in the vault,
// then redeploying, is enough to propagate it — without touching the cluster.
// The Kubernetes fallback keeps an installation without OpenBao perfectly
// functional, which is the rule of the secrets module.
//
// GENERATION ONLY TRIGGERS WHEN BOTH ARE SILENT, and it says so: a secret
// regenerated blindly is the most expensive outage, because it only shows up
// when the service no longer understands its own data.
func ensureSecrets(ctx context.Context) error {
	coffre := secrets.DepuisEnvironnement()

	// THE VAULT IS THE SINGLE SOURCE — there is NO copy in Kubernetes anymore.
	//
	// A value living in two places ends up diverging, and divergence is
	// discovered at the worst moment: when a service restarts on the wrong
	// version. The pod reads the vault through its agent; so there is nothing to
	// copy, and the Kubernetes Secret fallback has no reason to exist anymore.
	donnees := map[string]string{"username": "admin"}
	existant, err := secrets.LireEntreeCoffre(ctx, coffre, "stalwart", "admin")
	switch {
	case err == nil:
		for k, v := range existant {
			donnees[k] = v
		}
	case secrets.EntreeAbsente(err):
		// First install: the generation below takes care of it.
	default:
		// A configured but unreachable vault is NOT a reason to fabricate fresh
		// values: that would produce a new password while the service runs with
		// the old one.
		return fmt.Errorf("vault unreadable for stalwart/admin: %w", err)
	}
	// GENERATION ONLY TRIGGERS WHEN THE VAULT IS SILENT, and it says so: a secret
	// regenerated blindly is the most expensive outage, because it only shows up
	// when the service no longer understands its own data — Stalwart's storage
	// key is the exact example.
	for _, a := range []struct {
		cle      string
		longueur int
	}{
		{"password", 24},
		{"storage", 32},
	} {
		if donnees[a.cle] != "" {
			continue
		}
		g, err := genSecret(a.longueur)
		if err != nil {
			return err
		}
		donnees[a.cle] = g
		fmt.Printf("∙ Stalwart %s generated (absent from the vault)\n", a.cle)
	}
	if err := secrets.EcrireDansCoffre(ctx, coffre, "stalwart", "admin", donnees); err != nil {
		return err
	}
	// The Kubernetes Secret is no longer created. If one still lingers from an
	// earlier deployment, it is a dead copy: say so, rather than letting it pass
	// for the source.
	if secretExiste(ctx, "stalwart-admin") {
		fmt.Println("  ! Kubernetes Secret \"stalwart-admin\" still present — dead copy, to be removed")
	}
	return nil
}

func applyWorkload(ctx context.Context, domaine, plateforme string) error {
	fmt.Println("∙ Stalwart " + stalwartImage)

	// THE VOLUME IS NOT PART OF THIS MANIFEST, and that is deliberate:
	// `assurerVolume` (volume.go) creates it at the configured size and
	// enlarges it when asked, while refusing to shrink it. A claim rendered
	// here would race with that decision — and would carry the class name
	// twice, once from the installation and once from the cluster's truth.
	annotations := vault.AnnotationsAgent(8, "stalwart", "kv/data/ceffio/stalwart/admin",
		vault.GabaritExports("kv/data/ceffio/stalwart/admin",
			[2]string{"STALWART_ADMIN_PASSWORD", vault.ChampCoffre("password")},
			// Stalwart expects "user:password" in a SINGLE value.
			[2]string{"STALWART_RECOVERY_ADMIN", "admin:" + vault.ChampCoffre("password")},
			[2]string{"STALWART_ENCRYPTION_KEY", vault.ChampCoffre("storage")},
		))

	manifest := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: stalwart-config
  namespace: %[1]s
data:
  # REAL FORMAT OF STALWART v0.16: a minimal JSON that says ONLY where the
  # database lives. Everything else (domains, accounts, TLS, SMTP rules) is
  # stored IN this database and is administered through the web interface or
  # the CLI — not through this file. A detailed TOML here would fail at startup:
  # "Failed to parse data store settings: expected value at line 1 column 2".
  config.json: |
    {"@type":"RocksDb","path":"/var/lib/stalwart"}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: stalwart
  namespace: %[1]s
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stalwart
  namespace: %[1]s
  labels: {app: stalwart}
spec:
  replicas: 1
  strategy: {type: Recreate}   # a single writer on RocksDB
  selector: {matchLabels: {app: stalwart}}
  template:
    metadata:
      labels: {app: stalwart}
      # SECRETS ARE LAID DOWN BY THE OPENBAO INJECTOR, from this block.
      # It adds the init-container that renders them itself, with the right
      # user/group pair and an IN-MEMORY volume. My hand-written init-container
      # did this in forty lines, permissions included — and that is precisely
      # where I went wrong.
      #
      # NO FALLBACK: the vault is the single source, and there is no Kubernetes
      # Secret left for this component. A fallback would mask a vault failure
      # instead of showing it.
      annotations:
%[4]s
    spec:
      # THIS ServiceAccount IS THE ONE THE VAULT ROLE DESIGNATES, and it is the
      # one the agent presents to authenticate.
      serviceAccountName: stalwart
      # fsGroup: THE OFFICIAL IMAGE RUNS AS UID 2000 (its Dockerfile declares
      # useradd -u 2000 then USER stalwart), while a freshly provisioned
      # Longhorn volume belongs to root:root. Without this line the container
      # starts and dies immediately on:
      #
      #   Failed to open database: IO error: While open a file for appending:
      #   /var/lib/stalwart/LOG: Permission denied
      #
      # fsGroup makes the kubelet chown the volume to this group before the
      # container starts. It only applies when the driver declares
      # ReadWriteOnceWithFSType — which Longhorn does, on an RWO ext4 volume
      # exactly like this one. The same setting is already used for vault.
      securityContext:
        fsGroup: 2000
      containers:
      - name: stalwart
        image: %[3]s
        # THE MAIN CONTAINER SOURCES THE RENDERED FILE, THEN STARTS THE SERVICE.
        # The file is ALWAYS there: the agent stops with an error if a template
        # fails (exit_on_retry_failure + error_on_missing_key), so a missing file
        # means a pod that does not start — visible — and not a service running
        # with empty values.
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -a
          . /secrets/env
          set +a
          exec /usr/local/bin/stalwart --config /etc/stalwart/config.json
        volumeMounts:
        # Paths from the official image: /etc/stalwart (config) and
        # /var/lib/stalwart (data). Mounting elsewhere left the data INSIDE the
        # container — lost on the slightest pod restart.
        # The injector adds the secrets mount at /secrets itself.
        - {name: data, mountPath: /var/lib/stalwart}
        - {name: config, mountPath: /etc/stalwart}
        # THE CERTIFICATE'S TWO FILES, mounted where tls.go says the
        # x:Certificate object reads them. readOnly, because the server only
        # ever reads them.
        - {name: mail-tls, mountPath: /etc/stalwart/tls, readOnly: true}
        ports:
%[6]s        # Probe on /healthz/live: this is the endpoint that Stalwart's official
        # Dockerfile declares itself (STALWART_HEALTHCHECK_URL). It answers
        # without authentication, unlike /api/account (401).
        readinessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 15
          periodSeconds: 10
        livenessProbe:
          httpGet: {path: /healthz/live, port: 8080}
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: data
        persistentVolumeClaim: {claimName: stalwart-data}
      - name: config
        configMap: {name: stalwart-config}
      # OPTIONAL, AND THE WHOLE INSTALLATION DEPENDS ON THAT WORD: on a fresh
      # cluster cert-manager has not issued the certificate yet when this
      # Deployment is created. A required volume would leave the pod in
      # CreateContainerConfigError — no server, no mail, no way to see the
      # certificate page — until a DNS challenge completes somewhere else.
      # Optional lets the pod start with an empty directory; tls.go installs the
      # certificate as soon as it appears, and the tls check reports the gap
      # meanwhile.
      - name: mail-tls
        secret: {secretName: mail-tls, optional: true}
---
# The admin interface is exposed through Ingress, like the other apps.
# Without this object, the mail.<domain> domain resolves and the firewall
# routes, but Traefik does not know the Host: it answers 404 and the interface
# is unreachable.
#
# IT DOES CARRY A TLS BLOCK, and that is the mail layer's one real divergence
# from the other Ingresses: mail clients verify the name on the certificate, so
# the platform-level wildcard is not enough on its own (the mail host, its
# autoconfig/autodiscover/mta-sts names and the SMTP/IMAP listeners must all
# present the same certificate). secretName: mail-tls is what Stalwart is
# told to serve by tls.go; cert-manager fills it from the hosts listed below.
#
# Only the ADMINISTRATION port goes through the Ingress. Mail (SMTP, IMAP) stays
# directly accessible: we do not push mail through an HTTP proxy.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mail
  namespace: %[1]s
  annotations:
    # TLS AND HTTPS REDIRECTION, ABSENT HERE AND MEASURED ON THE CLUSTER:
    # the mail host answered http://mail.ceffio.org/ and redirected to
    # http://mail.ceffio.org/account — a login form in clear, while every
    # other host of the domain was on Let's Encrypt. The administration
    # interface carries the admin session, so it is the last one that should
    # have been left out.
    #
    # It was missed because this Ingress is written here, in the mail package,
    # rather than in ingressesManifest with the others. The issuer and the
    # redirection annotation are set the same way as there.
    cert-manager.io/cluster-issuer: %[5]s
    traefik.ingress.kubernetes.io/router.middlewares: %[1]s-ceffio-redirect-https@kubernetescrd
spec:
  ingressClassName: traefik
  # FOUR NAMES, FOUR CONSUMERS, ONE CERTIFICATE: mail. is the server itself
  # (admin interface, JMAP), autoconfig./autodiscover. are what a mail client
  # asks for BEFORE it knows the settings, and mta-sts. publishes the SMTP
  # transport-security policy. cert-manager's ingress-shim creates — or
  # EXTENDS — the mail-tls Certificate from this list, so the names belong
  # here rather than in a second object that would issue a second certificate.
  tls:
  - hosts: [%[7]s]
    secretName: mail-tls
  rules:
%[8]s
`, ns, domaine, stalwartImage, annotations, ingress.PourDomaine(domaine),
		rendrePortsConteneur(portsConteneur()), strings.Join(hotesIngress(plateforme, domaine), ", "),
		rendreReglesIngress(hotesIngress(plateforme, domaine)))

	return apply(ctx, manifest)
}

// waitReady waits until Stalwart answers on its admin port.
//
// We probe the HTTP API and not SMTP: the SMTP port can be open before the
// service is ready to accept mail, and an SMTP test on a server without a
// configured domain fails for the wrong reasons.
func waitReady(ctx context.Context) error {
	fmt.Println("∙ waiting for Stalwart to be ready...")
	// ON ATTEND LE DÉPLOIEMENT, PAS UN POD QUELCONQUE.
	//
	// « Un pod porte readiness=true » est vrai dès que l'ancien RéplicaSet l'est,
	// c'est-à-dire pendant tout le rollout : la vérification rendait la main
	// immédiatement, et l'étape suivante (un exec) tombait sur le pod que le
	// kubelet était en train de supprimer. Mesuré en production, au passage à
	// Stalwart 1.0.3 : « JMAP call x:AllowedIp/get: exit status 7 ».
	//
	// Ce qui attend le NOUVEAU RéplicaSet, celui qui va servir, c'est l'état du
	// déploiement : génération observée à jour, réplicas mis à jour ET
	// disponibles. La condition est lue par l'API, pas déduite d'une sortie.
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("cluster access: %w", err)
	}
	if err := cli.AttendreDeploiement(ctx, ns, "stalwart", 4*time.Minute); err != nil {
		return fmt.Errorf("Stalwart did not become ready within 4 minutes: %w", err)
	}
	fmt.Println("  ✓ Stalwart ready")
	return nil
}

// portsStalwart is the SINGLE SOURCE of the ports this layer publishes.
//
// WHY IT IS A TABLE AND NOT FOUR LINES IN TWO MANIFESTS: the POC measured the
// real listeners of Stalwart 1.0.3 (docs/plan-mail.md §9.E): 25, 465, 993 and
// 8080. The manifest previously declared 587 and 143 as well — ports the server
// does not listen on. A Service that publishes a closed port is worse than a
// missing one: the firewall lets the connection in, and the client waits.
//
// The container ports and the Service ports are derived from the same table, so
// they cannot drift; a test asserts the rendered manifests.
type portStalwart struct {
	Nom    string
	Numero int
}

// portsConteneur lists what the server listens on, independent of exposure.
//
// THE CONTAINER PORTS ARE CONSTANT even when the outside is not exposed: they
// are metadata that Kubernetes does not enforce, and keeping them constant
// means a change of exposure never requires re-creating the pod.
func portsConteneur() []portStalwart {
	return []portStalwart{
		{"smtp", 25},
		{"submission", 465},
		{"imaps", 993},
		{"http", 8080},
	}
}

// portsService lists what the INTERNAL Service publishes: every port the
// server listens on, always.
//
// IT DOES NOT DEPEND ON `clients_externes` ANY MORE, and the separation is what
// makes the exposure setting safe: the cluster's Service exposes all four ports
// on the pod network (Traefik needs 8080, the checks dial 25/465/993 from
// inside), while the PUBLIC Service — portsPublics — is the only one whose port
// list follows the setting. Closing 993 on the inside would have hidden it from
// the checks and from any in-cluster client, without changing what the Internet
// can reach.
func portsService() []portStalwart { return portsConteneur() }

// portsPublics lists what the INTERNET can reach, which is the `clients_externes`
// setting's whole effect: 25 always (inbound mail), 465 and 993 only when the
// operator asked to connect mail clients from outside. 8080 is never public:
// the administration interface goes through the Ingress, on 443.
func portsPublics(cfg Reglages) []portStalwart {
	ports := []portStalwart{{"smtp", 25}}
	if cfg.ClientsExternes {
		ports = append(ports,
			portStalwart{"submission", 465},
			portStalwart{"imaps", 993},
		)
	}
	return ports
}

// rendrePortsConteneur renders the container's port list (eight-space indent,
// inside the pod template).
func rendrePortsConteneur(ports []portStalwart) string {
	var b strings.Builder
	for _, p := range ports {
		fmt.Fprintf(&b, "        - {name: %s, containerPort: %d}\n", p.Nom, p.Numero)
	}
	return strings.TrimRight(b.String(), "\n")
}

// rendrePortsService renders the Service's port list (two-space indent, top
// level of the spec).
func rendrePortsService(ports []portStalwart) string {
	var b strings.Builder
	for _, p := range ports {
		fmt.Fprintf(&b, "  - {name: %s, port: %d, targetPort: %d}\n", p.Nom, p.Numero, p.Numero)
	}
	return strings.TrimRight(b.String(), "\n")
}

// applyService publishes the ports the settings ask for, then reads the Service
// back.
//
// THE READ-BACK IS THE POINT OF THIS FUNCTION: the port list is the one place
// where a wrong value is invisible until a user cannot connect. The check
// compares the ports in place with the ports wanted, by name and number, and
// reports the difference rather than assuming that the apply did what it was
// told.
func applyService(ctx context.Context, cfg Reglages) error {
	manifest := manifesteServices(cfg)
	if err := apply(ctx, manifest); err != nil {
		return err
	}

	// THE INTERNAL SERVICE IS READ BACK ON EVERY PORTS VALUE, because it is the
	// one the checks and every in-cluster client use.
	enPlace, err := lirePortsService(ctx, "stalwart")
	if err != nil {
		return err
	}
	voulus := portsService()
	if !memesPorts(enPlace, voulus) {
		return fmt.Errorf("the stalwart Service reads back the ports %s, expected %s",
			decrirePorts(enPlace), decrirePorts(voulus))
	}
	fmt.Printf("  ∙ ports in the cluster: %s\n", decrirePorts(enPlace))

	// THE PUBLIC SERVICE IS READ BACK WITH ITS TYPE AND POLICY, not only its
	// ports: a ClusterIP or a masquerading policy would look perfectly healthy
	// in the port list and be wrong for everything the outside world does.
	publics, err := lireServicePublic(ctx)
	if err != nil {
		return err
	}
	if !memesPorts(publics.Ports, portsPublics(cfg)) {
		return fmt.Errorf("the stalwart-public Service reads back the ports %s, expected %s",
			decrirePorts(publics.Ports), decrirePorts(portsPublics(cfg)))
	}
	if publics.Type != "LoadBalancer" || publics.Policy != "Local" {
		return fmt.Errorf("the stalwart-public Service reads back type %q and externalTrafficPolicy %q, expected LoadBalancer and Local",
			publics.Type, publics.Policy)
	}
	fmt.Printf("  ∙ ports published outside: %s\n", decrirePorts(publics.Ports))
	return nil
}

// manifesteServices renders the two Service objects Install applies.
//
// SEPARATE FROM applyService SO THE TEST PARSES THE REAL MANIFEST: a test that
// rebuilt the YAML itself would pass while the applied one had lost a port, and
// the port list is what decides whether mail can arrive at all.
func manifesteServices(cfg Reglages) string {
	// TWO SERVICES, TWO AUDIENCES. `stalwart` is the cluster's own endpoint: it
	// publishes everything, and nothing outside the cluster needs a route to it.
	// `stalwart-public` is the Internet-facing one; its port list is the
	// `clients_externes` setting, its externalTrafficPolicy is Local so the real
	// client address survives (POC 9.D), and it is the object the OPNsense port
	// forwards point at.
	return fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: stalwart
  namespace: %[1]s
spec:
  selector: {app: stalwart}
  ports:
%[2]s
---
# THE SECOND SERVICE IS NOT A DUPLICATE: a Service's type applies to ALL its
# ports, so a LoadBalancer carrying 8080 would publish the administration
# interface on a raw port of the Internet, and a ClusterIP cannot be reached
# from a port forward. Splitting it also makes "which ports are open" readable
# from one object, which is what the operator and the checks both need.
apiVersion: v1
kind: Service
metadata:
  name: stalwart-public
  namespace: %[1]s
spec:
  type: LoadBalancer
  # THE REAL CLIENT ADDRESS IS PRESERVED, and this is not a micro-optimisation:
  # Stalwart's auto-ban and its logs key on the source address, and a proxied
  # one would ban the proxy. Measured in POC 9.D: Local keeps it, Cluster
  # masquerades it.
  externalTrafficPolicy: Local
  selector: {app: stalwart}
  ports:
%[3]s
`, ns, rendrePortsService(portsService()), rendrePortsService(portsPublics(cfg)))
}

// lirePortsService reads a Service's ports through the API.
func lirePortsService(ctx context.Context, nom string) ([]portStalwart, error) {
	client, err := clientK8s()
	if err != nil {
		return nil, fmt.Errorf("mail service: %w", err)
	}
	svc, err := client.Kubernetes().CoreV1().Services(ns).Get(ctx, nom, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("the %s Service does not exist in namespace %q", nom, ns)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the %s Service: %w", nom, err)
	}
	ports := make([]portStalwart, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		ports = append(ports, portStalwart{Nom: p.Name, Numero: int(p.Port)})
	}
	return ports, nil
}

// servicePublic is what the read-back of `stalwart-public` is compared on.
type servicePublic struct {
	Type   string
	Policy string
	Ports  []portStalwart
}

func lireServicePublic(ctx context.Context) (servicePublic, error) {
	client, err := clientK8s()
	if err != nil {
		return servicePublic{}, fmt.Errorf("mail service: %w", err)
	}
	svc, err := client.Kubernetes().CoreV1().Services(ns).Get(ctx, "stalwart-public", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return servicePublic{}, fmt.Errorf("the stalwart-public Service does not exist in namespace %q", ns)
	}
	if err != nil {
		return servicePublic{}, fmt.Errorf("reading the stalwart-public Service: %w", err)
	}
	s := servicePublic{Type: string(svc.Spec.Type), Policy: string(svc.Spec.ExternalTrafficPolicy)}
	for _, p := range svc.Spec.Ports {
		s.Ports = append(s.Ports, portStalwart{Nom: p.Name, Numero: int(p.Port)})
	}
	return s, nil
}

// hotesIngress lists the names the mail Ingress serves, the mail host first.
//
// AUTOCONFIG AND AUTODISCOVER ARE THE FALLBACK PATH a mail client takes when
// the SRV records are missing: it asks these two names for a configuration
// file. mta-sts is the sender-side policy publication. All three are served by
// the same web interface, hence the same backend; only the certificate has to
// know the names.
func hotesIngress(plateforme, domaine string) []string {
	// THE MAIL HOST IS `domaine`, NOT `mail.<plateforme>`: CEFFIO_MAIL_DOMAIN
	// may have chosen another name, and the certificate must carry the name
	// that is really used. The three other hosts stay under the platform domain,
	// because that is the domain a mail client derives them from.
	hotes := []string{domaine}
	for _, sous := range []string{"autoconfig", "autodiscover", "mta-sts"} {
		hote := sous + "." + plateforme
		if hote != domaine {
			hotes = append(hotes, hote)
		}
	}
	return hotes
}

// rendreReglesIngress renders one rule per host, all pointing at the same
// backend.
func rendreReglesIngress(hotes []string) string {
	var b strings.Builder
	for i, hote := range hotes {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, `  - host: %s
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: stalwart
            port: {number: 8080}`, hote)
	}
	return b.String()
}

// memesPorts compares two port lists without caring about their order.
func memesPorts(a, b []portStalwart) bool {
	if len(a) != len(b) {
		return false
	}
	for _, p := range a {
		trouve := false
		for _, q := range b {
			if p == q {
				trouve = true
				break
			}
		}
		if !trouve {
			return false
		}
	}
	return true
}

// decrirePorts renders a port list for a message.
func decrirePorts(ports []portStalwart) string {
	parties := make([]string, 0, len(ports))
	for _, p := range ports {
		parties = append(parties, fmt.Sprintf("%s/%d", p.Nom, p.Numero))
	}
	return strings.Join(parties, ", ")
}

// ---------------------------------------------------------------------------
// Local utilities
// ---------------------------------------------------------------------------

// secretExiste is used to FLAG a dead copy, never to use it: since the vault
// became the single source, a Kubernetes Secret of the same name is no longer
// read by anyone. Detecting it prevents mistaking it for the source.
func secretExiste(ctx context.Context, nom string) bool {
	cli, err := clientK8s()
	if err != nil {
		return false
	}
	_, err = cli.Kubernetes().CoreV1().Secrets(ns).Get(ctx, nom, metav1.GetOptions{})
	return err == nil
}

func createSecret(ctx context.Context, name string, kv map[string]string) error {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + name + "\n  namespace: " + ns + "\ntype: Opaque\nstringData:\n")
	for k, v := range kv {
		b.WriteString("  " + k + ": " + v + "\n")
	}
	return apply(ctx, b.String())
}

func apply(ctx context.Context, manifest string) error {
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("cluster access: %w", err)
	}
	if err := cli.Appliquer(ctx, manifest); err != nil {
		return fmt.Errorf("applying the manifest: %w", err)
	}
	return nil
}

// genSecret produces a random password in hexadecimal.
func genSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
