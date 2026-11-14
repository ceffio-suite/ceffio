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
// TWO REAL CONSTRAINTS, MEASURED BEFORE WRITING THIS CODE:
//
//  1. OUTBOUND port 25 is BLOCKED at Free (verified). Stalwart therefore cannot
//     deliver directly to Gmail. It is configured with a SEND relay
//     (send.one.com:587): the relay sends to the outside, and it carries the
//     reverse DNS. This is the standard configuration for self-hosters behind a
//     residential connection.
//
//  2. The reverse DNS of the public IP is "<fai>.example.net", not the domain.
//     Without a relay, Gmail would reject the messages. With a relay, the
//     question disappears — one.com is responsible for deliverability.
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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/k8s"
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
	fmt.Printf("∙ mail domain: %s\n", domaine)

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

	if err := applyWorkload(ctx, domaine); err != nil {
		return err
	}
	if err := applyService(ctx, cfg); err != nil {
		return err
	}
	if err := waitReady(ctx); err != nil {
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

func applyWorkload(ctx context.Context, domaine string) error {
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
---
# The admin interface is exposed through Ingress, like the other apps.
# Without this object, the mail.<domain> domain resolves and the firewall
# routes, but Traefik does not know the Host: it answers 404 and the interface
# is unreachable.
#
# No TLS block here: the other Ingresses of the platform do not have one either
# (the certificate is laid down at the cluster and firewall level). Adding one
# would create an inconsistency, and a nonexistent secretName would break the
# routing.
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
  tls:
  - hosts: [%[2]s]
    secretName: mail-tls
  rules:
  - host: %[2]s
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: stalwart
            port: {number: 8080}
`, ns, domaine, stalwartImage, annotations, ingress.PourDomaine(domaine),
		rendrePortsConteneur(portsConteneur()))

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
	// `rollout status` attend le NOUVEAU RéplicaSet, celui qui va servir.
	out, err := k8s.Command(ctx, "kubectl", "-n", ns, "rollout", "status",
		"deployment/stalwart", "--timeout=240s").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Stalwart did not become ready within 4 minutes: %w: %s",
			err, strings.TrimSpace(string(out)))
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

// portsService lists what the Service publishes, which depends on the
// `clients_externes` setting: mail clients (Thunderbird, a phone) need 465 and
// 993 from the outside, while 25 and 8080 are required either way (inbound mail
// and the administration interface).
func portsService(cfg Reglages) []portStalwart {
	ports := []portStalwart{{"smtp", 25}}
	if cfg.ClientsExternes {
		ports = append(ports,
			portStalwart{"submission", 465},
			portStalwart{"imaps", 993},
		)
	}
	return append(ports, portStalwart{"http", 8080})
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
// reports the difference rather than assuming that `kubectl apply` did what it
// was told.
func applyService(ctx context.Context, cfg Reglages) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: stalwart
  namespace: %[1]s
spec:
  selector: {app: stalwart}
  ports:
%[2]s
`, ns, rendrePortsService(portsService(cfg)))
	if err := apply(ctx, manifest); err != nil {
		return err
	}
	enPlace, err := lirePortsService(ctx)
	if err != nil {
		return err
	}
	voulus := portsService(cfg)
	if !memesPorts(enPlace, voulus) {
		return fmt.Errorf("the stalwart Service reads back the ports %s, expected %s",
			decrirePorts(enPlace), decrirePorts(voulus))
	}
	fmt.Printf("  ∙ published ports: %s\n", decrirePorts(enPlace))
	return nil
}

// lirePortsService reads the Service's ports through the API.
func lirePortsService(ctx context.Context) ([]portStalwart, error) {
	client, err := clientK8s()
	if err != nil {
		return nil, fmt.Errorf("mail service: %w", err)
	}
	svc, err := client.Kubernetes().CoreV1().Services(ns).Get(ctx, "stalwart", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("the stalwart Service does not exist in namespace %q", ns)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the stalwart Service: %w", err)
	}
	ports := make([]portStalwart, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		ports = append(ports, portStalwart{Nom: p.Name, Numero: int(p.Port)})
	}
	return ports, nil
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
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", nom, "-n", ns).CombinedOutput()
	return err == nil && strings.Contains(string(out), nom)
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
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply: %w: %s", err, tronquer(string(out), 300))
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
