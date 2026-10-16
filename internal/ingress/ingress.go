// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package ingress makes the suite reachable from a browser: cert-manager TLS
// issuers (self-signed CA for domains without public ACME — dev/SME) and
// Traefik Ingresses with their own hosts (*.<domain>).
//
// Prerequisites: cert-manager installed (Phase 2) and a "traefik" Ingress
// controller (native to k3s; on k3d, plan for a compatible controller).
package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
	"net"
	"os"
	"os/exec"
	"strings"
)

// The two issuers a certificate can come from. Named once, referenced
// everywhere: a typo in an issuer name does not fail loudly — the Ingress is
// created, no certificate is ever issued, and the browser shows the default
// Traefik certificate, which looks like a TLS problem nobody can place.
const (
	// issuerACME: Let's Encrypt. Trusted by every browser out of the box.
	issuerACME = "ceffio-letsencrypt"
	// issuerCA: our own authority, created by caManifest. For private names,
	// and as the fallback the operator can force.
	issuerCA = "ceffio-ca-issuer"
)

// Deploy applies idempotently the CA + the Ingresses for the domain.
// domain: base domain, e.g. "company.fr" → cloud.company.fr, chat.company.fr...
func Deploy(ctx context.Context, domain string) error {
	fmt.Printf("\nIngress / TLS (Phase 9) for domain=%s...\n", domain)

	// The internal CA is created ALWAYS, even when Let's Encrypt signs the
	// public hostnames: the components call each other on https://<host> and
	// verify that authority (InjecterConfianceTLS below). It costs three small
	// objects and it is what makes the internal calls work at all.
	if err := apply(ctx, caManifest()); err != nil {
		return err
	}

	// Let's Encrypt issuers: created ONLY for a public domain, and only when
	// the operator gave an address.
	//
	// WITHOUT THE EMAIL, NO ISSUER: Let's Encrypt requires one at
	// registration, and it is the only channel they use to warn about an
	// expiring certificate or a suspended account. Inventing an address would
	// send those warnings to somebody who does not exist — so we would rather
	// not create the issuer and say so, than create one that silently drops
	// them.
	if issuerPour(domain) == issuerACME {
		email := strings.TrimSpace(os.Getenv("CEFFIO_ACME_EMAIL"))
		if email == "" {
			// A hard stop, not a warning: continuing would install Ingress
			// objects asking for certificates that can never be issued, and
			// the deployment would look successful while every browser showed
			// a certificate warning.
			return fmt.Errorf("CEFFIO_ACME_EMAIL is required to obtain Let's Encrypt "+
				"certificates for %s — set it to the address that should receive "+
				"expiry warnings, or force the internal authority with "+
				"CEFFIO_TLS_ISSUER=ca", domain)
		}
		if err := apply(ctx, acmeManifest(email)); err != nil {
			return err
		}
		fmt.Printf("∙ Let's Encrypt issuers ready (HTTP-01, account %s)\n", email)
	} else {
		fmt.Println("∙ internal authority only (private domain, or CEFFIO_TLS_ISSUER=ca)")
	}

	// HTTPS redirection on port 80, with the ACME path exempted. Applied
	// BEFORE the Ingresses so the middleware exists when they reference it —
	// an Ingress pointing at a missing middleware is accepted by the API and
	// then silently ignored by Traefik, which serves the route in clear.
	// ONE MIDDLEWARE PER NAMESPACE, and this is not a detail.
	//
	// Traefik resolves "<namespace>-<name>@kubernetescrd", so the middleware
	// must live in the SAME namespace as the Ingress that references it.
	// Verified on the cluster both ways: referenced as
	// "ceffio-system/ceffio-redirect-https" (slash) Traefik logs
	// « middleware does not exist » and serves the route IN CLEAR, without
	// failing the deployment — the worst possible outcome, since everything
	// looks applied.
	for _, ns := range []string{"ceffio-files", "ceffio-identity", "ceffio-office",
		"ceffio-vault", "ceffio-video", "ceffio-system", "ceffio-mail"} {
		if err := apply(ctx, redirectionManifest(ns)); err != nil {
			return err
		}
	}

	if err := apply(ctx, ingressesManifest(domain)); err != nil {
		return err
	}

	// KEYCLOAK'S PUBLIC HOSTNAME IS SET HERE, NOT LATER.
	//
	// It used to happen in AdoptURLs, which runs after the application
	// layers. Too late: without KC_HOSTNAME_URL, Keycloak builds its OIDC
	// discovery document with the scheme it sees internally — http — so the
	// issuer came out as
	//
	//   "issuer":"http://keycloak.<domain>/realms/ceffio"
	//
	// while every client configures and expects https. Stalwart compares what
	// it gets against its own https issuer and refuses:
	//
	//   discovery does not return the expected provider
	//   (https://keycloak.ceffio.org/realms/ceffio):
	//   {"issuer":"http://keycloak.ceffio.org/realms/ceffio",...}
	//
	// The deployment stopped there. Nothing is wrong with Keycloak: it simply
	// has to be told its public name before anyone asks it who it is.
	if err := adoptKeycloakHost(ctx, domain); err != nil {
		return err
	}

	// TLS TRUST FOR THE INTERNAL AUTHORITY, ALSO BEFORE THE OIDC BLOCKS.
	//
	// Moved here with adoptKeycloakHost, for the same reason: what runs after
	// this point talks to https://keycloak.<domain>, and a component that does
	// not trust our authority fails at the handshake. Stalwart is the clearest
	// case — curl without -k exits 60 with no output, and the deployment then
	// reports a discovery problem, which reads like a Keycloak fault.
	//
	// The applications are already running when Deploy is called, so patching
	// their trust store here works.
	if err := InjecterConfianceTLS(ctx, domain, isDemo(domain)); err != nil {
		return err
	}

	fmt.Println("✓ Ingress / TLS configured (Traefik + ClusterIssuer CA + hosts *." + domain + ")")
	return nil
}

// AdoptURLs makes the apps fully usable through the ingress public URLs:
// real homeserver for Element, Synapse public_baseurl, Nextcloud https
// protocol, SSO redirect URIs and the ONLYOFFICE connector URL.
func AdoptURLs(ctx context.Context, domain string) error {
	fmt.Printf("\nAdopting public URLs *.%s...\n", domain)
	cloud := "cloud." + domain
	office := "office." + domain

	// 3) Nextcloud: https protocol + public URL + SSRF + proxy behind Traefik.
	// Nextcloud's HttpClient blocks private addresses by default (SSRF): but
	// Keycloak/ONLYOFFICE are on cluster IPs → allow local servers.
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

	// 4) Keycloak SSO redirect of the nextcloud client to https.
	if err := ssoRedirect(ctx, domain); err != nil {
		return err
	}

	// 5) ONLYOFFICE connector → public URL. EXACT keys (CamelCase, otherwise
	// "L'application ONLYOFFICE n'est pas configuré").
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "DocumentServerInternalUrl", "--value", "https://"+office+"/"); err != nil {
		return err
	}
	if err := occSet(ctx, "config:app:set", "onlyoffice", "StorageUrl", "--value", "https://"+cloud+"/"); err != nil {
		return err
	}

	// 6) Keycloak: public hostname + https frontend URL + proxy headers —
	// otherwise its browser redirects point to the hardcoded internal hostname.
	//
	// ALREADY APPLIED BY Deploy, and replayed here on purpose: Deploy runs
	// before the application layers, this one after. The call is idempotent,
	// and repeating it costs one `kubectl set env` that changes nothing. It
	// stays because a cluster deployed by an older binary has never run it
	// from Deploy, and this is the pass that would fix it.
	if err := adoptKeycloakHost(ctx, domain); err != nil {
		return err
	}

	// 6b) Traefik behind an upstream proxy. Without it, a firewall terminating
	// TLS (OPNsense, Caddy, nginx) forwards in HTTP and Traefik announces
	// X-Forwarded-Proto: http → applications redirect to http:// from an https
	// client. Observed in production on Keycloak.
	if err := ProxyAmont(ctx); err != nil {
		return err
	}

	// 6c) Remove the old domains from the configurations. A migrated installation
	// otherwise keeps the old hardcoded name (observed: demo.local in Keycloak,
	// Element, Synapse) and redirects to a domain that no longer exists.
	for _, ancien := range DomainesConnus(domain) {
		if err := NettoyerAncienDomaine(ctx, ancien, domain); err != nil {
			return err
		}
	}

	// 7) Internal TLS trust — ALWAYS, not only in demo.
	//
	// The hardening was locked inside `if isDemo(domain)`: on a public domain it
	// was therefore skipped, and the CA injection from the original installation
	// (done on demo.local) stayed in place — with its SSL_CERT_FILE stripped of
	// the public authorities. Consequence: Synapse's OIDC callback to Keycloak
	// failed on "certificate verify failed" even though the presented
	// certificate was a valid Let's Encrypt one.
	//
	// The services call each other by their PUBLIC name over https (behind
	// Traefik), so the internal authority must be recognized in both cases.
	// Only the hostAliases are demo-specific: on a public domain the DNS really
	// resolves, and overriding it would send traffic to the wrong place.
	if err := InjecterConfianceTLS(ctx, domain, isDemo(domain)); err != nil {
		return err
	}

	fmt.Println("✓ Public URLs adopted in Nextcloud, ONLYOFFICE, Keycloak + SSO redirect")
	return nil
}

// adoptKeycloakHost forces Keycloak's public hostname (browser redirects) with
// an https frontend URL and Traefik's proxy headers. Idempotent.
func adoptKeycloakHost(ctx context.Context, domain string) error {
	host := "keycloak." + domain
	url := "https://" + host
	cmd := k8s.Command(ctx, "kubectl", "set", "env", "-n", "ceffio-identity", "deploy/keycloak",
		"KC_HOSTNAME="+host, "KC_HOSTNAME_URL="+url,
		"KC_HOSTNAME_STRICT=false", "KC_PROXY_HEADERS=xforwarded")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	rcmd := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/keycloak", "-n", "ceffio-identity", "--timeout=240s")
	rcmd.Stdout = os.Stdout
	rcmd.Stderr = os.Stderr
	return rcmd.Run()
}

// isDemo → private `.local` domain: no real DNS or public CA → hostAliases +
// CA injection hardening. A public domain does not need it.
func isDemo(domain string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(domain)), ".local")
}

// InjecterConfianceTLS makes the internal authority recognizable by the
// services, so that their server→server calls over public https succeed.
//
// Applies ALWAYS (public domain as well as demo): the applications call each
// other by their public name, and this certificate is signed by our authority.
//
// avecHostAliases is reserved for the demo: only there does the DNS not resolve
// the public names and they must be force-routed to Traefik. On a public
// domain, laying down hostAliases would be harmful — traffic must go through
// the real DNS, not be diverted to the cluster.
func InjecterConfianceTLS(ctx context.Context, domain string, avecHostAliases bool) error {
	if avecHostAliases == false {
		fmt.Println("Internal TLS trust (ceffio CA injected, without hostAliases — public domain)...")
	} else {
		fmt.Println("Internal TLS trust + hostAliases→Traefik (demo)...")
	}
	tip, err := svcIP(ctx, "traefik", "kube-system")
	if err != nil {
		return fmt.Errorf("Traefik IP: %w", err)
	}
	ca, err := caCert(ctx)
	if err != nil {
		return err
	}
	kc := "keycloak." + domain
	cloud := "cloud." + domain
	office := "office." + domain

	// On a public domain, hosts stays EMPTY: this purges the hostAliases laid
	// down in the demo.local days (a "hostAliases: null" removes them) and lets
	// the real DNS do its job.
	hostsAutres := []string{kc, office}
	hostsOffice := []string{cloud, office, kc}
	if !avecHostAliases {
		hostsAutres, hostsOffice = nil, nil
	}

	// Nextcloud (PHP): CA via a php.ini pointing at the mounted CA (persistent for PHP).
	if err := createCAConfigs(ctx, "ceffio-files", ca); err != nil {
		return err
	}
	// SSL_CERT_FILE REPLACES the default list (see the Synapse note below): we
	// point at the COMBINED bundle, otherwise Nextcloud loses all trust in
	// public certificates and its outbound calls fail.
	if err := patchApp(ctx, "ceffio-files", "nextcloud", "nextcloud", tip,
		hostsAutres, []envKV{{"SSL_CERT_FILE", cheminPaquetCombine}}, true); err != nil {
		return err
	}

	// ONLYOFFICE (Node.js): NODE_EXTRA_CA_CERTS.
	// This one ADDS to the authority list, it does not replace it — we can
	// therefore point at our authority alone without losing the public
	// certificates. Do NOT "uniformize" with the combined bundle: it would also
	// be correct, but needlessly heavier.
	if err := createCAConfigs(ctx, "ceffio-office", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-office", "onlyoffice", "onlyoffice", tip,
		hostsOffice, []envKV{{"NODE_EXTRA_CA_CERTS", "/etc/ceffio-ca/ceffio-ca.crt"}}, false); err != nil {
		return err
	}

	// Stalwart (Rust): SSL_CERT_FILE, like Nextcloud.
	//
	// IT WAS MISSING HERE, AND THAT SILENTLY BROKE ITS OIDC LOGIN. Stalwart
	// verifies its own single sign-on by fetching the discovery document over
	// https://keycloak.<domain>. Without our authority in its trust store the
	// fetch failed at the TLS handshake (curl exit 60), and the failure did
	// not look like a certificate problem at all:
	//
	//   curl without -k  → exit 60, no output
	//   curl with    -k  → {"issuer":"https://keycloak.ceffio.org/realms/ceffio",...}
	//
	// The deployment then reported « discovery does not return the expected
	// provider », which reads like a Keycloak misconfiguration and sent the
	// investigation there. Keycloak was correct the whole time.
	//
	// Combined bundle, not our authority alone: SSL_CERT_FILE REPLACES the
	// default list, so pointing at ceffio-ca.crt would make Stalwart reject
	// every public certificate — including the ones its outbound SMTP and
	// spam-filter calls rely on.
	if err := createCAConfigs(ctx, "ceffio-mail", ca); err != nil {
		return err
	}
	if err := patchApp(ctx, "ceffio-mail", "stalwart", "stalwart", tip,
		nil, []envKV{{"SSL_CERT_FILE", cheminPaquetCombine}}, false); err != nil {
		return err
	}
	if avecHostAliases {
		fmt.Println("✓ Internal TLS trust applied (hostAliases→" + tip + ")")
	} else {
		fmt.Println("✓ Internal TLS trust applied (public domain, no hostAliases)")
	}
	return nil
}

type envKV struct{ name, value string }

// cheminPaquetCombine: file containing the SYSTEM authorities plus our internal
// authority. To be used wherever SSL_CERT_FILE is set, which REPLACES the
// default list instead of adding to it.
const cheminPaquetCombine = "/etc/ceffio-ca/paquet-combine.crt"

// svcIP reads the ClusterIP of a Service.
func svcIP(ctx context.Context, name, ns string) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "svc", name, "-n", ns, "-o", "jsonpath={.spec.clusterIP}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// paquetCombine assembles the SYSTEM authorities and our internal authority
// into a single PEM file.
//
// Why: SSL_CERT_FILE (Python, OpenSSL) designates THE list of trusted
// authorities, it does not add to it. Putting only our internal authority in it
// makes every public certificate invalid — that is exactly what broke the OIDC
// callback (Keycloak presents a valid Let's Encrypt, Synapse refused it).
//
// The bundle therefore combines both: nothing is lost, our authority is
// recognized.
func paquetCombine() (string, error) {
	systeme := ""
	for _, f := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if b, err := os.ReadFile(f); err == nil && len(b) > 0 {
			systeme = string(b)
			break
		}
	}
	if systeme == "" {
		return "", fmt.Errorf("no system authority bundle found")
	}
	if !strings.HasSuffix(systeme, "\n") {
		systeme += "\n"
	}
	// Our authority is added AFTER the system bundle.
	out, err := caCert(context.Background())
	if err != nil {
		return "", err
	}
	return systeme + out, nil
}

// caCert reads the CA certificate of the chain signed by cert-manager (ceffio-ca-tls).
func caCert(ctx context.Context) (string, error) {
	out, err := k8s.Command(ctx, "kubectl", "get", "secret", "ceffio-ca-tls", "-n", "cert-manager", "-o", "jsonpath={.data.ca\\.crt}").Output()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// createCAConfigs creates the ConfigMaps ceffio-ca-cm (CA) + ceffio-phpini (php.ini) in the ns.
func createCAConfigs(ctx context.Context, ns, ca string) error {
	// Two files in the ConfigMap:
	//   ceffio-ca.crt — our authority alone. For mechanisms that ADD
	//     (Node's NODE_EXTRA_CA_CERTS, PHP's openssl.cafile, curl.cainfo).
	//   paquet-combine.crt — system authorities + ours. Mandatory for
	//     SSL_CERT_FILE, which REPLACES the default list: pointing at our
	//     authority alone would make every public certificate refused (the
	//     cause of the "certificate verify failed" on Synapse's OIDC callback).
	paquet, err := paquetCombine()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-ca-cm -n "+ns+
			" --from-file=ceffio-ca.crt=/dev/stdin"+
			" --from-file=paquet-combine.crt=/tmp/paquet-combine.crt"+
			" --dry-run=client -o yaml | kubectl apply -f -")
	if err := os.WriteFile("/tmp/paquet-combine.crt", []byte(paquet), 0o644); err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(ca)
	cmd.Env = k8s.Env()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	os.Remove("/tmp/paquet-combine.crt")
	// openssl.cafile and curl.cainfo REPLACE the default list (same trap as
	// SSL_CERT_FILE): the combined bundle, so as not to lose the public
	// authorities PHP needs for its outbound calls.
	ini := "openssl.cafile=" + cheminPaquetCombine + "\ncurl.cainfo=" + cheminPaquetCombine + "\n"
	cmd2 := exec.CommandContext(ctx, "sh", "-c",
		"kubectl create configmap ceffio-phpini -n "+ns+" --from-file=zz-ceffio.ini=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -")
	cmd2.Stdin = strings.NewReader(ini)
	cmd2.Env = k8s.Env()
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	return cmd2.Run()
}

// patchApp applies hostAliases + CA volume + env (+ php.ini) via merge patch (idempotent).
func patchApp(ctx context.Context, ns, deploy, container, traefikIP string, hosts []string, envs []envKV, withPHPIni bool) error {
	// Empty hosts = no hostAliases. We lay them down ONLY in demo: on a public
	// domain, forcing resolution towards the cluster would short-circuit the real
	// DNS and send traffic to the wrong place.
	var ha []map[string]any
	if len(hosts) > 0 {
		ha = []map[string]any{{"ip": traefikIP, "hostnames": hosts}}
	}
	vols := []map[string]any{{"name": "ceffio-ca", "configMap": map[string]string{"name": "ceffio-ca-cm"}}}
	env := []map[string]string{}
	for _, e := range envs {
		env = append(env, map[string]string{"name": e.name, "value": e.value})
	}
	mounts := []map[string]string{{"name": "ceffio-ca", "mountPath": "/etc/ceffio-ca"}}
	if withPHPIni {
		vols = append(vols, map[string]any{"name": "ceffio-phpini", "configMap": map[string]string{"name": "ceffio-phpini"}})
		// subPath on the FILE: the Nextcloud entrypoint writes redis-session.ini into
		// conf.d at boot — mounting a read-only ConfigMap directory over that folder
		// breaks the entrypoint (Read-only file system). subPath only mounts the
		// zz-ceffio.ini file.
		mounts = append(mounts, map[string]string{"name": "ceffio-phpini", "mountPath": "/usr/local/etc/php/conf.d/zz-ceffio.ini", "subPath": "zz-ceffio.ini"})
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
	cmd := k8s.Command(ctx, "kubectl", "patch", "deploy", deploy, "-n", ns, "--type=strategic", "-p", string(b))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	r := k8s.Command(ctx, "kubectl", "rollout", "status", "deploy/"+deploy, "-n", ns, "--timeout=200s")
	r.Stdout = os.Stdout
	r.Stderr = os.Stderr
	return r.Run()
}

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

func appendNonDuplicate(ctx context.Context, ns, cm, key, line, needle, target string) error {
	data, err := cmData(ctx, ns, cm, key)
	if err != nil {
		return err
	}
	if strings.Contains(data, needle) {
		return nil // already present
	}
	if err := applyCMData(ctx, ns, cm, key, data+"\n"+line); err != nil {
		return err
	}
	return rolloutRestart(ctx, target)
}

// ssoRedirect adds the https redirect URIs of the OIDC clients via kcadm.
func ssoRedirect(ctx context.Context, domain string) error {
	for _, client := range []struct{ id, base string }{
		{id: "nextcloud", base: "cloud." + domain},
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
	full := append([]string{"exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--", "php", "occ"}, args...)
	cmd := k8s.Command(ctx, "kubectl", full...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmData(ctx context.Context, ns, name, key string) (string, error) {
	tpl := "{.data." + strings.ReplaceAll(key, ".", "\\.") + "}"
	out, err := k8s.Command(ctx, "kubectl", "get", "cm", name, "-n", ns, "-o", "jsonpath="+tpl).Output()
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
	cmd.Env = k8s.Env()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// rolloutRestart restarts a deployment.
//
// The namespace can be passed explicitly: "deploy/traefik" lives in kube-system,
// outside the table below, and the previous version FAILED on a target absent
// from the table — which interrupted the whole deployment in progress (observed
// on ProxyAmont, which stopped the sequence before the console).
func rolloutRestart(ctx context.Context, target string) error {
	explicite := ""
	if strings.Contains(target, "@") {
		parties := strings.SplitN(target, "@", 2)
		target, explicite = parties[0], parties[1]
	}
	deploy := strings.TrimPrefix(target, "deploy/")
	ns := explicite
	if ns == "" {
		ns = map[string]string{
			"nextcloud": "ceffio-files", "onlyoffice": "ceffio-office",
			"keycloak": "ceffio-identity",
			"traefik":  "kube-system",
		}[deploy]
	}
	if ns == "" {
		return fmt.Errorf("unknown namespace for %q (use \"deploy/name@namespace\")", target)
	}
	cmd := k8s.Command(ctx, "kubectl", "rollout", "restart", "deploy/"+deploy, "-n", ns)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runKcadm runs kcadm.sh in the Keycloak pod and returns the combined output.
//
// ADMIN CREDENTIALS COME FROM THE VAULT and travel through STANDARD INPUT,
// never through the command line (an argument is readable in
// /proc/<pid>/cmdline, and inspecting a process must not reveal a secret).
//
// THIS CODE USED TO READ $KC_BOOTSTRAP_ADMIN_* FROM THE POD ENVIRONMENT, which
// no longer works: the OpenBao injector migration removed those variables from
// the Deployment. They now live only in /secrets/env, sourced by the
// CONTAINER'S STARTUP COMMAND for its own process — a `kubectl exec` opens a
// NEW shell that inherits none of it. The variables were EMPTY, kcadm answered
// "Invalid user credentials", and this surfaced as:
//
//	get client nextcloud: exit status 1
//
// which points at a password problem that does not exist. internal/sso already
// did it correctly (its own runKcadm); this copy had not been updated.
func runKcadm(ctx context.Context, args ...string) (string, error) {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return "", fmt.Errorf("Keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return "", fmt.Errorf("incomplete keycloak/admin vault entry (username and password required)")
	}

	// Injects -r ceffio after the verb (the SSO clients live in the application realm).
	quoted := make([]string, 0, len(args)+3)
	for i, a := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		if i == 0 {
			quoted = append(quoted, "'-r'", "'ceffio'")
		}
	}
	script := `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master ` +
		`--user '` + strings.ReplaceAll(utilisateur, "'", `'\''`) + `' --password "$motdepasse" >/dev/null 2>&1 && ` +
		`/opt/keycloak/bin/kcadm.sh ` + strings.Join(quoted, " ")

	full := []string{"exec", "-i", "-n", "ceffio-identity", "deploy/keycloak", "-c", "keycloak", "--", "sh", "-c", script}
	cmd := k8s.Command(ctx, "kubectl", full...)
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// kcadmRedirect adds a redirect URI to the Keycloak OIDC client without overwriting the existing ones.
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
		return fmt.Errorf("client %s not found in the ceffio realm", clientID)
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

// issuerPour decides WHERE a domain's certificates are signed.
//
// TWO KINDS OF DOMAIN, AND THE DIFFERENCE IS NOT COSMETIC:
//
//	A PUBLIC domain (example.com): Let's Encrypt signs it. The visitor's
//	browser already trusts that authority, so nobody sees a warning. The
//	ACME server validates over HTTP-01, which needs the domain to resolve
//	here and port 80 to answer — both true by construction for a domain
//	the operator just pointed at us.
//
//	A PRIVATE domain (*.local, *.test, or any name that does not resolve on
//	the public Internet): our own CA. Let's Encrypt cannot validate a name
//	it cannot reach, and an HTTP-01 challenge would simply never complete.
//
// THE OPERATOR CAN FORCE EITHER ONE with CEFFIO_TLS_ISSUER=letsencrypt or
// CEFFIO_TLS_ISSUER=ca — for a public domain behind a VPN, or a private name
// that has a real DNS record internally. Without the variable, the rule above
// applies and the answer is right for the normal case.
//
// NEVER BOTH. cert-manager applies one issuer per Ingress, and asking for a
// certificate we cannot obtain means no certificate at all: the Ingress would
// serve the default self-signed Traefik certificate, which is worse than the
// honest CA we control.
// PourDomaine exposes the issuer choice to the other layers (console, talk).
//
// They build their Ingress and Certificate objects in their own package, so
// they cannot call issuerPour. Without this export they would keep the CA
// issuer hardcoded, and a public domain would end up with a mix: most hosts on
// Let us Encrypt, the console and the signaling server on our CA — exactly the
// inconsistency this change exists to remove.
func PourDomaine(domain string) string { return issuerPour(domain) }

func issuerPour(domain string) string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CEFFIO_TLS_ISSUER"))) {
	case "letsencrypt", "le", "acme":
		return issuerACME
	case "ca", "selfsigned", "interne":
		return issuerCA
	}
	if domainePublic(domain) {
		return issuerACME
	}
	return issuerCA
}

// domainePublic: does this name resolve on the public Internet?
//
// A domain that ends in a reserved TLD or has no dot at all is private — that
// is a name, not an address. `.local` is reserved by RFC 6762 (mDNS) and is
// what the demo deployment uses; it can never be signed by a public authority.
func domainePublic(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" || !strings.Contains(d, ".") {
		return false
	}
	for _, prive := range []string{".local", ".test", ".internal", ".invalid", ".example"} {
		if strings.HasSuffix(d, prive) {
			return false
		}
	}
	// A bare IP address has no certificate to obtain over HTTP-01.
	if net.ParseIP(d) != nil {
		return false
	}
	return true
}

func apply(ctx context.Context, manifest string) error {
	cmd := k8s.Command(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// acmeManifest: the Let's Encrypt ClusterIssuer, plus a STAGING twin.
//
// WHY STAGING EXISTS AND MUST STAY: Let's Encrypt limits production to 5
// failures per account per hostname per hour, and 50 certificates per
// registered domain per week. A deployment that is being debugged retries —
// against production those retries lock the domain out for days, and the
// operator has no way to ask for it back. The staging endpoint has the same
// behaviour with no limit that matters, so a deployment in doubt can be run
// against it and switched over once.
//
// The email is REQUIRED by Let's Encrypt: it is the only way they warn about
// an expiring certificate or an account problem. It comes from the operator
// (CEFFIO_ACME_EMAIL) with no default — inventing an address would send
// expiry warnings to somebody who does not exist.
func acmeManifest(email string) string {
	bloc := func(nom, url string) string {
		return fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: %s
spec:
  acme:
    server: %s
    email: %s
    privateKeySecretRef:
      name: %s-account
    solvers:
    # HTTP-01 ONLY. The challenge is served by Traefik on port 80, which is
    # already open for the Ingresses — no DNS credential to store, rotate or
    # leak. DNS-01 would allow a wildcard, but it needs a provider token in
    # the cluster, and a wildcard certificate is not needed to serve seven
    # known hostnames.
    - http01:
        ingress:
          class: traefik
`, nom, url, email, nom)
	}
	return bloc("ceffio-letsencrypt", "https://acme-v02.api.letsencrypt.org/directory") +
		"---\n" +
		bloc("ceffio-letsencrypt-staging", "https://acme-staging-v02.api.letsencrypt.org/directory")
}

// caManifest: self-signed CA (bootstrap issuer → CA certificate → CA issuer)
// to sign the Ingress certificates. Done once, idempotent.
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

// appRoute describes an application route: host "<sub>.<domain>", target service.
type appRoute struct {
	sub, namespace, service string
	port                    int
}

// redirectionManifest: force HTTPS on port 80, WITHOUT breaking the ACME
// challenge.
//
// THE PORT CANNOT SIMPLY BE CLOSED: HTTP-01 is how Let's Encrypt proves the
// domain points here, and it reads the token over plain http on port 80.
// Closing it means no certificate at renewal — and the failure shows up months
// later, when nobody is watching.
//
// So the port stays open and serves TWO things:
//
//	/.well-known/acme-challenge/*  served as-is, in clear (it is a public
//	                               token, not a secret)
//	everything else                301 to https, permanent
//
// VERIFIED NECESSARY, not theoretical: Keycloak and ONLYOFFICE build their
// redirects with the scheme they receive. Arriving over http, they answered
// http://keycloak.<domain>/admin/ and http://office.<domain>/welcome/ — a
// login page and a document server handed back to the browser in clear, right
// after we had paid for real certificates.
//
// WHY A MIDDLEWARE AND NOT TRAEFIK'S entryPoint REDIRECTION: the entryPoint
// setting cannot be excluded per Ingress, so it would also capture the
// challenge path and break renewal. The middleware lets us exempt it.
func redirectionManifest(ns string) string {
	return fmt.Sprintf(`apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ceffio-redirect-https
  namespace: %s
spec:
  redirectScheme:
    scheme: https
    permanent: true
`, ns)
}

// redirectionAnnotations returns the annotation forcing https on one Ingress.
//
// Applied to EVERY route, including the signaling server: its WebSocket
// upgrade carries the session, and leaving one host reachable in clear would
// mean the rule holds everywhere except the one place nobody remembers to
// check.
func redirectionAnnotations(ns string) string {
	return "    traefik.ingress.kubernetes.io/router.middlewares: " +
		ns + "-ceffio-redirect-https@kubernetescrd\n"
}

func ingressesManifest(domain string) string {
	// One decision for the whole set: every host of a domain is signed by the
	// same authority. Mixing them would mean some names show a browser warning
	// and others do not, with no rule the operator could state.
	issuer := issuerPour(domain)
	routes := []appRoute{
		{sub: "cloud", namespace: "ceffio-files", service: "nextcloud", port: 80},
		{sub: "keycloak", namespace: "ceffio-identity", service: "keycloak", port: 8080},
		{sub: "office", namespace: "ceffio-office", service: "onlyoffice", port: 80},
		// Talk: the signaling server is reached by the BROWSER (not only
		// internally) — so it must be exposed, and over WebSocket.
		{sub: "spreed", namespace: "ceffio-video", service: "talk-signaling", port: 8081},
		// The vault needs a PUBLIC address, and not for display: OIDC
		// authentication sends the browser back to a return address, which must
		// be reachable and over TLS. A vault only reachable on a clear-text port
		// cannot authenticate a human.
		{sub: "bao", namespace: "ceffio-vault", service: "openbao", port: 8200},
	}
	var sb strings.Builder
	for _, r := range routes {
		// Extra annotations, specific to certain routes.
		//
		// WHY HERE AND NOT IN A FIELD OF appRoute: only one route needs
		// annotations today (the signaling, whose WebSocket connections last for
		// hours). A field in the structure would suggest that all routes have
		// them, while the vast majority do not.
		//
		// WATCH THE YAML: a malformed annotation line or a mis-numbered Fprintf
		// index produces an invalid manifest, and kubectl refuses the WHOLE batch
		// (not just the affected route). The indexes below are explicit for that
		// reason.
		ann := ""
		if r.sub == "spreed" {
			ann = "    traefik.ingress.kubernetes.io/proxy-read-timeout: \"3600\"\n" +
				"    traefik.ingress.kubernetes.io/proxy-send-timeout: \"3600\""
		}
		host := r.sub + "." + domain
		fmt.Fprintf(&sb, `---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: %[1]s
  namespace: %[2]s
  annotations:
    cert-manager.io/cluster-issuer: %[7]s
    traefik.ingress.kubernetes.io/router.middlewares: %[2]s-ceffio-redirect-https@kubernetescrd
%[5]s
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
                  number: %[6]d
`, r.sub, r.namespace, host, r.service, ann, r.port, issuer)
	}
	return sb.String()
}
