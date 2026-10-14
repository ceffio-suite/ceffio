// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package ingress — fixes born from the real deployment behind OPNsense.
//
// This file adds what was missing for a Ceffio deployment to be usable behind
// an upstream proxy that terminates TLS (the normal case: the firewall exposes
// *.domain, Traefik only sees HTTP).
//
// Without these fixes, the applications generate redirects to http:// and to
// the old domain: the service answers, but navigation breaks.
// Observed in production: keycloak redirected to http://keycloak.demo.local
// from an https client.
package ingress

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// candidatsAnciensDomaines lists the domains an installation may have carried
// before its migration. We remove them from the configurations when adopting a
// new domain: otherwise the redirects keep pointing at them (lived case:
// demo.local stayed hardcoded in Keycloak, Nextcloud, Element and Synapse after
// the switch to *.ceffio.example.com).
var candidatsAnciensDomaines = []string{
	"demo.local",
	"ceffio.local",
}

// ProxyAmont configures Traefik to trust the X-Forwarded-Proto header coming
// from the upper proxy (OPNsense, Caddy, nginx...).
//
// WHY this is necessary, and why elsewhere it does not work:
// When a firewall terminates TLS and forwards in HTTP, Traefik announces to the
// applications "the request arrived over HTTP". Applications that honor this
// header correctly (Keycloak, Nextcloud, ONLYOFFICE) then build their redirects
// to http://, and the user switches to clear text or lands on a nonexistent
// URL. Setting KC_HOSTNAME_URL to https is NOT enough: the redirect proto comes
// from the header, not from that variable.
//
// The fix therefore happens in Traefik, the only place where the information is
// reliably available, and not in each application.
//
// SECURITY: forwardedHeaders.insecure trusts the incoming header. That is only
// acceptable if Traefik is reachable ONLY from a trusted network (the upstream
// firewall). On a directly exposed machine, an explicit trusted-IP list would be
// required.
func ProxyAmont(ctx context.Context) error {
	manifest := fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    additionalArguments:
      - "--entryPoints.web.forwardedHeaders.insecure=true"
      - "--entryPoints.websecure.forwardedHeaders.insecure=true"
`)
	if err := apply(ctx, manifest); err != nil {
		return err
	}
	if err := rolloutRestart(ctx, "deploy/traefik@kube-system"); err != nil {
		return err
	}
	fmt.Println("✓ Traefik configured for an upstream proxy (X-Forwarded-Proto honored)")
	return nil
}

// NettoyerAncienDomaine removes an old domain from the application
// configurations, replacing it with the current domain.
//
// Targets: the ConfigMaps and environment variables where an old name can stay
// hardcoded. We replace it wherever it appears, then restart the concerned
// deployments. Idempotent: if the old domain is no longer present, nothing is
// modified.
func NettoyerAncienDomaine(ctx context.Context, ancien, nouveau string) error {
	if ancien == "" || nouveau == "" || ancien == nouveau {
		return nil
	}
	fmt.Printf("Cleaning the old domain %s -> %s...\n", ancien, nouveau)

	// 1) ConfigMaps: Element, Synapse (+ any other that would contain the name).
	cibles := []struct{ ns, cm, cle string }{}
	for _, c := range cibles {
		data, err := cmData(ctx, c.ns, c.cm, c.cle)
		if err != nil || !strings.Contains(data, ancien) {
			continue
		}
		data = strings.ReplaceAll(data, ancien, nouveau)
		if err := applyCMData(ctx, c.ns, c.cm, c.cle, data); err != nil {
			return fmt.Errorf("%s/%s : %w", c.ns, c.cm, err)
		}
		fmt.Printf("  ✓ %s/%s updated\n", c.ns, c.cm)
	}

	// 2) Deployments: environment variables containing the old name.
	//    Keycloak is the critical case — its KC_HOSTNAME points to the public domain.
	deps := []struct{ ns, nom string }{
		{"ceffio-identity", "keycloak"},
	}
	for _, d := range deps {
		out, err := k8s.Command(ctx, "kubectl", "get", "deploy", d.nom, "-n", d.ns,
			"-o", "jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}={.value}{\"\\n\"}{end}").Output()
		if err != nil {
			continue
		}
		var args []string
		for _, ligne := range strings.Split(string(out), "\n") {
			ligne = strings.TrimSpace(ligne)
			if ligne == "" || !strings.Contains(ligne, ancien) {
				continue
			}
			cle := strings.SplitN(ligne, "=", 2)[0]
			args = append(args, cle+"="+strings.ReplaceAll(ligne[len(cle)+1:], ancien, nouveau))
		}
		if len(args) == 0 {
			continue
		}
		kargs := append([]string{"set", "env", "-n", d.ns, "deploy/" + d.nom}, args...)
		if out, err := k8s.Command(ctx, "kubectl", kargs...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s/%s : %w : %s", d.ns, d.nom, err, string(out))
		}
		fmt.Printf("  ✓ %s/%s: %s\n", d.ns, d.nom, strings.Join(args, ", "))
	}

	// 3) Nextcloud: occ, several keys may cite the old name.
	for _, cmd := range [][]string{
		{"config:system:get", "overwritehost"},
		{"config:system:get", "overwrite.cli.url"},
	} {
		res, err := k8s.Command(ctx, "kubectl", "exec", "-n", "ceffio-files",
			"deploy/nextcloud", "--", "su", "-s", "/bin/sh", "www-data", "-c",
			"php occ "+strings.Join(cmd, " ")).Output()
		if err == nil && strings.Contains(string(res), ancien) {
			fmt.Printf("  · Nextcloud: %s still contains the old domain\n", cmd[1])
		}
	}

	// 4) Restart what was modified.
	return nil
}

// DomainesConnus returns the list of old domains to clean up for a given target
// domain (all those that are not the current domain).
func DomainesConnus(courant string) []string {
	var out []string
	for _, d := range candidatsAnciensDomaines {
		if d != courant {
			out = append(out, d)
		}
	}
	return out
}
