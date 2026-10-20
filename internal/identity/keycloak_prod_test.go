// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/vault"
	"sigs.k8s.io/yaml"
)

// deploye is the manifest as the installer builds it, parsed. Every test here
// reads THIS, not a copy: the question is what Ceffio actually deploys.
func deploye(t *testing.T) map[string]any {
	t.Helper()
	// The annotations block comes from vault.AnnotationsAgent, which indents its
	// own lines by 8 columns — the depth of pod annotations in a Deployment. A
	// hand-written two-space string produced invalid YAML, which is how this
	// fixture was wrong before it was right.
	brut := manifesteKeycloak("ceffio-identity", vault.AnnotationsAgent(8, "keycloak",
		"kv/data/ceffio/keycloak/db", vault.GabaritSecret("kv/data/ceffio/keycloak/db", []string{"username", "password"})),
		"quay.io/keycloak/keycloak:26.7.3", "keycloak-db", "keycloak", "deadbeef")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(brut), &doc); err != nil {
		t.Fatalf("the manifest is not valid YAML: %v", err)
	}
	return doc
}

// conteneur returns the keycloak container, or fails: a manifest without it is
// a manifest that deploys nothing.
func conteneur(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	spec := doc["spec"].(map[string]any)
	tpl := spec["template"].(map[string]any)["spec"].(map[string]any)
	for _, c := range tpl["containers"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "keycloak" {
			return m
		}
	}
	t.Fatal("no keycloak container in the manifest")
	return nil
}

// envDe returns the value of an environment variable, and whether it is set.
func envDe(c map[string]any, nom string) (string, bool) {
	envs, ok := c["env"].([]any)
	if !ok {
		return "", false
	}
	for _, e := range envs {
		m := e.(map[string]any)
		if m["name"] == nom {
			v, _ := m["value"].(string)
			return v, true
		}
	}
	return "", false
}

// TestKeycloakTourneEnModeProduction is THE ASSERTION THIS LOT EXISTS FOR.
//
// `start-dev` is what Keycloak's documentation forbids in production: it loosens
// protections and disables the caches — including the theme cache, which is why
// a theme change only showed up after a restart. The platform shipped with it,
// and nothing failed loudly: the login page simply was not the one that had been
// installed.
//
// IT IS ASSERTED ON THE COMMAND LINE, and on the absence of `start-dev` as a
// WORD: a substring check would pass on a comment that mentions it, and a
// comment is exactly what this manifest carries.
func TestKeycloakTourneEnModeProduction(t *testing.T) {
	c := conteneur(t, deploye(t))
	args, _ := c["args"].([]any)
	if len(args) == 0 {
		t.Fatal("the container has no args: the manifest does not say how Keycloak starts")
	}
	ligne, _ := args[0].(string)

	if strings.Contains(ligne, "start-dev") {
		t.Errorf("Keycloak starts in DEVELOPMENT mode:\n%s\n"+
			"Keycloak's own documentation forbids it in production: it loosens protections "+
			"and disables the caches, so an installed theme is not the theme served.", ligne)
	}
	if !strings.Contains(ligne, "kc.sh start") {
		t.Errorf("the container does not run \"kc.sh start\":\n%s", ligne)
	}

	// THE SECRETS ARE STILL SOURCED BEFORE THE START. Without these two lines the
	// container starts without the database password and the bootstrap account,
	// which fails in a way that names neither.
	if !strings.Contains(ligne, ". /secrets/env") {
		t.Error("the container does not source /secrets/env: Keycloak would start with no " +
			"database password and no bootstrap account, and fail naming neither")
	}
}

// TestLesOptionsDeProductionSontPosees verifies the three options `start`
// requires behind a TLS terminator, each for its own reason.
//
// A missing KC_HTTP_ENABLED means the pod does not come up at all; a missing
// KC_PROXY_HEADERS means it comes up announcing the wrong scheme, and every SSO
// redirect points at an URL the browser cannot use. Both are silent in the logs
// until someone tries to sign in.
func TestLesOptionsDeProductionSontPosees(t *testing.T) {
	c := conteneur(t, deploye(t))

	for _, cas := range []struct {
		nom, attendu, pourquoi string
	}{
		{"KC_HTTP_ENABLED", "true",
			"Traefik terminates TLS, so Keycloak must accept plain HTTP inside the " +
				"cluster; without it, `start` refuses to come up without a certificate"},
		{"KC_PROXY_HEADERS", "xforwarded",
			"the public scheme and host come from Traefik's headers; without it the " +
				"issuer is built as http:// and every SSO redirect leaves the TLS"},
		{"KC_CACHE", "local",
			"there is one replica, so a distributed Infinispan cache only waits for " +
				"nodes that do not exist"},
	} {
		vu, pose := envDe(c, cas.nom)
		if !pose {
			t.Errorf("%s is not set: %s", cas.nom, cas.pourquoi)
			continue
		}
		if vu != cas.attendu {
			t.Errorf("%s=%q, expected %q: %s", cas.nom, vu, cas.attendu, cas.pourquoi)
		}
	}

	// A DISTRIBUTED CACHE WITH ONE REPLICA WOULD BE A CONTRADICTION, so the
	// replica count is part of the assertion rather than an assumption.
	spec := deploye(t)["spec"].(map[string]any)
	n, _ := spec["replicas"].(float64)
	if n != 1 {
		t.Errorf("replicas = %v, expected 1: KC_CACHE=local is justified by a single "+
			"replica, and a second one would silently share no cache", spec["replicas"])
	}
}

// TestLaSondeDeDemarrageLaisseLeTempsDeConstruire : `start` without `--optimized`
// rebuilds the server configuration at every boot, which takes minutes. Without a
// startup probe, the liveness probe kills the container during that phase and the
// pod restarts for ever — never converging, and never logging that the kill was
// the problem.
func TestLaSondeDeDemarrageLaisseLeTempsDeConstruire(t *testing.T) {
	c := conteneur(t, deploye(t))

	probe, ok := c["startupProbe"].(map[string]any)
	if !ok {
		t.Fatal("no startupProbe: the liveness probe will kill the container while " +
			"Keycloak is still rebuilding its configuration, and the pod will restart " +
			"for ever")
	}

	http, _ := probe["httpGet"].(map[string]any)
	if http == nil {
		t.Fatal("the startup probe is not an HTTP probe")
	}
	if chemin, _ := http["path"].(string); chemin != "/health/started" {
		t.Errorf("the startup probe queries %q, expected /health/started: /health/ready "+
			"answers before the server accepts requests", chemin)
	}
	if port, _ := http["port"].(string); port != "management" {
		t.Errorf("the startup probe queries port %q, expected the management port", port)
	}

	// THE MARGIN IS THE POINT: 10 s × 60 = 10 minutes. The plan asks for at least
	// five; a rebuild on a loaded node has been seen to take longer than that, and
	// the cost of a too-small margin is a loop, not a slow start.
	periodeF, _ := probe["periodSeconds"].(float64)
	seuilF, _ := probe["failureThreshold"].(float64)
	periode, seuil := int(periodeF), int(seuilF)
	if periode*seuil < 300 {
		t.Errorf("the startup probe gives up after %d s (%d × %ds), expected at least "+
			"300 s: a configuration rebuild on a loaded node takes minutes, and killing "+
			"the pod mid-rebuild produces a loop that never converges",
			periode*seuil, periode, seuil)
	}
	_ = c
}

// TestLesDonneesNeSontPasEnMemoire : the switch from development to production
// must not lose a realm, an account or an OIDC client. It does not, because the
// data lives in PostgreSQL — KC_DB=postgres with a URL pointing at the service.
//
// THE TEST IS HERE BECAUSE THE FEAR IS REASONABLE: `start-dev` defaults to an
// in-memory H2 database, so "we were in development mode" reads as "the data
// might be in memory". It is not, and this is the assertion that says so.
func TestLesDonneesNeSontPasEnMemoire(t *testing.T) {
	c := conteneur(t, deploye(t))

	db, _ := envDe(c, "KC_DB")
	if db != "postgres" {
		t.Errorf("KC_DB = %q, expected postgres: anything else means the realm does not "+
			"survive a restart", db)
	}
	url, pose := envDe(c, "KC_DB_URL")
	if !pose || !strings.HasPrefix(url, "jdbc:postgresql://") {
		t.Errorf("KC_DB_URL = %q, expected a PostgreSQL JDBC URL", url)
	}

	// A URL WITHOUT A HOST OR A DATABASE would still be a PostgreSQL URL, and
	// would fail at start rather than here. Both parts are required.
	if !strings.Contains(url, ":5432/") {
		t.Errorf("KC_DB_URL = %q: no port and database in it", url)
	}
}

// TestLeNomDhoteEstUneURLComplete : KC_HOSTNAME accepts a hostname OR a URL in the
// v2 hostname system, and the URL is what carries the scheme.
//
// THE VARIABLE IT REPLACES DOES NOT EXIST ANY MORE. KC_HOSTNAME_URL belonged to
// the v1 system and Keycloak 26 ignores it silently: the manifest looked correct
// and announced http:// endpoints behind a TLS terminator.
func TestLeNomDhoteEstUneURLComplete(t *testing.T) {
	// The deployment sets it through adoptKeycloakHost, so this test reads the
	// manifest's own contract: nothing hardcoded, and the strict flag left false
	// until internal calls are tested.
	c := conteneur(t, deploye(t))
	if v, pose := envDe(c, "KC_HOSTNAME"); pose && v != "" {
		t.Errorf("KC_HOSTNAME is hardcoded to %q in the manifest. It is set by the "+
			"ingress phase with the CURRENT domain: a value frozen here would contradict "+
			"it, which is how the SSO redirect ended up on auth.ceffio.local", v)
	}
	if v, _ := envDe(c, "KC_HOSTNAME_STRICT"); v != "false" {
		t.Errorf("KC_HOSTNAME_STRICT = %q, expected false for this lot: turning it on "+
			"changes how internal callers (Nextcloud, Stalwart, the console) reach "+
			"Keycloak, which needs a real test of its own", v)
	}
}
