// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/identity/theme"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"sigs.k8s.io/yaml"
)

// manifesteTheme is the deployment with a real theme checksum, parsed.
func manifesteTheme(t *testing.T) map[string]any {
	t.Helper()
	ann := vault.AnnotationsAgent(8, "keycloak", "kv/data/ceffio/keycloak/db",
		vault.GabaritSecret("kv/data/ceffio/keycloak/db", []string{"username", "password"}))
	somme, err := theme.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	brut := manifesteKeycloak("ceffio-identity", ann,
		"quay.io/keycloak/keycloak:26.7.3", "keycloak-db", "keycloak", somme)

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(brut), &doc); err != nil {
		t.Fatalf("the manifest is not valid YAML: %v", err)
	}
	return doc
}

func podSpec(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	return doc["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}

// TestLeThemeEstMonteEnLectureSeule : Keycloak reads /opt/keycloak/themes/<name> at
// startup, and a directory dropped there needs no `kc.sh build`.
//
// READ-ONLY IS THE SECURITY PART: Keycloak only ever reads this directory, so a
// writable mount would add nothing — and would let a compromised process rewrite the
// page every user signs in through.
func TestLeThemeEstMonteEnLectureSeule(t *testing.T) {
	ps := podSpec(t, manifesteTheme(t))

	var monte bool
	for _, c := range ps["containers"].([]any) {
		cc := c.(map[string]any)
		if cc["name"] != "keycloak" {
			continue
		}
		mounts, _ := cc["volumeMounts"].([]any)
		for _, m := range mounts {
			mm := m.(map[string]any)
			if mm["name"] != theme.NomVolume {
				continue
			}
			monte = true
			if chemin := mm["mountPath"]; chemin != "/opt/keycloak/themes/ceffio" {
				t.Errorf("the theme is mounted at %v, expected /opt/keycloak/themes/ceffio: "+
					"anywhere else and Keycloak never looks for it", chemin)
			}
			if ro, _ := mm["readOnly"].(bool); !ro {
				t.Error("the theme is mounted writable: Keycloak only reads it, and a " +
					"writable mount lets a compromised process rewrite the sign-in page")
			}
		}
	}
	if !monte {
		t.Fatal("the theme is not mounted into the keycloak container: every file " +
			"would ship in the binary and never reach the pod")
	}
}

// TestLeVolumeReconstruitLArborescence : a ConfigMap is FLAT and its keys cannot
// contain a slash. Without items[].path, Keycloak would find every file at the theme
// root, look for login/theme.properties, miss it, and render the DEFAULT page — with
// no error in any log.
func TestLeVolumeReconstruitLArborescence(t *testing.T) {
	ps := podSpec(t, manifesteTheme(t))
	vols, _ := ps["volumes"].([]any)

	var items []any
	for _, v := range vols {
		vv := v.(map[string]any)
		if vv["name"] != theme.NomVolume {
			continue
		}
		cm, ok := vv["configMap"].(map[string]any)
		if !ok {
			t.Fatalf("the theme volume is not a configMap: %v", vv)
		}
		if cm["name"] != theme.NomConfigMap {
			t.Errorf("the volume reads %v, expected %v", cm["name"], theme.NomConfigMap)
		}
		items, _ = cm["items"].([]any)
	}

	if len(items) == 0 {
		t.Fatal("the volume declares no items: the flattening would put " +
			"login__resources__css__ceffio.css at the theme root and Keycloak would " +
			"serve its default page with no error anywhere")
	}

	fichiers, err := theme.Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != len(fichiers) {
		t.Errorf("%d items for %d files: a file without an item never reaches the pod",
			len(items), len(fichiers))
	}

	// EVERY ITEM MUST GIVE BACK A REAL PATH. `key` is the flattened name and `path`
	// is where it lands; a mismatch mounts the file somewhere Keycloak does not look.
	var vuThemeProps bool
	for _, it := range items {
		m := it.(map[string]any)
		cle, _ := m["key"].(string)
		chemin, _ := m["path"].(string)
		if strings.Contains(cle, "/") {
			t.Errorf("item key %q contains a slash, which a ConfigMap refuses", cle)
		}
		if strings.Contains(chemin, "__") {
			t.Errorf("item path %q was not rebuilt: it still carries the flattened form",
				chemin)
		}
		if chemin == "login/theme.properties" {
			vuThemeProps = true
		}
	}
	if !vuThemeProps {
		t.Error("no item lands on login/theme.properties: Keycloak finds no theme at " +
			"that path and falls back to the default one silently")
	}
}

// TestLAnnotationRedemarreLePod : in production Keycloak CACHES themes. Replacing the
// files in the volume changes nothing until the process restarts, so the checksum
// goes on the pod template — Kubernetes restarts it by itself when the value changes,
// and, just as importantly, does not when nothing did.
func TestLAnnotationRedemarreLePod(t *testing.T) {
	doc := manifesteTheme(t)
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	ann, _ := tpl["metadata"].(map[string]any)["annotations"].(map[string]any)

	vu, ok := ann["ceffio.io/theme-checksum"].(string)
	if !ok || vu == "" {
		t.Fatal("the pod template carries no ceffio.io/theme-checksum annotation: in " +
			"production Keycloak caches themes, so a changed theme would never reach " +
			"the browser")
	}

	somme, err := theme.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if vu != somme {
		t.Errorf("the annotation says %q, the theme hashes to %q: the pod would restart "+
			"on every install (cutting the login page) or never pick up a change",
			vu, somme)
	}

	// THE SECRETS ANNOTATIONS MUST SURVIVE. The theme annotation is added to a map
	// that the vault injector fills; overwriting instead of merging would strip the
	// injection and Keycloak would start with no database password.
	if _, ok := ann["vault.hashicorp.com/agent-inject"]; !ok {
		t.Error("the vault injector annotations are gone: Keycloak would start with no " +
			"database password and no bootstrap account")
	}
}
