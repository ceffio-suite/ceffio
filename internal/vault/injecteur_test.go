// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestRenduInjecteurSeDecoupeSansBlocVide guards against a defect that reached
// production: a comment block placed BEFORE the first `---` of the render.
//
// k8sapi.Appliquer splits on "\n---" and keeps every block whose TrimSpace is
// non-empty. A leading comment block therefore survives the split as a
// document of its own, YAMLToJSON turns it into `null`, and the deployment
// fails with "Object 'Kind' is missing in 'null'" — the agent-injector never
// installs, and with it the whole vault layer.
//
// Verified by re-reading the actual file, not a copy: this is the exact
// artefact that ships.
func TestRenduInjecteurSeDecoupeSansBlocVide(t *testing.T) {
	if strings.TrimSpace(manifesteInjecteur) == "" {
		t.Fatal("the embedded render is empty")
	}

	// Mirror of k8sapi.decouper — the same split, applied to the real content.
	var docs []string
	for _, bloc := range strings.Split(manifesteInjecteur, "\n---") {
		if strings.TrimSpace(bloc) != "" {
			docs = append(docs, bloc)
		}
	}
	if len(docs) == 0 {
		t.Fatal("no document found in the render")
	}

	for i, doc := range docs {
		brut, err := yaml.YAMLToJSON([]byte(doc))
		if err != nil {
			t.Fatalf("document %d is not readable YAML: %v", i, err)
		}
		// THE CHECK THAT MATTERS: a block made only of comments becomes `null`,
		// and that is what broke the deployment.
		if strings.TrimSpace(string(brut)) == "null" {
			premiere := strings.Split(strings.TrimSpace(doc), "\n")[0]
			t.Errorf("document %d is empty (only comments): %q — "+
				"a comment block must not sit before the first `---`", i, premiere)
		}
	}
}

// TestRenduInjecteurContientSesRessources checks the render actually carries
// what the deployer expects to apply, so a truncated file is caught here
// rather than in a cluster.
func TestRenduInjecteurContientSesRessources(t *testing.T) {
	for _, attendu := range []string{
		"ServiceAccount",
		"ClusterRole",
		"ClusterRoleBinding",
		"Service",
		"Deployment",
		"MutatingWebhookConfiguration",
	} {
		if !strings.Contains(manifesteInjecteur, "kind: "+attendu) {
			t.Errorf("the render is missing a %s", attendu)
		}
	}
}
