// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package capture

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestAucunDroitSurLaBase is the non-regression test of lot B5, and it is the
// whole point of the relay: the capture used to exec into the PostgreSQL pod to
// read the recording state and the room language. Both come from the relay's
// notification now, so the Role, its binding and the exec handshake in
// ceffio-data must be GONE — not merely unused.
//
// A rule left in a manifest is a rule granted: the namespace's administrator
// reads it, and the next person to need a query will use it.
func TestAucunDroitSurLaBase(t *testing.T) {
	manifeste := manifesteCompteEtDroits()

	if strings.Contains(manifeste, nsData) {
		t.Errorf("the manifest still mentions %s:\n%s", nsData, manifeste)
	}
	// THE DEPOSIT IS STILL AN EXEC in the Nextcloud pod: B4 established that the
	// OCS store route refuses a .srt (only ogg, ogv, mp4, webm and mkv), so this
	// right stays on purpose.
	if !strings.Contains(manifeste, "namespace: "+nsFiles) {
		t.Errorf("no right in %s: the deposit would fail", nsFiles)
	}
	if !strings.Contains(manifeste, `resources: ["pods/exec"]`) {
		t.Errorf("no pods/exec rule:\n%s", manifeste)
	}
	if !strings.Contains(manifeste, "kind: RoleBinding") || !strings.Contains(manifeste, "kind: Role") {
		t.Errorf("the identity has no binding:\n%s", manifeste)
	}
}

// TestLePodNePortePlusLaVariableDeBase: a variable nothing reads is a sign that
// the code that read it may still be somewhere. CEFFIO_DB_NAMESPACE is gone.
func TestLePodNePortePlusLaVariableDeBase(t *testing.T) {
	manifeste := manifesteDeploiement("exemple.org", annotationsCapture())

	// THE ENVIRONMENT IS PARSED, NOT SEARCHED: a comment naming the variable
	// would make a text search pass or fail for the wrong reason.
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(manifeste), &doc); err != nil {
		t.Fatalf("the manifest is not valid YAML: %v", err)
	}
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	env := tpl["containers"].([]any)[0].(map[string]any)["env"].([]any)

	vus := map[string]bool{}
	for _, e := range env {
		vus[e.(map[string]any)["name"].(string)] = true
	}
	if vus["CEFFIO_DB_NAMESPACE"] {
		t.Error("the pod still carries CEFFIO_DB_NAMESPACE: the database is no longer read")
	}
	// THE ENVIRONMENT IS THE CONTRACT THE IMAGE EXPECTS, and nothing else.
	for _, nom := range []string{"CEFFIO_DOMAIN", "CEFFIO_HPB_URL", "CEFFIO_NEXTCLOUD_URL",
		"CEFFIO_NC_NAMESPACE", "CEFFIO_THREADS"} {
		if !vus[nom] {
			t.Errorf("variable %s manquante", nom)
		}
	}
	if len(vus) != 5 {
		t.Errorf("the pod carries %d variables, expected 5: %v", len(vus), vus)
	}
}

// TestLesAnnotationsSontCellesDuCoffre catches a defect this lot introduced and
// that a "does it contain EXTRA" check would not: after removing an argument
// from the format, the annotation placeholder pointed at the PVC name, so the
// pod carried no vault annotations at all — and started without secrets.
func TestLesAnnotationsSontCellesDuCoffre(t *testing.T) {
	annotations := annotationsCapture()
	manifeste := manifesteDeploiement("exemple.org", annotations)

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(manifeste), &doc); err != nil {
		t.Fatalf("the manifest is not valid YAML: %v", err)
	}
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	ann := tpl["metadata"].(map[string]any)["annotations"].(map[string]any)

	if ann["vault.hashicorp.com/agent-inject"] != "true" {
		t.Errorf("the pod does not ask for injection: %v", ann)
	}
	if ann["vault.hashicorp.com/role"] != "capture" {
		t.Errorf("vault role = %v, expected the module's ID", ann["vault.hashicorp.com/role"])
	}
	if _, ok := ann["vault.hashicorp.com/agent-inject-secret-env"]; !ok {
		t.Errorf("no env file injected: %v", ann)
	}
	// AND THE PVC IS NOT AN ANNOTATION: the two placeholders are distinct.
	spec := tpl["spec"].(map[string]any)
	vols := spec["volumes"].([]any)
	claim := vols[0].(map[string]any)["persistentVolumeClaim"].(map[string]any)["claimName"]
	if claim != pvcNom {
		t.Errorf("claimName = %v, expected %v", claim, pvcNom)
	}
}

// TestLaPolitiqueReseauNOuvreQueVersLEnregistreur: the capture accepts
// notifications from one source — the relay, labelled app=talk-recording in this
// namespace — and from nothing else.
func TestLaPolitiqueReseauNOuvreQueVersLEnregistreur(t *testing.T) {
	var p map[string]any
	if err := yaml.Unmarshal([]byte(manifestePolitiqueReseau()), &p); err != nil {
		t.Fatalf("the policy is not valid YAML: %v", err)
	}
	if p["kind"] != "NetworkPolicy" {
		t.Fatalf("kind = %v", p["kind"])
	}
	spec := p["spec"].(map[string]any)
	if sel := spec["podSelector"].(map[string]any)["matchLabels"].(map[string]any); sel["app"] != nom {
		t.Errorf("the policy selects %v, expected the capture pod (%s)", sel, nom)
	}
	types := spec["policyTypes"].([]any)
	if len(types) != 1 || types[0] != "Ingress" {
		t.Errorf("policyTypes = %v : egress must not be restricted (the capture reaches the signaling and deposits)", types)
	}
	regles := spec["ingress"].([]any)
	if len(regles) != 1 {
		t.Fatalf("%d ingress rule(s), expected one", len(regles))
	}
	regle := regles[0].(map[string]any)
	source := regle["from"].([]any)[0].(map[string]any)["podSelector"].(map[string]any)["matchLabels"].(map[string]any)
	if source["app"] != "talk-recording" {
		t.Errorf("the source is %v, expected the recorder pod", source)
	}
	port := regle["ports"].([]any)[0].(map[string]any)
	if port["port"].(float64) != 8080 {
		t.Errorf("port = %v, expected 8080", port["port"])
	}
}
