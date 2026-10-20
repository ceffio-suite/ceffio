// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE ROLE THE SIGN-IN PAGE SETTING NEEDS.
//
// The console reads the realm's loginTheme from the RUNNING Keycloak — not from a
// stored value — because someone may have changed it from the Keycloak admin console,
// and a form showing a stored value would lie about what users see. That read is a
// kcadm call inside the keycloak pod, so it needs pods/exec in ceffio-identity.
//
// FOUND IN PRODUCTION, not in review: the form rendered with an empty theme selector
// and the API answered `exec: "kubectl": executable file not found in $PATH` — the
// console container has no kubectl, and its ServiceAccount had no pods/exec outside
// ceffio-files. The declaration was right and the right was missing.

// roleIdentitySource returns the ceffio-console-identity Role document from deploy.go.
func roleIdentitySource(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile("deploy.go")
	if err != nil {
		t.Fatalf("reading deploy.go: %v", err)
	}
	src := string(brut)

	// THE ANCHOR IS THE DOCUMENT, at indentation zero, followed by its name:
	// "ceffio-console-identity" also appears in the RoleBinding and in this test's
	// own text, so a plain substring search reads the wrong object.
	re := regexp.MustCompile(
		`(?m)^kind: Role\nmetadata:\n  name: ceffio-console-identity\n  namespace: ceffio-identity\nrules:\n`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatal("no Role ceffio-console-identity in deploy.go: the settings form for the " +
			"sign-in page reads an empty theme, because the console cannot run kcadm " +
			"inside the keycloak pod")
	}
	// Read up to the end of the document.
	reste := src[loc[1]:]
	if i := strings.Index(reste, "\n---"); i >= 0 {
		reste = reste[:i]
	}
	return reste
}

// TestLeRoleIdentityExisteEtResteEtroit : existence AND scope.
//
// A Role is namespaced by construction, so the risk is not a cluster-wide grant — it
// is a grant WIDER THAN THE ONE THING THAT NEEDED IT. Only pods (get, list) and
// pods/exec (create). The console reads the realm and writes it back through kcadm;
// it never modifies, restarts or deletes a pod itself.
func TestLeRoleIdentityExisteEtResteEtroit(t *testing.T) {
	doc := roleIdentitySource(t)

	// THE RESOURCES ARE A CLOSED LIST. Anything beyond pods and pods/exec is a right
	// nobody will narrow later, granted for a form that shows two dropdowns.
	ressources := regexp.MustCompile(`(?m)^- apiGroups: \[""\]\n  resources: \[(.*)\]`).
		FindAllStringSubmatch(doc, -1)
	if len(ressources) == 0 {
		t.Fatal("the Role declares no rule: it grants nothing and the form stays empty")
	}
	for _, m := range ressources {
		for _, res := range strings.Split(m[1], ",") {
			res = strings.TrimSpace(res)
			if res != "pods" && res != "pods/exec" {
				t.Errorf("the Role grants %q, which the login page setting does not need: "+
					"a grant wider than the one thing that needed it is a grant nobody "+
					"will narrow later", res)
			}
		}
	}

	// WHAT IS RUN INSIDE THE POD IS A COMMAND, so create on pods/exec is required and
	// there is no narrower verb. What must NOT appear is any write on the pods
	// themselves, or a delete anywhere.
	for _, m := range regexp.MustCompile(`(?m)^  verbs: \[(.*)\]`).FindAllStringSubmatch(doc, -1) {
		for _, v := range strings.Split(m[1], ",") {
			switch strings.TrimSpace(v) {
			case "delete", "deletecollection", "update", "patch":
				t.Errorf("the Role grants %q: the console reads the realm and writes it "+
					"through kcadm, it never modifies a pod", strings.TrimSpace(v))
			}
		}
	}

	// A MATCHING BINDING. A Role with no binding looks installed and behaves as if it
	// were not — which is exactly the failure this whole file exists for.
	brut, _ := os.ReadFile("deploy.go")
	src := string(brut)
	lie := regexp.MustCompile(
		`(?m)^kind: RoleBinding\nmetadata:\n  name: ceffio-console-identity\n  namespace: ceffio-identity\n`).
		MatchString(src)
	if !lie {
		t.Error("no RoleBinding for ceffio-console-identity: the Role exists and grants " +
			"nothing, which looks installed and behaves as if it were not")
	}

	// AND THE BINDING POINTS AT IT. A RoleBinding that binds a different Role is the
	// same nothing, with an extra step.
	if !strings.Contains(src, "name: ceffio-console-identity\n  apiGroup: rbac.authorization.k8s.io") {
		t.Error("the RoleBinding does not reference the ceffio-console-identity Role")
	}
}

// TestLeRoleIdentityNeTouchePasAKeycloak : the login page setting has no business
// restarting, scaling or deleting Keycloak. The deployment restarts the pod itself
// through the theme checksum annotation.
func TestLeRoleIdentityNeTouchePasAKeycloak(t *testing.T) {
	doc := roleIdentitySource(t)
	for _, interdit := range []string{"deployments", "statefulsets", "secrets", "pods/log"} {
		if strings.Contains(doc, interdit) {
			t.Errorf("the Role mentions %q: the login page setting reads the realm and "+
				"writes it through kcadm; the pod is restarted by the theme checksum "+
				"annotation, never by the console", interdit)
		}
	}
}

// TestLeRoleIdentityEstDansLeBonNamespace : pods/exec in ceffio-identity, and nowhere
// wider. Binding it to the platform namespace would hand the console command
// execution over the identity layer for a setting that touches two strings.
func TestLeRoleIdentityEstDansLeBonNamespace(t *testing.T) {
	// THE SCOPE IS IN THE ANCHOR, before `rules:` — so it is read from deploy.go
	// rather than from the document body the helper returns.
	brut, err := os.ReadFile("deploy.go")
	if err != nil {
		t.Fatalf("reading deploy.go: %v", err)
	}
	ancre := regexp.MustCompile(
		`(?m)^kind: Role\nmetadata:\n  name: ceffio-console-identity\n  namespace: (\S+)`)
	m := ancre.FindStringSubmatch(string(brut))
	if m == nil {
		t.Fatal("the Role ceffio-console-identity is not declared with an explicit namespace")
	}
	if m[1] != "ceffio-identity" {
		t.Errorf("the Role is scoped to %q, expected ceffio-identity: handing the console "+
			"command execution over another namespace for a setting that touches two "+
			"strings is a right nobody asked for", m[1])
	}
}
