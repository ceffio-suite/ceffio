// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// NON-REGRESSION TEST OF BATCH B6 — the console's namespace-scoped RBAC.
//
// WHAT IT PROVES: the grant generated from the module registry (AdminRights
// + AdminRolesManifest, the exact YAML kubectl applies) is EQUAL — neither
// wider nor narrower — to the grant the hand-written ClusterRole
// ceffio-admin-namespaces produced before batch B6.
//
// WHY THE LEGACY REFERENCE IS COPIED HERE VERBATIM: it must be frozen. If
// the test derived its expectation from the same code it tests, a rule lost
// in the registry would silently rewrite the expectation and the comparison
// would pass. The reference below is a hand copy of deploy.go as it stood
// before this batch, and any drift between the two sides fails loudly,
// naming the exact (namespace, apiGroup, resource, verb) tuple.
//
// WHY THIS FILE IS package console_test (external): the real end-to-end
// proof needs the REAL registry, and internal/console cannot import
// internal/modules (cycle: internal/modules/console imports internal/console).
// An external test package can import both: console_test → internal/modules
// → internal/modules/console → internal/console is not a cycle, because
// internal/console never imports console_test.
//
// WHAT IT DOES NOT COVER, deliberately: the console's OWN hard-coded rights
// (cluster-scoped reads in the ceffio-admin ClusterRole, the namespace
// create/update/patch rule, and the ceffio-console-occ Role) stayed in
// deploy.go untouched by this batch — they are outside the registry sum, so
// they are outside this comparison. Their non-regression is the git diff of
// deploy.go showing those blocks unchanged.
package console_test

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/ceffio-suite/ceffio/internal/console"
	// Blank import: fills the module registry exactly like cmd/ceffio does,
	// so AdminRights sees the REAL thirteen modules, not fakes.
	_ "github.com/ceffio-suite/ceffio/internal/modules"
)

// legacyNamespaces is the VERBATIM copy of namespacesPlateforme (deploy.go
// before batch B6): the ten namespaces where the RoleBinding named
// ceffio-admin granted the ClusterRole ceffio-admin-namespaces.
var legacyNamespaces = []string{
	"ceffio-system",
	"ceffio-files",
	"ceffio-identity",
	"ceffio-office",
	"ceffio-video",
	"ceffio-mail",
	"ceffio-data",
	"ceffio-vault",
	"ceffio-observability",
	"ceffio-exapps",
}

// legacyRules is the VERBATIM copy of the rules of the ClusterRole
// ceffio-admin-namespaces (deploy.go before batch B6), which the ten
// RoleBindings above applied identically in every platform namespace.
var legacyRules = []rbacv1.PolicyRule{
	{
		APIGroups: []string{""},
		Resources: []string{"pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "serviceaccounts"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
	{
		APIGroups: []string{""},
		Resources: []string{"pods/exec", "pods/log"},
		Verbs:     []string{"get", "create"},
	},
	{
		APIGroups: []string{"apps"},
		Resources: []string{"deployments", "statefulsets", "replicasets"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
	{
		APIGroups: []string{"networking.k8s.io"},
		Resources: []string{"ingresses"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
	{
		APIGroups: []string{"cert-manager.io"},
		Resources: []string{"certificates", "certificaterequests"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
	{
		APIGroups: []string{"rbac.authorization.k8s.io"},
		Resources: []string{"roles", "rolebindings"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
	{
		APIGroups: []string{"postgresql.cnpg.io"},
		Resources: []string{"*"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	},
}

// ruleTuple is one indivisible grant: (namespace, apiGroup, resource, verb).
// The comparison runs on tuples, not on rule blocks: two YAML shapes can
// carry the same privilege (a rule split in two, resources merged), and what
// must not regress is the PRIVILEGE, not its formatting.
type ruleTuple struct{ ns, group, resource, verb string }

func (t ruleTuple) String() string {
	g := t.group
	if g == "" {
		g = `"" (core)`
	}
	return g + "/" + t.resource + " verb " + t.verb + " in " + t.ns
}

// expandTuples flattens rules into their tuple set, under one namespace.
func expandTuples(ns string, rules []rbacv1.PolicyRule) map[ruleTuple]bool {
	out := map[ruleTuple]bool{}
	for _, r := range rules {
		groups := r.APIGroups
		if len(groups) == 0 {
			groups = []string{""}
		}
		for _, g := range groups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					out[ruleTuple{ns, g, res, v}] = true
				}
			}
		}
	}
	return out
}

// legacyReference builds the frozen expectation: every legacy rule, in every
// legacy namespace.
func legacyReference(t *testing.T) map[ruleTuple]bool {
	t.Helper()
	ref := map[ruleTuple]bool{}
	for _, ns := range legacyNamespaces {
		for k := range expandTuples(ns, legacyRules) {
			ref[k] = true
		}
	}
	// DECIDED ADDITION (module capture, lot A3): the module reads its own
	// /status through the API's services/proxy instead of exec'ing into the
	// pod. One tuple, for a GET, in ceffio-video only — and it is what lets
	// B5 remove pods/exec from the capture later.
	ref[ruleTuple{"ceffio-video", "", "services/proxy", "get"}] = true

	// A reference of zero tuples would make the comparison vacuous (and an
	// empty grant would "pass"). The count is the hand-computed product of
	// the frozen lists above: 10 namespaces × 109 tuples per namespace.
	if len(ref) != 1091 {
		t.Fatalf("legacy reference holds %d tuples, expected 1091 (10 namespaces × 109 + 1 decided addition) — the frozen lists above were edited; fix them or fix the count", len(ref))
	}
	return ref
}

// compareTuples fails on ANY asymmetry, naming every offending tuple:
// missing = a privilege LOST (the console breaks on the first click),
// extra = a privilege ADDED (a widened grant nobody decided).
func compareTuples(t *testing.T, label string, want, got map[ruleTuple]bool) {
	t.Helper()
	for k := range want {
		if !got[k] {
			t.Errorf("%s: MISSING privilege (regression): %s", label, k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s: EXTRA privilege (widened grant, nobody decided it): %s", label, k)
		}
	}
	if t.Failed() {
		t.Logf("%s: %d tuples expected, %d produced", label, len(want), len(got))
	}
}

// TestRBACNonRegression is the heart of batch B6: the registry sum equals the
// legacy hand-written grant, tuple by tuple, in both directions.
func TestRBACNonRegression(t *testing.T) {
	want := legacyReference(t)

	rights, err := console.AdminRights()
	if err != nil {
		t.Fatalf("AdminRights: %v", err)
	}

	// Namespace sets compared first: a lost or added namespace would already
	// show up in the tuple comparison, but naming it here makes the failure
	// immediately readable.
	gotNS := map[string]bool{}
	for _, r := range rights {
		if gotNS[r.Namespace] {
			t.Errorf("namespace %q appears twice in AdminRights", r.Namespace)
		}
		gotNS[r.Namespace] = true
	}
	for _, ns := range legacyNamespaces {
		if !gotNS[ns] {
			t.Errorf("namespace %q lost from the grant", ns)
		}
	}
	for ns := range gotNS {
		if !strings.HasPrefix(ns, "ceffio-") {
			t.Errorf("namespace %q gained rights it never had (infrastructure namespaces stay out of the console's reach)", ns)
		}
	}
	if len(gotNS) != len(legacyNamespaces) {
		t.Errorf("grant covers %d namespaces, expected %d", len(gotNS), len(legacyNamespaces))
	}

	// 1. The DATA: AdminRights flattened into tuples.
	gotData := map[ruleTuple]bool{}
	for _, r := range rights {
		for k := range expandTuples(r.Namespace, r.Rules) {
			gotData[k] = true
		}
	}
	compareTuples(t, "AdminRights", want, gotData)

	// 2. The MANIFEST: the exact YAML kubectl applies, parsed back into
	// rbacv1 objects. Comparing only the data would leave the rendering
	// untested — a bug in AdminRolesManifest (wrong namespace, dropped
	// rule) would ship anyway.
	gotYAML, bindings := parseManifest(t, console.AdminRolesManifest(rights))
	compareTuples(t, "AdminRolesManifest YAML", want, gotYAML)

	// Every Role carries its binding, bound to the console's ServiceAccount,
	// and to nothing else: a stray subject would grant these rights to an
	// identity nobody reviewed.
	if len(bindings) != len(gotNS) {
		t.Errorf("manifest holds %d RoleBindings for %d namespaces", len(bindings), len(gotNS))
	}
	for ns, b := range bindings {
		if b.RoleRef.Kind != "Role" || b.RoleRef.Name != "ceffio-console" ||
			b.RoleRef.APIGroup != "rbac.authorization.k8s.io" {
			t.Errorf("RoleBinding in %q references %+v, expected Role ceffio-console", ns, b.RoleRef)
		}
		if len(b.Subjects) != 1 || b.Subjects[0].Kind != "ServiceAccount" ||
			b.Subjects[0].Name != "ceffio-admin" || b.Subjects[0].Namespace != "ceffio-system" {
			t.Errorf("RoleBinding in %q has subjects %+v, expected exactly ServiceAccount ceffio-system/ceffio-admin", ns, b.Subjects)
		}
		if !gotNS[ns] {
			t.Errorf("RoleBinding in %q has no matching Role namespace", ns)
		}
	}
}

// parseManifest splits the generated multi-doc YAML and reads it back into
// typed objects: the flat tuple set of every Role, plus every RoleBinding by
// namespace. It fails on any unexpected kind — the manifest must contain
// nothing but the grant.
func parseManifest(t *testing.T, manifest string) (map[ruleTuple]bool, map[string]rbacv1.RoleBinding) {
	t.Helper()
	roles := map[string][]rbacv1.PolicyRule{}
	bindings := map[string]rbacv1.RoleBinding{}

	docs := strings.Split(strings.TrimSpace(manifest), "\n---\n")
	if len(docs) == 0 || manifest == "" {
		t.Fatal("generated manifest is EMPTY — a test comparing against it would prove nothing")
	}
	for i, doc := range docs {
		var kind struct {
			Kind     string            `json:"kind"`
			Metadata metav1.ObjectMeta `json:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(doc), &kind); err != nil {
			t.Fatalf("manifest doc %d unreadable: %v\n%s", i, err, doc)
		}
		switch kind.Kind {
		case "Role":
			var role rbacv1.Role
			if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
				t.Fatalf("Role doc %d: %v", i, err)
			}
			if role.Name != "ceffio-console" {
				t.Errorf("Role doc %d is named %q, expected ceffio-console", i, role.Name)
			}
			if len(role.Rules) == 0 {
				t.Errorf("Role in %q has zero rules", role.Namespace)
			}
			if roles[role.Namespace] != nil {
				t.Errorf("two Roles generated in %q", role.Namespace)
			}
			roles[role.Namespace] = role.Rules
		case "RoleBinding":
			var rb rbacv1.RoleBinding
			if err := yaml.Unmarshal([]byte(doc), &rb); err != nil {
				t.Fatalf("RoleBinding doc %d: %v", i, err)
			}
			if _, seen := bindings[rb.Namespace]; seen {
				t.Errorf("two RoleBindings generated in %q", rb.Namespace)
			}
			bindings[rb.Namespace] = rb
		default:
			t.Errorf("manifest doc %d has unexpected kind %q — the grant manifest must contain only Roles and RoleBindings", i, kind.Kind)
		}
	}

	// Flatten every Role's rules into one tuple set.
	flat := map[ruleTuple]bool{}
	for ns, rules := range roles {
		for k := range expandTuples(ns, rules) {
			flat[k] = true
		}
	}
	return flat, bindings
}

// TestRBACManifestDeterministic refuses an unstable manifest: two runs must
// produce byte-identical YAML, or equality tests drift and every
// `kubectl apply` rewrites the objects for nothing (map iteration order is
// the usual culprit — AdminRights sorts to kill it).
func TestRBACManifestDeterministic(t *testing.T) {
	r1, err := console.AdminRights()
	if err != nil {
		t.Fatalf("AdminRights (run 1): %v", err)
	}
	r2, err := console.AdminRights()
	if err != nil {
		t.Fatalf("AdminRights (run 2): %v", err)
	}
	m1, m2 := console.AdminRolesManifest(r1), console.AdminRolesManifest(r2)
	if m1 != m2 {
		t.Error("AdminRolesManifest is not deterministic between two runs — the generated YAML must be byte-identical")
	}
	if m1 == "" {
		t.Fatal("AdminRolesManifest produced an empty manifest")
	}
}

// TestRBACLegacyObjectsGoneFromManifest: the pre-batch objects must no
// longer be part of the generated grant. Keeping the name ceffio-admin for
// the RoleBindings would collide with Kubernetes' immutable roleRef (the
// old bindings reference a ClusterRole; the new ones a Role) and every
// upgrade of an existing installation would be rejected.
func TestRBACLegacyObjectsGoneFromManifest(t *testing.T) {
	rights, err := console.AdminRights()
	if err != nil {
		t.Fatalf("AdminRights: %v", err)
	}
	manifest := console.AdminRolesManifest(rights)
	if strings.Contains(manifest, "ceffio-admin-namespaces") {
		t.Error("the generated manifest still references the legacy ClusterRole ceffio-admin-namespaces")
	}
	if strings.Contains(manifest, "kind: ClusterRole") {
		t.Error("the generated manifest contains a ClusterRole: the namespace grant must be namespace-scoped Roles only")
	}
	// The metadata names (NOT the subject: the RoleBinding legitimately
	// binds the ServiceAccount named ceffio-admin) must carry the fresh
	// name — roleRef is immutable, so reusing the old binding name would
	// make every upgrade of an existing installation fail.
	if strings.Contains(manifest, "metadata:\n  name: ceffio-admin\n") {
		t.Error("the generated manifest reuses the name ceffio-admin for a Role or RoleBinding — roleRef is immutable, the fresh objects must carry a fresh name")
	}
}
