// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console_test

// THE CLUSTERROLE, WHICH NOTHING WAS CHECKING.
//
// Found while adding the monitoring tab's rights: the RBAC non-regression test
// freezes the NAMESPACE grants — the ten Roles built from the modules'
// permissions — and never reads the ClusterRole written by hand in deploy.go.
// The cluster-scoped rights could therefore be widened, or narrowed, without a
// single test noticing.
//
// WHY THAT MATTERS MORE THAN THE NAMESPACE HALF: the ClusterRole is where the
// console's reach beyond its own namespaces is decided — the nodes, the metrics,
// the platform's storage. It is also the half that is written by hand rather
// than derived from what the modules declare, so nothing else constrains it:
// a line added there grants a right to every namespace at once.
//
// THIS TEST IS DELIBERATELY A FROZEN LIST, for the same reason the namespace
// reference is one: adding a right must be a deliberate act, visible in a diff,
// with its reason written beside it. What it checks, in order of importance:
//
//   1. READ-ONLY, ALWAYS. Not one verb may write. The console displays the
//      platform; a widened rule here is how it would start being able to break
//      it, and the monitoring tab touches the platform's DISKS.
//   2. NO SECRETS, at cluster scope. Reading every Secret in every namespace
//      from one rule is the shortest path to leaking the whole platform.
//   3. EXACTLY the resources in the frozen list — no more, no fewer.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// reglesClusterAutorisees is the CLOSED list of cluster-scoped rules.
//
// ONE RULE IS NOT READ-ONLY, and it is the single exception this test allows:
// the console creates the platform's namespaces at installation. It is declared
// HERE, with its reason, rather than tolerated by a loosened check — so the next
// reader sees that an exception exists, which one it is, and why.
//
// WHY EACH ONE IS HERE, because a right without a reason is a right nobody
// dares remove:
//
//	pods, namespaces          the Overview, the certificates, the infrastructure
//	                          tab — they list pods of ALL namespaces
//	deployments               the infrastructure tab shows the layers' deployments
//	ingresses                 the exposed sites
//	certificates              the TLS page
//	nodes                     the MONITORING tab: capacity and pressure conditions
//	metrics.k8s.io            the MONITORING tab: live CPU and memory
//	storageclasses            the MONITORING tab: which provisioner backs a volume
//	longhorn.io               the MONITORING tab: used space and disk fill
var reglesClusterAutorisees = []regleCluster{
	{apiGroup: "", ressources: "pods namespaces", verbes: "get list watch"},
	{apiGroup: "apps", ressources: "deployments", verbes: "get list watch"},
	{apiGroup: "networking.k8s.io", ressources: "ingresses", verbes: "get list watch"},
	{apiGroup: "cert-manager.io", ressources: "certificates", verbes: "get list watch"},
	{apiGroup: "", ressources: "nodes", verbes: "get list watch"},
	{apiGroup: "metrics.k8s.io", ressources: "nodes pods", verbes: "get list"},
	{apiGroup: "storage.k8s.io", ressources: "storageclasses", verbes: "get list"},
	{apiGroup: "longhorn.io", ressources: "volumes nodes replicas engines", verbes: "get list"},

	// THE ONE WRITE, and it is not in the list above because that list is the
	// READ-ONLY one: the console creates the platform's namespaces. Only create,
	// update and patch — NO DELETE, since removing the platform removes the
	// workloads and the volumes, never the namespace. The right is the strict
	// minimum for an action that belongs to no namespace and therefore cannot be
	// granted per namespace.
	{apiGroup: "", ressources: "namespaces", verbes: "create patch update"},
}

// ecrituresClusterAutorisees names the ONLY resource the console may write at
// cluster scope, with the verbs allowed on it.
//
// WHY A SEPARATE LIST AND NOT A BOOLEAN: a monitoring page or a future tab must
// not be able to reuse this exception. Naming the resource and the verbs means
// the test can refuse a write on anything else BY NAME, and can refuse an
// added verb on namespaces itself — `delete` in particular, which would let a
// console tab destroy a namespace.
var ecrituresClusterAutorisees = map[string][]string{
	"namespaces": {"create", "patch", "update"},
}

// regleCluster is one parsed rule of the ClusterRole.
type regleCluster struct {
	apiGroup   string
	ressources string // sorted, space-separated
	verbes     string // sorted, space-separated
}

// TestLeClusterRoleNeDonneQueLaLecture fails on any write verb, anywhere.
//
// THIS IS THE ASSERTION THAT MUST NEVER BE RELAXED. The console administers the
// platform through the namespace Roles, and it is expected to create and delete
// there. At CLUSTER scope it only observes: a write verb here reaches every
// namespace at once, and the monitoring tab it was written for reads disks.
//
// Counter-test: adding "create" to the longhorn.io rule fails this test by name.
func TestLeClusterRoleNeDonneQueLaLecture(t *testing.T) {
	clusterRole := clusterRoleSource(t)

	for _, r := range analyserRegles(t, clusterRole) {
		for _, v := range strings.Fields(r.verbes) {
			if v == "get" || v == "list" || v == "watch" {
				continue
			}
			// THE ONE DECLARED EXCEPTION, checked verb by verb: a write is
			// accepted only on a resource named in ecrituresClusterAutorisees,
			// and only with the verbs listed there. `delete` on namespaces is
			// therefore refused, which is the verb that would let a browser tab
			// destroy a namespace and everything in it.
			if permis, ok := ecrituresClusterAutorisees[r.ressources]; ok {
				for _, p := range permis {
					if v == p {
						goto suivant
					}
				}
			}
			t.Errorf("the ClusterRole grants %q on %s/%s.\n"+
				"At CLUSTER scope the console only OBSERVES, with one declared exception "+
				"(see ecrituresClusterAutorisees): a write verb here reaches every namespace "+
				"at once. The administrative writes belong to the per-namespace Roles, where "+
				"the RBAC non-regression test freezes them.",
				v, r.apiGroup, r.ressources)
		suivant:
		}
	}
}

// TestLeClusterRoleNeLitPasLesSecrets : reading every Secret of every namespace
// from one cluster-scoped rule would leak the whole platform.
//
// The platform's secrets live in OpenBao and in namespace-scoped Secrets; the
// console reads the latter through its namespace Roles, where the scope is
// explicit. A cluster-wide grant would make every future namespace's secrets
// readable the moment it is created, without anyone deciding it.
func TestLeClusterRoleNeLitPasLesSecrets(t *testing.T) {
	clusterRole := clusterRoleSource(t)

	for _, r := range analyserRegles(t, clusterRole) {
		if strings.Contains(r.ressources, "secrets") {
			t.Errorf("the ClusterRole reads %s in apiGroup %q.\n"+
				"A cluster-scoped rule on Secrets makes EVERY namespace's secrets readable, "+
				"including the ones created later, without a decision anyone took. The console "+
				"reads secrets through its namespace Roles, where the scope is named.",
				r.ressources, r.apiGroup)
		}
	}
}

// TestLeClusterRoleEstExactementLaListeFermee : no rule appears or disappears
// without this list changing with it.
//
// Both directions are checked, and they mean opposite things: a MISSING rule
// shows as a page that can no longer read what it displays, an ADDED one as a
// privilege nobody decided. The second is the one that goes unnoticed.
func TestLeClusterRoleEstExactementLaListeFermee(t *testing.T) {
	clusterRole := clusterRoleSource(t)
	obtenues := analyserRegles(t, clusterRole)

	attendues := map[regleCluster]bool{}
	for _, r := range reglesClusterAutorisees {
		r.ressources = trierMots(strings.ReplaceAll(r.ressources, " ", ","))
		r.verbes = trierMots(strings.ReplaceAll(r.verbes, " ", ","))
		attendues[r] = true
	}
	got := map[regleCluster]bool{}
	for _, r := range obtenues {
		got[r] = true
	}
	// The comparisons are on SORTED tuples: a rule listing its resources in the
	// other order means the same thing, and the reference above is written in
	// reading order for a human — normalising here keeps the reference readable
	// while the comparison stays exact.

	for r := range attendues {
		if !got[r] {
			t.Errorf("the ClusterRole no longer carries: apiGroups %q, resources %q, verbs %q.\n"+
				"A right listed above and absent here is a page that can no longer read what it shows.",
				r.apiGroup, r.ressources, r.verbes)
		}
	}
	for r := range got {
		if !attendues[r] {
			t.Errorf("the ClusterRole gained: apiGroups %q, resources %q, verbs %q.\n"+
				"A privilege added to a CLUSTER-scoped rule reaches every namespace at once. "+
				"If it is intended, add it to reglesClusterAutorisees WITH ITS REASON, in the "+
				"same commit — that is what makes the next reader able to judge it.",
				r.apiGroup, r.ressources, r.verbes)
		}
	}
}

// --- Parsing ---------------------------------------------------------------

// clusterRoleSource returns the ClusterRole's rules, read from the SOURCE FILE.
//
// WHY THE SOURCE AND NOT A FUNCTION'S RETURN VALUE: the ClusterRole is written
// inside the manifest string that applyConsoleManifest builds, and that string
// also carries a ServiceAccount, a second ClusterRole for the namespace list,
// bindings and a Deployment. Pulling one document out of it needs a parser, and
// this test's job is to freeze EIGHT RULES, not to parse YAML.
//
// Reading the source has the advantage that matters here: the rules are checked
// where they are written, so a rule added to the manifest is caught even if it
// is never routed through a helper. The anchor is the role's NAME — what
// distinguishes the console's ClusterRole from any other document in the file.
func clusterRoleSource(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile("deploy.go")
	if err != nil {
		t.Fatalf("reading deploy.go: %v", err)
	}
	src := string(brut)

	// THE ANCHOR IS THE DOCUMENT ITSELF, at indentation zero.
	//
	// deploy.go holds four occurrences of "ClusterRole": two documents at
	// indentation zero (the real ClusterRole, and the ClusterRoleBinding's
	// roleRef later on), one indented inside a comment, and its own definition
	// of this test's anchor. Taking the FIRST occurrence found reads a comment;
	// taking the last reads the wrong object. The pattern below pins the one
	// that matters: a line starting with "kind: ClusterRole" and NOTHING BEFORE
	// IT, followed by the console's name.
	re := regexp.MustCompile(`(?m)^kind: ClusterRole\nmetadata:\n  name: ceffio-admin\nrules:\n`)
	m := re.FindStringIndex(src)
	if m == nil {
		t.Fatal("the ceffio-admin ClusterRole was not found at the start of a line in deploy.go.\n" +
			"Four occurrences of that keyword exist and only one is the role; if its shape changed, " +
			"this test would compare nothing while staying green.")
	}
	regles := src[m[1]:]
	// THE RULES END AT THE DOCUMENT SEPARATOR *OR* AT THE CLOSING BACKTICK.
	//
	// Taking only "---" as the end was the first version, and it read HALF the
	// ClusterRole: the rules continued past the first separator, so the rules
	// below it were compared against nothing while the test stayed green on the
	// ones above. The separator is what ends the document in the built manifest;
	// the backtick is what ends it in the SOURCE this test reads, and the two
	// differ.
	fin := strings.Index(regles, "\n---")
	if b := strings.Index(regles, "`"); b >= 0 && (fin < 0 || b < fin) {
		fin = b
	}
	if fin < 0 {
		t.Fatal("the ClusterRole's rules could not be delimited: the parser below would read " +
			"past them and compare another object's rules")
	}
	bloc := regles[:fin]
	// The roles of the console's OTHER objects (the occ Role) must not be read
	// as part of this one: they are namespace-scoped and frozen elsewhere.
	if strings.Contains(bloc, "name: ceffio-console") {
		fin2 := strings.Index(bloc, "name: ceffio-console")
		bloc = bloc[:fin2]
	}
	return bloc
}

// analyserRegles reads the YAML rules back into comparable tuples.
//
// HAND-PARSED rather than decoded: the document is produced by string
// concatenation, and pulling in a YAML decoder for eight rules would add a
// dependency to the package for a test's convenience. The format is fixed by the
// writer, and a change to it fails here — loudly — rather than silently
// comparing nothing.
func analyserRegles(t *testing.T, document string) []regleCluster {
	t.Helper()
	var out []regleCluster
	lignes := strings.Split(document, "\n")

	var courant *regleCluster
	flush := func() {
		if courant != nil {
			out = append(out, *courant)
			courant = nil
		}
	}

	for _, l := range lignes {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "- apiGroups:") {
			flush()
			courant = &regleCluster{apiGroup: crochets(l)}
			continue
		}
		if courant == nil {
			continue
		}
		if strings.HasPrefix(l, "resources:") {
			// SORTED, so two rules listing the same resources in a different
			// order compare equal: the order carries no meaning, and a
			// reordering must not read as a change of rights.
			courant.ressources = trierMots(crochets(l))
		}
		if strings.HasPrefix(l, "verbs:") {
			courant.verbes = trierMots(crochets(l))
		}
	}
	flush()

	if len(out) == 0 {
		t.Fatal("no rule was parsed out of the ClusterRole: the parser read nothing, " +
			"and every assertion below would pass vacuously")
	}
	return out
}

// crochets returns the content of the [a, b] list in a YAML line.
//
// THE QUOTES ARE STRIPPED, and they have to be: the hand-written rules in
// deploy.go are written ["apps"] while the generated ones are written [apps],
// and the two spellings mean the same thing. Comparing them without normalising
// reported a difference of rights where there was only a difference of quoting —
// which would have hidden a real one behind noise.
func crochets(l string) string {
	debut := strings.Index(l, "[")
	fin := strings.LastIndex(l, "]")
	if debut < 0 || fin <= debut {
		return ""
	}
	return strings.NewReplacer(`"`, "", `'`, "").Replace(l[debut+1 : fin])
}

// trierMots sorts a comma-separated list and normalises it to spaces.
func trierMots(s string) string {
	mots := []string{}
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			mots = append(mots, m)
		}
	}
	for i := 0; i < len(mots); i++ {
		for j := i + 1; j < len(mots); j++ {
			if mots[j] < mots[i] {
				mots[i], mots[j] = mots[j], mots[i]
			}
		}
	}
	return strings.Join(mots, " ")
}
