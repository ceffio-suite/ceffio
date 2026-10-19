//go:build integration

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console_test

// THIS TEST RUNS AGAINST A REAL CLUSTER, behind the `integration` tag, because
// what it checks cannot be faked: whether the API PATHS this code uses are the
// ones the API actually serves.
//
// WHY IT IS WORTH THE TAG: every path here is a string, and a wrong one fails
// the same way as a permission problem — an empty section. The unit tests verify
// the parsing and the arithmetic; only a live read proves that
// /apis/longhorn.io/v1beta2/volumes exists and that a cluster answers. Written
// after the last false positive, where a test passed whether or not the code
// under it ran: a test that cannot fail is not evidence, and only the cluster
// can settle these four paths.
//
// WHAT IT DOES NOT DO: it does not assert on VALUES. How many volumes exist,
// how full the disk is — those change with the installation. It asserts on the
// SHAPE: a source answered, the figures are coherent, and no warning names a
// path this cluster does serve.
//
// Run it with:
//
//	KUBECONFIG=~/.kube/config go test -tags integration ./internal/console/ -run TestMonitoringSurClusterReel -v

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/console"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestMonitoringSurClusterReel(t *testing.T) {
	chemin := os.Getenv("KUBECONFIG")
	if chemin == "" {
		t.Skip("KUBECONFIG is not set: this test needs a cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", chemin)
	if err != nil {
		t.Fatalf("kubeconfig unreadable (%s): %v", chemin, err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	srv := console.NouveauPourTest(cli)
	m := srv.CollecterMonitoring(context.Background())

	// 1. The node. Its capacity comes from the core API, which is always there:
	// a cluster that answers nothing here means the code, not the environment.
	if len(m.Noeuds) == 0 {
		t.Fatalf("no node was read: the core API answered nothing.\nWarnings: %s", strings.Join(m.Avertissements, " | "))
	}
	for _, n := range m.Noeuds {
		t.Logf("node %s: %.2f/%.0f cores (%.0f%%), %s/%s memory (%.0f%%)",
			n.Nom, n.CPUUtilise, n.CPUTotal, n.PctCPU(),
			human(n.MemUtilise), human(n.MemTotal), n.PctMem())
		if n.CPUTotal == 0 {
			t.Errorf("node %s: total CPU is zero — the capacity path is wrong", n.Nom)
		}
		if n.MemTotal == 0 {
			t.Errorf("node %s: total memory is zero — the capacity path is wrong", n.Nom)
		}
	}

	// 2. The conditions must be found, and Ready must be among them: it is the
	// one that says the node is usable.
	var vuReady bool
	for _, c := range m.Conditions {
		t.Logf("condition %s = %s (%s)", c.Type, c.Statut, c.Raison)
		if c.Type == "Ready" {
			vuReady = true
		}
	}
	if !vuReady {
		t.Error("the node's Ready condition was not read: the conditions path is wrong")
	}

	// 3. The volumes. This cluster has some; a zero here means the PVC path is
	// wrong, not that the platform is empty.
	if len(m.Volumes) == 0 {
		t.Errorf("no volume was read from a cluster that has PVCs: the path or the namespace filter is wrong")
	}
	var avecUsage int
	for _, v := range m.Volumes {
		etat := "unknown"
		if v.UtiliseConnu {
			etat = human(v.Utilise) + "/" + human(v.Demande)
			avecUsage++
		}
		t.Logf("volume %s/%s: %s (%s, %s)", v.Namespace, v.Nom, etat, v.Classe, v.Etat)
		if v.Demande == 0 {
			t.Errorf("volume %s/%s: requested size is zero — the quantity was not parsed", v.Namespace, v.Nom)
		}
	}

	// 4. THE STORAGE. If a warning mentions "absent", this cluster does not use
	// Longhorn — legitimate elsewhere, but not on this one, and the test has to
	// say so rather than accept an empty page.
	var longhornAbsent bool
	for _, a := range m.Avertissements {
		t.Logf("warning: %s", a)
		if strings.Contains(a, "is absent") {
			longhornAbsent = true
		}
	}
	if longhornAbsent {
		t.Errorf("Longhorn answered nothing on a cluster that uses it: one of the four API paths is wrong")
	}
	if longhornAbsent && avecUsage > 0 {
		t.Errorf("incoherent: the used sizes were read while the storage section reports the CRDs absent")
	}

	// 5. The disk. A zero maximum would render "0% full", the one wrong reading
	// that looks reassuring — so it fails here rather than misleading an
	// operator later.
	if !longhornAbsent {
		if len(m.Disques) == 0 {
			t.Errorf("Longhorn answered but no disk was read: the diskStatus path is wrong")
		}
		for _, d := range m.Disques {
			t.Logf("disk %s: %s used of %s (%.0f%%), %s committed",
				d.Chemin, human(int64(float64(d.Maximum)-float64(d.Disponible))), human(d.Maximum), d.PctUtilise(), human(d.Programme))
			if d.Maximum == 0 {
				t.Errorf("disk %s: maximum is zero — the disc's path is wrong", d.Chemin)
			}
			if d.Disponible > d.Maximum {
				t.Errorf("disk %s: available (%d) exceeds maximum (%d)", d.Chemin, d.Disponible, d.Maximum)
			}
		}
	}

	// 6. And the whole point of the join: the used sizes came back for the
	// volumes that were listed.
	if !longhornAbsent && avecUsage == 0 {
		t.Errorf("no volume has a used figure: the actualSize path or the join is wrong")
	}

	t.Logf("health alert: %v", m.SouciSante())
}

// human renders bytes for a log line.
func human(n int64) string {
	switch {
	case n >= 1<<40:
		return strings.TrimSpace(strings.Join([]string{
			itoa(n / (1 << 40)),
			"." + itoa((n%(1<<40))/(1<<30)),
			"TiB",
		}, ""))
	case n >= 1<<30:
		return itoa(n/(1<<30)) + "." + itoa((n%(1<<30))/(1<<20)) + " GiB"
	case n >= 1<<20:
		return itoa(n/(1<<20)) + " MiB"
	default:
		return itoa(n) + " B"
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
