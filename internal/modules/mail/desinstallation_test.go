// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards the mail module's Uninstall: what it removes, and what it must keep.
//
// WHY THEY EXIST: uninstalling a mail server is not a request to destroy every
// mailbox. The plan says the volume and the vault entries survive, and the
// Nextcloud Mail accounts keep working after a reinstall — a regression here is
// unrecoverable data loss, so the boundary is asserted, not left to the comment
// that documents it.
package mail

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/platformmail"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// clusterComplet builds a cluster where every object Uninstall knows about
// exists, plus the data it must leave alone.
func clusterComplet() *fake.Clientset {
	return fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: nsMail}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: nsMail}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "stalwart-public", Namespace: nsMail}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "mail", Namespace: nsMail}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "stalwart", Namespace: nsMail}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "stalwart-config", Namespace: nsMail}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "stalwart-data", Namespace: nsMail}},
	)
}

// expeFaux stands in for `platformmail` in the uninstall guard.
//
// WHY IT EXISTS: the real appliers connect to the cluster and exec into pods,
// which a fake clientset cannot answer. The seam lets the test assert the part
// that belongs to Uninstall — that the applications are REPOINTED, with the
// sender Resolve chose — without pretending to be Kubernetes.
type expeFaux struct {
	poses []*platformmail.Sender
}

// resoudre answers "no sender": the test's cluster stores no relay settings, so
// the applications are CLEARED rather than pointed at a server that is gone.
func (e *expeFaux) resoudre(context.Context, module.Env) (*platformmail.Sender, error) {
	return nil, nil
}

func (e *expeFaux) appliquer(_ context.Context, s *platformmail.Sender) error {
	e.poses = append(e.poses, s)
	return nil
}

// poserExpediteurFaux installs the fake and restores the real seams after the
// test, so no other test in this package sees it.
func poserExpediteurFaux(t *testing.T) *expeFaux {
	t.Helper()
	faux := &expeFaux{}
	anciens := []any{resoudreExpediteur, appliquerNextcloud, appliquerKeycloak}
	resoudreExpediteur = faux.resoudre
	appliquerNextcloud = faux.appliquer
	appliquerKeycloak = faux.appliquer
	t.Cleanup(func() {
		resoudreExpediteur = anciens[0].(func(context.Context, module.Env) (*platformmail.Sender, error))
		appliquerNextcloud = anciens[1].(func(context.Context, *platformmail.Sender) error)
		appliquerKeycloak = anciens[2].(func(context.Context, *platformmail.Sender) error)
	})
	return faux
}

// TestLaDesinstallationEnleveLeServiceEtGardeLeVolume: the public side and the
// workload go, the mailboxes stay.
func TestLaDesinstallationEnleveLeServiceEtGardeLeVolume(t *testing.T) {
	expe := poserExpediteurFaux(t)
	cs := clusterComplet()
	var sortie bytes.Buffer
	env := module.Env{Domain: "example.com", Kube: cs, Out: &sortie}

	if err := (&mailModule{}).Uninstall(context.Background(), env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	for _, reste := range []struct {
		quoi   string
		existe func() error
	}{
		{"the deployment", func() error {
			_, err := cs.AppsV1().Deployments(nsMail).Get(context.Background(), "stalwart", metav1.GetOptions{})
			return err
		}},
		{"the cluster Service", func() error {
			_, err := cs.CoreV1().Services(nsMail).Get(context.Background(), "stalwart", metav1.GetOptions{})
			return err
		}},
		{"the public Service", func() error {
			// THE LOADBALANCER IS THE ONE THAT MATTERS: left behind, it keeps
			// a load balancer and published ports alive for a server that no
			// longer exists.
			_, err := cs.CoreV1().Services(nsMail).Get(context.Background(), "stalwart-public", metav1.GetOptions{})
			return err
		}},
		{"the Ingress", func() error {
			_, err := cs.NetworkingV1().Ingresses(nsMail).Get(context.Background(), "mail", metav1.GetOptions{})
			return err
		}},
		{"the ServiceAccount", func() error {
			_, err := cs.CoreV1().ServiceAccounts(nsMail).Get(context.Background(), "stalwart", metav1.GetOptions{})
			return err
		}},
		{"the ConfigMap", func() error {
			_, err := cs.CoreV1().ConfigMaps(nsMail).Get(context.Background(), "stalwart-config", metav1.GetOptions{})
			return err
		}},
	} {
		if reste.existe() == nil {
			t.Errorf("%s survived the uninstall", reste.quoi)
		}
	}

	// THE DATA MUST STAY. This is the assertion the whole test exists for.
	if _, err := cs.CoreV1().PersistentVolumeClaims(nsMail).Get(context.Background(),
		"stalwart-data", metav1.GetOptions{}); err != nil {
		t.Errorf("the mail volume was deleted: %v — a reinstall would start empty", err)
	}

	// THE APPLICATIONS ARE REPOINTED, not left on the deleted server: both are
	// applied, and the sender is nil because no relay is stored — "clear" is the
	// honest answer, not a pointer to `mail.<domain>` that no longer answers.
	if len(expe.poses) != 2 {
		t.Fatalf("the platform sender was applied %d time(s); Nextcloud AND Keycloak must "+
			"both be repointed when the server goes", len(expe.poses))
	}
	for i, pose := range expe.poses {
		if pose != nil {
			t.Fatalf("application %d was pointed at %q although no relay is stored; it must "+
				"be cleared", i, pose.Host)
		}
	}

	texte := sortie.String()
	for _, attendu := range []struct{ motif, pourquoi string }{
		{"kept: the volume stalwart-data", "the operator must read that the mailboxes are still there"},
		{"kept: the Nextcloud Mail accounts", "the accounts stay, and the operator must know"},
		{"no external relay stored", "the operator must read where mail now goes"},
	} {
		if !strings.Contains(texte, attendu.motif) {
			t.Errorf("the output does not say %q (%s): %q", attendu.motif, attendu.pourquoi, texte)
		}
	}
}

// TestLaDesinstallationSansClientRefuse: without a Kubernetes client there is
// nothing to describe, and pretending otherwise would report a success that
// removed nothing.
func TestLaDesinstallationSansClientRefuse(t *testing.T) {
	err := (&mailModule{}).Uninstall(context.Background(), module.Env{Domain: "example.com"})
	if err == nil {
		t.Fatal("Uninstall without a Kubernetes client must refuse")
	}
}
