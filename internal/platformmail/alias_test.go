// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// WHY THESE TESTS EXIST: the in-cluster alias is the only reason Nextcloud and
// Keycloak can reach the platform's mail server when the mail module publishes no
// public submission port — and it is written by REWRITING A DEPLOYMENT, which
// restarts the application. A bug here loses the platform's mail silently, or
// restarts an application on every install. Both are asserted.

// clusterFaux is the fake cluster the appliers talk to.
type clusterFaux struct {
	cs kubernetes.Interface
	// sortie is what the shell probe answers ("OUVERT" or "FERME").
	sortie string
	// sondes counts the probes, so a test can assert one did NOT run.
	sondes int
	// occ answers the application's own command, when the applier writes settings.
	// Nil means "this test does not configure the application".
	occ func(args ...string) (string, error)
	// attentes counts the rollouts waited for.
	attentes int
}

func (c *clusterFaux) Executer(_ context.Context, _, pod, conteneur string, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "sh" {
		c.sondes++
		return c.sortie, nil
	}
	// THE APPLIERS RUN `php occ ...`: the fake hands the occ command alone to the
	// fake configuration, so a test asserts the command it cares about.
	if len(args) > 2 && args[0] == "php" && args[1] == "occ" {
		args = args[2:]
	}
	if c.occ != nil {
		return c.occ(args...)
	}
	return "", nil
}

func (c *clusterFaux) ExecuterAvecEntree(_ context.Context, _, pod, conteneur, _ string, args ...string) (string, error) {
	if len(args) > 2 && args[0] == "php" && args[1] == "occ" {
		args = args[2:]
	}
	if c.occ != nil {
		return c.occ(args...)
	}
	return "", nil
}

func (c *clusterFaux) PodDuDeploiement(context.Context, string, string, string) (string, error) {
	return "pod-1", nil
}

func (c *clusterFaux) AttendreDeploiement(context.Context, string, string, time.Duration) error {
	c.attentes++
	return nil
}

func (c *clusterFaux) Kubernetes() kubernetes.Interface { return c.cs }

// clusterMinimal gives the fake cluster one Deployment and nothing else.
func clusterMinimal(t *testing.T, ns, nom string) *clusterFaux {
	t.Helper()
	return &clusterFaux{cs: kubefake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: ns}},
	)}
}

// clusterDuMail adds the mail Ingress and Service the alias step reads.
func clusterDuMail(t *testing.T, ip string, objets ...runtime.Object) *clusterFaux {
	t.Helper()
	base := []runtime.Object{
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: ingressMail, Namespace: nsMail},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{Host: "mail.example.com"}},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: serviceMail, Namespace: nsMail},
			Spec:       corev1.ServiceSpec{ClusterIP: ip},
		},
	}
	return &clusterFaux{cs: kubefake.NewSimpleClientset(append(base, objets...)...)}
}

// deploiementFaux builds the application's Deployment with the given state.
func deploiementFaux(ns, nom string, aliases []corev1.HostAlias, annotations map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: ns, Annotations: annotations},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{HostAliases: aliases},
			},
		},
	}
}

// senderPlateformeFaux is the sender every alias test points at.
func senderPlateformeFaux() *Sender {
	return &Sender{
		Host: "mail.example.com", Port: 465, Security: "ssl",
		User: "noreply@example.com", Password: "app-secret",
		From: "noreply@example.com", FromName: "Ceffio",
	}
}

// relire returns the Deployment as it now stands in the fake cluster.
func relire(t *testing.T, c *clusterFaux, ns, nom string) *appsv1.Deployment {
	t.Helper()
	dep, err := c.cs.AppsV1().Deployments(ns).Get(context.Background(), nom, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading back %s/%s: %v", ns, nom, err)
	}
	return dep
}

// misesAJour counts the Deployment updates the fake cluster recorded.
func misesAJour(c *clusterFaux) int {
	n := 0
	for _, a := range c.cs.(*kubefake.Clientset).Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "deployments" {
			n++
		}
	}
	return n
}

// TestAliasPointsTheApplicationAtTheMailService : the public path is closed, so the
// name must resolve to the Service — without moving the operator's own entry.
func TestAliasPointsTheApplicationAtTheMailService(t *testing.T) {
	occSilencieux(t)
	operateur := corev1.HostAlias{IP: "10.0.0.9", Hostnames: []string{"metrics.local"}}
	c := clusterDuMail(t, "10.43.0.5",
		deploiementFaux(nsFiles, deploiementNextcloud, []corev1.HostAlias{operateur}, nil))
	c.sortie = "FERME"
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), senderPlateformeFaux()); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}

	dep := relire(t, c, nsFiles, deploiementNextcloud)
	attendu := []corev1.HostAlias{
		{IP: "10.0.0.9", Hostnames: []string{"metrics.local"}},
		{IP: "10.43.0.5", Hostnames: []string{"mail.example.com"}},
	}
	if len(dep.Spec.Template.Spec.HostAliases) != len(attendu) {
		t.Fatalf("hostAliases are %v; want %v", dep.Spec.Template.Spec.HostAliases, attendu)
	}
	for i := range attendu {
		if dep.Spec.Template.Spec.HostAliases[i].IP != attendu[i].IP ||
			dep.Spec.Template.Spec.HostAliases[i].Hostnames[0] != attendu[i].Hostnames[0] {
			t.Fatalf("hostAliases are %v; want %v", dep.Spec.Template.Spec.HostAliases, attendu)
		}
	}
	if dep.Annotations[annotationAlias] != "mail.example.com=10.43.0.5" {
		t.Fatalf("the annotation is %q; without it the alias cannot be refreshed or "+
			"removed later", dep.Annotations[annotationAlias])
	}
	if c.attentes != 1 {
		t.Fatalf("%d rollout(s) waited for; the caller execs into this application next, "+
			"so exactly one restart must be awaited", c.attentes)
	}
}

// TestAliasIsNotInstalledWhenThePublicPathWorks : a platform whose node hairpins
// the NAT must not have its applications restarted for nothing.
func TestAliasIsNotInstalledWhenThePublicPathWorks(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.5", deploiementFaux(nsFiles, deploiementNextcloud, nil, nil))
	c.sortie = "OUVERT"
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), senderPlateformeFaux()); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}
	if n := misesAJour(c); n != 0 {
		t.Fatalf("the deployment was updated %d time(s) although the pod already reaches "+
			"the sender", n)
	}
	dep := relire(t, c, nsFiles, deploiementNextcloud)
	if len(dep.Spec.Template.Spec.HostAliases) != 0 {
		t.Fatalf("an alias was installed anyway: %v", dep.Spec.Template.Spec.HostAliases)
	}
}

// TestAliasIsRefreshedWhenTheServiceAddressChanges : a recreated Service gets a new
// ClusterIP, and a stale alias sends the mail to an address nobody answers.
func TestAliasIsRefreshedWhenTheServiceAddressChanges(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.7",
		deploiementFaux(nsFiles, deploiementNextcloud,
			[]corev1.HostAlias{{IP: "10.43.0.5", Hostnames: []string{"mail.example.com"}}},
			map[string]string{annotationAlias: "mail.example.com=10.43.0.5"}))
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), senderPlateformeFaux()); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}
	dep := relire(t, c, nsFiles, deploiementNextcloud)
	if len(dep.Spec.Template.Spec.HostAliases) != 1 ||
		dep.Spec.Template.Spec.HostAliases[0].IP != "10.43.0.7" {
		t.Fatalf("hostAliases are %v; want a single entry pointing at the new ClusterIP",
			dep.Spec.Template.Spec.HostAliases)
	}
	if dep.Annotations[annotationAlias] != "mail.example.com=10.43.0.7" {
		t.Fatalf("the annotation still records %q", dep.Annotations[annotationAlias])
	}
	if c.sondes != 0 {
		// THE PROBE MUST NOT RUN ON A REFRESH: once the alias exists, the name
		// resolves through it and the probe can no longer answer its question.
		t.Fatalf("the refresh probed the pod %d time(s)", c.sondes)
	}
}

// TestAliasIsLeftAloneWhenItIsAlreadyExact : an install replay must not restart the
// application.
func TestAliasIsLeftAloneWhenItIsAlreadyExact(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.5",
		deploiementFaux(nsFiles, deploiementNextcloud,
			[]corev1.HostAlias{{IP: "10.43.0.5", Hostnames: []string{"mail.example.com"}}},
			map[string]string{annotationAlias: "mail.example.com=10.43.0.5"}))
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), senderPlateformeFaux()); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}
	if n := misesAJour(c); n != 0 {
		t.Fatalf("a correct alias was rewritten %d time(s)", n)
	}
	if c.attentes != 0 {
		t.Fatalf("%d rollout(s) waited for although nothing changed", c.attentes)
	}
}

// TestAliasIsRemovedWhenThePlatformUsesAnExternalRelay : an external relay is
// reached by public DNS, and redirecting it to the local mail server would deliver
// the platform's mail to a server the operator did not choose.
func TestAliasIsRemovedWhenThePlatformUsesAnExternalRelay(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.5",
		deploiementFaux(nsFiles, deploiementNextcloud,
			[]corev1.HostAlias{
				{IP: "10.43.0.5", Hostnames: []string{"mail.example.com"}},
				{IP: "10.0.0.9", Hostnames: []string{"metrics.local"}},
			},
			map[string]string{annotationAlias: "mail.example.com=10.43.0.5"}))
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), &Sender{Host: "relay.example.net", Port: 587,
		Security: "starttls", User: "ceffio@example.com", From: "no-reply@example.com"}); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}
	dep := relire(t, c, nsFiles, deploiementNextcloud)
	if len(dep.Spec.Template.Spec.HostAliases) != 1 ||
		dep.Spec.Template.Spec.HostAliases[0].Hostnames[0] != "metrics.local" {
		t.Fatalf("hostAliases are %v; the relay case must keep only the operator's entry",
			dep.Spec.Template.Spec.HostAliases)
	}
	if _, ok := dep.Annotations[annotationAlias]; ok {
		t.Fatal("the alias annotation survived: the next run would try to refresh it")
	}
}

// TestAliasRemovalLeavesAnUnmarkedEntryAlone : an operator's own `mail.<domain>`
// entry must not be deleted by a run that never installed it.
func TestAliasRemovalLeavesAnUnmarkedEntryAlone(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.5",
		deploiementFaux(nsFiles, deploiementNextcloud,
			[]corev1.HostAlias{{IP: "10.0.0.9", Hostnames: []string{"mail.example.com"}}}, nil))
	c.occ = (&occFaux{valeurs: map[string]string{}}).exec
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })

	if err := ApplyNextcloud(context.Background(), &Sender{Host: "relay.example.net", Port: 587,
		Security: "starttls", User: "ceffio@example.com", From: "no-reply@example.com"}); err != nil {
		t.Fatalf("ApplyNextcloud: %v", err)
	}
	dep := relire(t, c, nsFiles, deploiementNextcloud)
	if len(dep.Spec.Template.Spec.HostAliases) != 1 ||
		dep.Spec.Template.Spec.HostAliases[0].IP != "10.0.0.9" {
		t.Fatalf("an unmarked hostAliases entry was removed: %v",
			dep.Spec.Template.Spec.HostAliases)
	}
}

// TestAliasIsSkippedWhenTheApplicationIsNotDeployed : installing the mail module
// before the applications must not create them.
func TestAliasIsSkippedWhenTheApplicationIsNotDeployed(t *testing.T) {
	occSilencieux(t)
	c := clusterDuMail(t, "10.43.0.5")
	remplacer(t, &clientK8s, func() (clientCluster, error) { return c, nil })
	kcadmSilencieux(t, &kcadmFaux{realm: chargeKeycloak(senderPlateformeFaux())})

	if err := ApplyKeycloak(context.Background(), senderPlateformeFaux()); err != nil {
		t.Fatalf("ApplyKeycloak: %v", err)
	}
	if n := misesAJour(c); n != 0 {
		t.Fatalf("%d deployment update(s) on an absent application", n)
	}
	if c.sondes != 0 {
		t.Fatalf("a probe was attempted on an absent application (%d)", c.sondes)
	}
}
