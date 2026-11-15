// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package website

import (
	"context"
	"io"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/module"
	site "github.com/ceffio-suite/ceffio/internal/website"
)

// domaineTest is the domain the IANA reserves for documentation: the tests
// install the page on a host nobody owns, exactly like a real installation
// installs it on its own.
const domaineTest = "example.com"

func testEnv(cs *fake.Clientset) module.Env {
	return module.Env{Domain: domaineTest, Kube: cs, Out: io.Discard}
}

// fauxControleur plays the part of the Deployment controller, which the fake
// clientset does not have: without it a Deployment created in the fake cluster
// stays at 0 ready replica forever, and Install would wait out its whole
// deadline for a pod that no scheduler will ever create.
//
// The reactor answers the GET with the stored object PLUS the status a real
// cluster reports one image pull later, so that the waiting loop is exercised
// for real instead of being disabled by a hook.
func fauxControleur(cs *fake.Clientset) {
	cs.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		lecture, ok := action.(k8stesting.GetAction)
		if !ok {
			return false, nil, nil
		}
		obj, err := cs.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("deployments"),
			lecture.GetNamespace(), lecture.GetName())
		if err != nil {
			return true, nil, err
		}
		d := obj.(*appsv1.Deployment).DeepCopy()
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation,
			Replicas:           1,
			UpdatedReplicas:    1,
			ReadyReplicas:      1,
			AvailableReplicas:  1,
		}
		return true, d, nil
	})
}

func installer(t *testing.T, cs *fake.Clientset, m *websiteModule) {
	t.Helper()
	if err := m.Install(context.Background(), testEnv(cs)); err != nil {
		t.Fatalf("Install: %v", err)
	}
}

// TestInstallPublieLaPage verifies the whole chain a visitor needs: the
// namespace, the page itself (with its server configuration), the Service, the
// Deployment and the Ingress — plus the hardening promises the pod makes.
//
// It is one test and not six because the chain is the promise: a page missing
// any link of it is not "partly installed", it is not published.
func TestInstallPublieLaPage(t *testing.T) {
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	ctx := context.Background()
	installer(t, cs, &websiteModule{})

	if _, err := cs.CoreV1().Namespaces().Get(ctx, nsSite, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace %s not created: %v", nsSite, err)
	}

	cm, err := cs.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap not created: %v", err)
	}
	for _, p := range site.Paths() {
		if _, ok := cm.Data[p.Cle]; !ok {
			t.Errorf("ConfigMap is missing the published key %q (path %s)", p.Cle, p.Chemin)
		}
	}
	if _, ok := cm.Data[cleNginx]; !ok {
		t.Errorf("ConfigMap is missing the server configuration %q", cleNginx)
	}
	for cle, contenu := range cm.Data {
		if strings.Contains(contenu, "{{") {
			t.Errorf("ConfigMap key %q still contains an unresolved placeholder", cle)
		}
	}
	if !strings.Contains(cm.Data[site.CleIndexFR], "https://"+domaineTest+"/") {
		t.Errorf("the published FR page does not name https://%s/", domaineTest)
	}
	if !strings.Contains(cm.Data[cleNginx], "server_tokens off") {
		t.Errorf("the server configuration does not hide the nginx version")
	}

	svc, err := cs.CoreV1().Services(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Service not created: %v", err)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 80 {
		t.Errorf("Service ports = %+v, want exactly 80", svc.Spec.Ports)
	}
	if svc.Spec.Ports[0].TargetPort != intstr.FromInt32(portHTTP) {
		t.Errorf("Service targetPort = %v, want %d", svc.Spec.Ports[0].TargetPort, portHTTP)
	}

	d, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}
	if got := d.Spec.Template.Annotations["ceffio.io/page-checksum"]; got == "" {
		t.Errorf("the pod template carries no page checksum: a page edit would never roll out")
	}
	pod := d.Spec.Template.Spec
	if len(pod.Containers) != 1 {
		t.Fatalf("%d containers, want exactly one", len(pod.Containers))
	}
	conteneur := pod.Containers[0]
	if conteneur.Image != imagePage {
		t.Errorf("image = %q, want the pinned %q", conteneur.Image, imagePage)
	}
	// The hardening promises: a public page runs a static server, and a static
	// server needs no writable root, no privilege escalation and no token.
	if conteneur.SecurityContext == nil || conteneur.SecurityContext.ReadOnlyRootFilesystem == nil ||
		!*conteneur.SecurityContext.ReadOnlyRootFilesystem {
		t.Errorf("the container does not run with a read-only root filesystem")
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Errorf("the pod automounts a service account token it never uses")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.FSGroup == nil {
		t.Errorf("the pod declares no FSGroup: the writable volumes would not be group-writable")
	}

	ing, err := cs.NetworkingV1().Ingresses(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Ingress not created: %v", err)
	}
	if len(ing.Spec.Rules) != 1 || ing.Spec.Rules[0].Host != domaineTest {
		t.Errorf("Ingress rules = %+v, want the single host %q", ing.Spec.Rules, domaineTest)
	}
	if len(ing.Spec.TLS) != 1 || ing.Spec.TLS[0].SecretName != secretTLS {
		t.Errorf("Ingress TLS = %+v, want the secret %q", ing.Spec.TLS, secretTLS)
	}
	if got := ing.Annotations["traefik.ingress.kubernetes.io/router.entrypoints"]; got != "websecure" {
		t.Errorf("router entrypoints = %q, want websecure (the page must not be served over plain HTTP)", got)
	}
	if got := ing.Annotations["cert-manager.io/cluster-issuer"]; got != ingress.PourDomaine(domaineTest) {
		t.Errorf("cluster issuer = %q, want %q", got, ingress.PourDomaine(domaineTest))
	}
}

// TestInstallEstIdempotent verifies the module contract on the object that
// makes it observable: a second Install must not restart the pod, and it must
// still repair an object edited behind the module's back.
func TestInstallEstIdempotent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	ctx := context.Background()
	m := &websiteModule{}
	installer(t, cs, m)

	avant, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}

	// Re-install: the page did not change, so the pod must not be replaced.
	installer(t, cs, m)
	apres, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment disappeared after re-Install: %v", err)
	}
	if avant.ResourceVersion != apres.ResourceVersion {
		t.Errorf("re-Install rewrote the Deployment (%s -> %s): it must be a no-op",
			avant.ResourceVersion, apres.ResourceVersion)
	}

	// Somebody edited the published page behind the module's back.
	cm, err := cs.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap disappeared: %v", err)
	}
	cm.Data[site.CleIndexFR] = "tampered"
	if _, err := cs.CoreV1().ConfigMaps(nsSite).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("simulating drift: %v", err)
	}

	// Re-install: the drift is reconciled, which is the observable half of
	// the idempotency promise.
	installer(t, cs, m)
	cm, err = cs.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("ConfigMap disappeared after re-Install: %v", err)
	}
	if cm.Data[site.CleIndexFR] == "tampered" {
		t.Errorf("re-Install left the tampered page in place: Install must reconcile, not just tolerate")
	}
}

// TestInstallRedemarreQuandLaPageChange verifies the checksum's whole purpose:
// a page that changes (here: the installation's host moved) rewrites the
// Deployment, which is what makes the pod pick the new ConfigMap up.
func TestInstallRedemarreQuandLaPageChange(t *testing.T) {
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	ctx := context.Background()
	m := &websiteModule{}
	installer(t, cs, m)

	avant, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment not created: %v", err)
	}

	autre := module.Env{Domain: "autre.example.org", Kube: cs, Out: io.Discard}
	if err := m.Install(ctx, autre); err != nil {
		t.Fatalf("Install on the new host: %v", err)
	}

	apres, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Deployment disappeared: %v", err)
	}
	if avant.Spec.Template.Annotations["ceffio.io/page-checksum"] ==
		apres.Spec.Template.Annotations["ceffio.io/page-checksum"] {
		t.Errorf("the page checksum did not change with the host: the pod would keep serving the old page")
	}
	ing, err := cs.NetworkingV1().Ingresses(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Ingress disappeared: %v", err)
	}
	if ing.Spec.Rules[0].Host != "autre.example.org" {
		t.Errorf("Ingress host = %q, want the new host", ing.Spec.Rules[0].Host)
	}
}

// TestEtatSuitLeCluster verifies that State reports what is OBSERVED: absent
// before anything ran, installed once the chain is there, degraded when a link
// is missing, and unknown — never absent — without a client.
func TestEtatSuitLeCluster(t *testing.T) {
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	ctx := context.Background()
	m := &websiteModule{}
	env := testEnv(cs)

	if st := m.State(ctx, env); st.Status != module.Absent {
		t.Errorf("State before Install = %q, want absent", st.Status)
	}
	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if st := m.State(ctx, env); st.Status != module.Installed {
		t.Errorf("State after Install = %q (%s), want installed", st.Status, st.Detail)
	}
	// The Ingress is the link that makes the page reachable: without it the
	// pod still runs, so the honest answer is "degraded", not "absent".
	if err := cs.NetworkingV1().Ingresses(nsSite).Delete(ctx, nomPage, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("simulating a missing route: %v", err)
	}
	st := m.State(ctx, env)
	if st.Status != module.Degraded {
		t.Errorf("State without its Ingress = %q, want degraded", st.Status)
	}
	if !strings.Contains(st.Detail, "Ingress") {
		t.Errorf("State detail = %q, want it to name the missing Ingress", st.Detail)
	}
	if st := m.State(ctx, module.Env{}); st.Status != module.Unknown {
		t.Errorf("State without a Kubernetes client = %q, want unknown (never absent: nobody looked)", st.Status)
	}
}

// TestUninstallSupprimeEtEstRejouable verifies the removal and its
// re-runnability: a console retry after a partial uninstall must not error on
// the object it already deleted.
func TestUninstallSupprimeEtEstRejouable(t *testing.T) {
	cs := fake.NewSimpleClientset()
	fauxControleur(cs)
	ctx := context.Background()
	m := &websiteModule{}
	env := testEnv(cs)

	if err := m.Install(ctx, env); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := m.Uninstall(ctx, env); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if st := m.State(ctx, env); st.Status != module.Absent {
		t.Errorf("State after Uninstall = %q, want absent", st.Status)
	}
	for _, reste := range []func() error{
		func() error {
			_, err := cs.CoreV1().ConfigMaps(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := cs.CoreV1().Services(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := cs.AppsV1().Deployments(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := cs.NetworkingV1().Ingresses(nsSite).Get(ctx, nomPage, metav1.GetOptions{})
			return err
		},
	} {
		if err := reste(); !apierrors.IsNotFound(err) {
			t.Errorf("Uninstall left an object behind (err = %v)", err)
		}
	}
	if err := m.Uninstall(ctx, env); err != nil {
		t.Errorf("second Uninstall must be a no-op, got: %v", err)
	}
}

// TestInstallSansDomaineRefuse: a page without a host would be published on a
// certificate nobody asked for. Install must say so instead of guessing.
func TestInstallSansDomaineRefuse(t *testing.T) {
	cs := fake.NewSimpleClientset()
	m := &websiteModule{}
	err := m.Install(context.Background(), module.Env{Kube: cs, Out: io.Discard})
	if err == nil {
		t.Fatalf("Install accepted an empty domain")
	}
	if !strings.Contains(err.Error(), "domain") {
		t.Errorf("error = %q, want it to name the missing domain", err)
	}
}

// TestInstallSansClientRefuse: without a Kubernetes client there is nowhere to
// write — Install must say so instead of pretending to succeed.
func TestInstallSansClientRefuse(t *testing.T) {
	m := &websiteModule{}
	if err := m.Install(context.Background(), module.Env{Domain: domaineTest, Out: io.Discard}); err == nil {
		t.Fatalf("Install without a Kubernetes client succeeded")
	}
	if err := m.Uninstall(context.Background(), module.Env{Out: io.Discard}); err == nil {
		t.Fatalf("Uninstall without a Kubernetes client succeeded")
	}
}

// TestInfoDeclareLeContrat pins the registry-visible declarations: an Optional
// module that is NOT installed by default, depends on Ingress, and publishes on
// the APEX host — which is exactly why it declares no Service: the catalogue
// renders a Service as <sub>.<domain>, and the apex has no <sub>.
func TestInfoDeclareLeContrat(t *testing.T) {
	info := (&websiteModule{}).Info()
	if info.ID != "website" {
		t.Errorf("ID = %q", info.ID)
	}
	if info.Kind != module.Optional {
		t.Errorf("Kind = %v, want Optional: the page must be requested, never imposed", info.Kind)
	}
	if info.Default {
		t.Errorf("Default = true: an installation nobody asked would publish a public page")
	}
	if len(info.Requires) != 1 || info.Requires[0] != "ingress" {
		t.Errorf("Requires = %v, want exactly [ingress]", info.Requires)
	}
	if len(info.Namespaces) != 1 || info.Namespaces[0] != nsSite {
		t.Errorf("Namespaces = %v, want exactly [%s]", info.Namespaces, nsSite)
	}
	if len(info.Services) != 0 {
		t.Errorf("Services = %v: the page is on the apex host, which a Service entry cannot express", info.Services)
	}
	if strings.TrimSpace(info.Warning) == "" {
		t.Errorf("Warning is empty: publishing a public page is a decision the operator must see")
	}
	for _, p := range info.Permissions {
		if p.Namespace != nsSite {
			t.Errorf("Permission granted in %q: the module must not reach outside its own namespace", p.Namespace)
		}
	}
	if len(info.Permissions) == 0 {
		t.Errorf("no Permissions declared: the console could not install this module")
	}
}
