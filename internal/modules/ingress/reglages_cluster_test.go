// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"context"
	"errors"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// TestLesReglagesViennentDuClusterissuerEnPlace : the settings are derived from
// the issuer cert-manager is actually using.
//
// WHY THIS TEST EXISTS, and what it prevents: on an installation that manages
// TLS through cert-manager and was set up before settings existed, nothing is
// stored and the console pod may carry no TLS variable. Without this read the
// form shows an empty challenge and no provider while the cluster serves a
// working solver, and saving the page to change anything else REBUILDS the
// ClusterIssuer with no solver — after which every certificate stops renewing,
// silently, the failure surfacing weeks later when the first one expires.
//
// HOW IT TELLS A REAL READ FROM A FALLBACK, which is the subtle part: the
// declared default is http01 with an empty provider, so a test expecting that
// answer proves nothing — it passes whether or not the cluster was read. The
// tableau below therefore includes a case whose expected answer DIFFERS from the
// default (a dns01 solver), and a case that pins the ORDER when several solvers
// are listed. An earlier version of this test asserted only cases that the
// default also satisfies; it was counter-tested and passed with the read
// disabled, which is how the flaw was found.
func TestLesReglagesViennentDuClusterissuerEnPlace(t *testing.T) {
	cas := []struct {
		nom      string
		solvers  []map[string]interface{}
		attendu  map[string]string
		explique string
	}{
		{
			nom: "cloudflare in-tree",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"cloudflare": map[string]interface{}{
					"apiTokenSecretRef": map[string]interface{}{"name": "ceffio-acme-dns", "key": "api-token"},
				},
			}}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "cloudflare"},
		},
		{
			nom: "route53, also in-tree",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"route53": map[string]interface{}{"region": "eu-west-3"},
			}}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "route53"},
		},
		{
			nom: "a provider nobody has written yet",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"infomaniak": map[string]interface{}{"apiTokenSecretRef": map[string]interface{}{"name": "x"}},
			}}},
			// The name comes from the SOLVER'S SHAPE, never from a table in the
			// code: that is what makes the mechanism hold for a provider that
			// does not exist today, and for the 72 libdns webhooks.
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "infomaniak"},
		},
		{
			nom: "a selector accompanies the provider and is not one",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"selector": map[string]interface{}{"dnsNames": []interface{}{"*.example.org"}},
				"acmedns":  map[string]interface{}{"accountSecretRef": map[string]interface{}{"name": "a"}},
			}}},
			attendu:  map[string]string{"challenge": "dns01", "dns_provider": "acmedns"},
			explique: "`selector` accompanies a provider; reporting it as one would offer a provider that does not exist",
		},
		{
			nom: "the webhook solver, whose provider is nested",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"webhook": map[string]interface{}{"groupName": "acme.mycompany.com", "solverName": "my-solver"},
			}}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "webhook", "dns_zone": "acme.mycompany.com"},
		},
		{
			// THE CASE THAT MAKES THE OTHERS MEANINGFUL. Its expected answer is
			// NOT the default, so it fails if the cluster is not read.
			nom: "dns01 alone, which the default cannot produce",
			solvers: []map[string]interface{}{{"dns01": map[string]interface{}{
				"cloudflare": map[string]interface{}{
					"apiTokenSecretRef": map[string]interface{}{"name": "ceffio-acme-dns", "key": "api-token"},
				},
			}}},
			attendu:  map[string]string{"challenge": "dns01", "dns_provider": "cloudflare"},
			explique: "http01/empty is the declared default; only a real read answers dns01 here",
		},
		{
			// THE ORDER MATTERS, and this shape is what an existing installation
			// looks like the moment someone adds DNS-01 without removing the
			// HTTP solver. cert-manager tries the solvers in the order they are
			// listed and the first whose selector matches wins, so reporting the
			// FIRST one is faithful — and a page showing the second, or nothing,
			// would disagree with what the cluster does.
			nom: "http01 then dns01: the first solver is the one that applies",
			solvers: []map[string]interface{}{
				{"http01": map[string]interface{}{"ingress": map[string]interface{}{"class": "traefik"}}},
				{"dns01": map[string]interface{}{"cloudflare": map[string]interface{}{
					"apiTokenSecretRef": map[string]interface{}{"name": "ceffio-acme-dns", "key": "api-token"},
				}}},
			},
			attendu: map[string]string{"challenge": "http01", "dns_provider": ""},
		},
		{
			// dns01 FIRST and http01 second: the read must report the DNS solver,
			// whatever the default says.
			nom: "dns01 then http01: the DNS solver is the one that applies",
			solvers: []map[string]interface{}{
				{"dns01": map[string]interface{}{"route53": map[string]interface{}{"region": "eu-west-3"}}},
				{"http01": map[string]interface{}{"ingress": map[string]interface{}{"class": "traefik"}}},
			},
			attendu:  map[string]string{"challenge": "dns01", "dns_provider": "route53"},
			explique: "the default would answer http01/empty, so this case proves the issuer was read",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			remplacerClient(t, issuerAvecSolvers(c.solvers...))
			m := &ingressModule{}
			v, err := m.Current(context.Background(), envSansReglages(), groupeTLS)
			if err != nil {
				t.Fatalf("Current: %v", err)
			}
			for cle, attendu := range c.attendu {
				if v[cle] != attendu {
					t.Errorf("%s = %q, expected %q.\n%s", cle, v[cle], attendu, c.explique)
				}
			}
		})
	}
}

// TestSansClusterissuerLesDefautsSontRendus : no issuer, no variable, nothing
// stored — the declared defaults, and NEVER an invented provider.
//
// A module that guessed `cloudflare` here would write a solver the operator
// never asked for, against a secret that may not exist.
func TestSansClusterissuerLesDefautsSontRendus(t *testing.T) {
	remplacerClient(t, nil)
	m := &ingressModule{}
	v, err := m.Current(context.Background(), envSansReglages(), groupeTLS)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v["challenge"] != "http01" {
		t.Errorf("challenge = %q, expected http01: HTTP-01 is the historical default", v["challenge"])
	}
	if v["dns_provider"] != "" {
		t.Errorf("dns_provider = %q, expected empty: an invented provider would write a solver nobody asked for",
			v["dns_provider"])
	}
}

// TestUnIssuerSansSolverNeFaitPasInventer : the issuer exists but lists no
// solver. The read succeeds and finds nothing, and the caller must still fall
// back to the declared defaults rather than reporting a half-read configuration.
func TestUnIssuerSansSolverNeFaitPasInventer(t *testing.T) {
	remplacerClient(t, issuerAvecSolvers())
	m := &ingressModule{}
	v, err := m.Current(context.Background(), envSansReglages(), groupeTLS)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v["challenge"] != "http01" || v["dns_provider"] != "" {
		t.Errorf("challenge=%q provider=%q, expected the defaults: an issuer with no solver "+
			"must not produce a half-read answer", v["challenge"], v["dns_provider"])
	}
}

// TestAucunClusterNeRendPasLeModuleInutilisable : a workstation, no kubeconfig
// at all — `ceffio module config ingress` must still report the declared
// defaults rather than fail.
func TestAucunClusterNeRendPasLeModuleInutilisable(t *testing.T) {
	ancien := clientK8s
	clientK8s = func() (*k8sapi.Client, error) {
		return nil, errors.New("no kubeconfig")
	}
	t.Cleanup(func() { clientK8s = ancien })

	m := &ingressModule{}
	v, err := m.Current(context.Background(), envSansReglages(), groupeTLS)
	if err != nil {
		t.Fatalf("Current without a cluster: %v — it must fall back to the defaults", err)
	}
	if v["challenge"] != "http01" {
		t.Errorf("challenge = %q, expected http01", v["challenge"])
	}
}

// remplacerClient makes clientK8s answer a fake holding that issuer (nil for
// none), and restores it afterwards.
func remplacerClient(t *testing.T, issuer *unstructured.Unstructured) {
	t.Helper()
	ancien := clientK8s
	clientK8s = func() (*k8sapi.Client, error) {
		objets := []runtime.Object{}
		if issuer != nil {
			objets = append(objets, issuer)
		}
		scheme := runtime.NewScheme()
		// The fake refuses an object whose type is not registered, and the test
		// would then pass for the wrong reason — on an empty read.
		scheme.AddKnownTypeWithName(
			schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "ClusterIssuer"},
			&unstructured.Unstructured{})
		scheme.AddKnownTypeWithName(
			schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "ClusterIssuerList"},
			&unstructured.UnstructuredList{})
		return k8sapi.PourTest(
			kubefake.NewSimpleClientset(),
			dynamicfake.NewSimpleDynamicClient(scheme, objets...),
		), nil
	}
	t.Cleanup(func() { clientK8s = ancien })
}

// envSansReglages is an Env with no store and nothing primed from the
// environment: the case of an installation set up before settings existed.
func envSansReglages() module.Env {
	return module.Env{Domain: "ceffio.org", ModuleID: "ingress"}
}

// issuerAvecSolvers builds a ClusterIssuer carrying the listed solvers, in
// order.
//
// SEVERAL ARE NEEDED to make a case meaningful: an expected answer equal to the
// declared default cannot tell "the cluster was read" from "nothing was found
// and the default answered". Listing dns01 first distinguishes them.
func issuerAvecSolvers(solvers ...map[string]interface{}) *unstructured.Unstructured {
	convertis := make([]interface{}, 0, len(solvers))
	for _, s := range solvers {
		convertis = append(convertis, s)
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]interface{}{"name": "ceffio-letsencrypt"},
		"spec": map[string]interface{}{"acme": map[string]interface{}{
			"server":  "https://acme-v02.api.letsencrypt.org/directory",
			"email":   "admin@ceffio.org",
			"solvers": convertis,
		}},
	}}
}
