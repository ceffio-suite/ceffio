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
// TLS through cert-manager, the console pod carries NO TLS variable — its
// secrets come from the vault agent, and the DNS provider was never passed to
// it. The stored settings do not exist either, since they were introduced after
// the installation was set up.
//
// WITHOUT THIS FALLBACK the field comes back EMPTY while the cluster serves a
// working Cloudflare solver. An operator opening the page sees the challenge
// unset, and saving the page to change something else REBUILDS the ClusterIssuer
// with no solver — after which every certificate stops renewing, silently, and
// the failure shows up weeks later when the first one expires.
//
// The table includes an http01 case, so the test cannot pass by answering
// "dns01" unconditionally.
func TestLesReglagesViennentDuClusterissuerEnPlace(t *testing.T) {
	cas := []struct {
		nom      string
		solver   map[string]interface{}
		attendu  map[string]string
		explique string
	}{
		{
			nom: "cloudflare in-tree",
			solver: map[string]interface{}{"dns01": map[string]interface{}{
				"cloudflare": map[string]interface{}{
					"apiTokenSecretRef": map[string]interface{}{"name": "ceffio-acme-dns", "key": "api-token"},
				},
			}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "cloudflare"},
		},
		{
			nom: "route53, also in-tree",
			solver: map[string]interface{}{"dns01": map[string]interface{}{
				"route53": map[string]interface{}{"region": "eu-west-3"},
			}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "route53"},
		},
		{
			nom: "a provider nobody has written yet",
			solver: map[string]interface{}{"dns01": map[string]interface{}{
				"infomaniak": map[string]interface{}{"apiTokenSecretRef": map[string]interface{}{"name": "x"}},
			}},
			// The name comes from the SOLVER'S SHAPE, never from a table in the
			// code: that is what makes the mechanism hold for a provider that
			// does not exist today.
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "infomaniak"},
		},
		{
			nom: "a selector accompanies the provider and is not one",
			solver: map[string]interface{}{"dns01": map[string]interface{}{
				"selector": map[string]interface{}{"dnsNames": []interface{}{"*.example.org"}},
				"acmedns":  map[string]interface{}{"accountSecretRef": map[string]interface{}{"name": "a"}},
			}},
			attendu:  map[string]string{"challenge": "dns01", "dns_provider": "acmedns"},
			explique: "`selector` accompanies a provider; reporting it as one would offer a provider that does not exist",
		},
		{
			nom: "the webhook solver, whose provider is nested",
			solver: map[string]interface{}{"dns01": map[string]interface{}{
				"webhook": map[string]interface{}{
					"groupName": "acme.mycompany.com", "solverName": "my-solver",
				},
			}},
			attendu: map[string]string{"challenge": "dns01", "dns_provider": "webhook", "dns_zone": "acme.mycompany.com"},
		},
		{
			nom: "http01: there is no provider to report",
			solver: map[string]interface{}{"http01": map[string]interface{}{
				"ingress": map[string]interface{}{"class": "traefik"},
			}},
			attendu:  map[string]string{"challenge": "http01", "dns_provider": ""},
			explique: "answering dns01 here would offer DNS providers on an installation that uses HTTP-01",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			remplacerClient(t, issuerAvecSolver(c.solver))
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

// issuerAvecSolver builds a ClusterIssuer carrying one solver.
func issuerAvecSolver(solver map[string]interface{}) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]interface{}{"name": "ceffio-letsencrypt"},
		"spec": map[string]interface{}{"acme": map[string]interface{}{
			"server":  "https://acme-v02.api.letsencrypt.org/directory",
			"email":   "admin@ceffio.org",
			"solvers": []interface{}{solver},
		}},
	}}
}
