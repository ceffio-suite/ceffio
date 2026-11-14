// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on what the two Services publish and on the names the mail Ingress
// serves.
//
// WHY THESE TESTS EXIST: `clients_externes` is the only setting whose effect is
// a port list, and a wrong list has no local symptom — the server is healthy,
// the checks that dial from inside the cluster pass, and only a user on another
// network discovers that 993 was never published. The assertion is therefore on
// the REAL manifest that Install applies, not on a copy of it.
package mail

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"
)

type serviceYAML struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Type                  string `json:"type"`
		ExternalTrafficPolicy string `json:"externalTrafficPolicy"`
		Ports                 []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
}

func servicesDuManifeste(t *testing.T, cfg Reglages) map[string]serviceYAML {
	t.Helper()
	services := map[string]serviceYAML{}
	for _, doc := range strings.Split(manifesteServices(cfg), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var svc serviceYAML
		if err := yaml.Unmarshal([]byte(doc), &svc); err != nil {
			t.Fatalf("unreadable Service manifest: %v", err)
		}
		services[svc.Metadata.Name] = svc
	}
	return services
}

// numeros renders "smtp:25,submission:465" so the comparison ignores order.
func numeros(svc serviceYAML) string {
	var b strings.Builder
	for _, p := range svc.Spec.Ports {
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString(p.Name)
		b.WriteString(":")
		b.WriteString(strconv.Itoa(p.Port))
	}
	return b.String()
}

// TestLesPortsPublicsSuiventLesClientsExternes: with external clients, 465 and
// 993 are published; without them, only 25 — and the administration port is
// never published, in either case.
func TestLesPortsPublicsSuiventLesClientsExternes(t *testing.T) {
	cas := []struct {
		nom     string
		cfg     Reglages
		attendu string
	}{
		{"clients externes", Reglages{ClientsExternes: true}, "smtp:25,submission:465,imaps:993"},
		{"cluster seulement", Reglages{ClientsExternes: false}, "smtp:25"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			services := servicesDuManifeste(t, c.cfg)
			public, ok := services["stalwart-public"]
			if !ok {
				t.Fatalf("stalwart-public is missing from the manifest: %v", services)
			}
			if obtenu := numeros(public); obtenu != c.attendu {
				t.Fatalf("stalwart-public publishes %s, expected %s", obtenu, c.attendu)
			}
			// THE INTERNAL SERVICE DOES NOT DEPEND ON THE SETTING: it always
			// carries every port, so changing the exposure never recreates the
			// pod or surprises an in-cluster client.
			if obtenu := numeros(services["stalwart"]); obtenu != "smtp:25,submission:465,imaps:993,http:8080" {
				t.Fatalf("stalwart publishes %s, expected every container port", obtenu)
			}
		})
	}
}

// TestLeServicePublicPreserveLAdresseCliente: LoadBalancer + Local. A ClusterIP
// would not be reachable from a port forward; a Cluster policy masquerades the
// source address, and Stalwart's auto-ban then bans the proxy (POC 9.D).
func TestLeServicePublicPreserveLAdresseCliente(t *testing.T) {
	public := servicesDuManifeste(t, Reglages{ClientsExternes: true})["stalwart-public"]
	if public.Spec.Type != "LoadBalancer" {
		t.Errorf("stalwart-public type = %q, expected LoadBalancer", public.Spec.Type)
	}
	if public.Spec.ExternalTrafficPolicy != "Local" {
		t.Errorf("stalwart-public externalTrafficPolicy = %q, expected Local", public.Spec.ExternalTrafficPolicy)
	}
	// The administration port never leaves the cluster, whatever the settings.
	for _, p := range public.Spec.Ports {
		if p.Port == 8080 {
			t.Fatal("stalwart-public publishes 8080: the administration interface must stay behind the Ingress")
		}
	}
}

// TestHotesIngress: the mail host is the configured domain, the three discovery
// names hang off the platform domain, and a duplicate is not rendered twice.
func TestHotesIngress(t *testing.T) {
	cas := []struct {
		nom        string
		plateforme string
		domaine    string
		attendu    string
	}{
		{"domaine distinct", "example.com", "mail.example.com",
			"mail.example.com,autoconfig.example.com,autodiscover.example.com,mta-sts.example.com"},
		{"domaine égal au nom déduit", "example.com", "example.com",
			"example.com,autoconfig.example.com,autodiscover.example.com,mta-sts.example.com"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			obtenu := strings.Join(hotesIngress(c.plateforme, c.domaine), ",")
			if obtenu != c.attendu {
				t.Fatalf("hosts = %s, expected %s", obtenu, c.attendu)
			}
		})
	}
	// Every host must have its own rule, all pointing at the same backend: a
	// rule missing here is a client that cannot find its settings.
	regles := rendreReglesIngress(hotesIngress("example.com", "mail.example.com"))
	for _, hote := range hotesIngress("example.com", "mail.example.com") {
		if !strings.Contains(regles, "host: "+hote+"\n") {
			t.Errorf("the rule for %s is missing from the Ingress: %s", hote, regles)
		}
	}
}

// TestAppliquerLesServicesDeuxFoisNEcritPas: a second install writes nothing.
//
// WHY THIS TEST EXISTS: `Install` is replayed on every upgrade by
// `RejouerInstalles`, and a write per replay bumps the Services' generation and
// restarts the pods that consume them. `Appliquer` probes with a `create` — an
// existing object answers `AlreadyExists`, which writes nothing — then compares
// and calls `update` only when a field differs. This test installs a reactor
// that counts the `update` calls: the second pass must produce none.
func TestAppliquerLesServicesDeuxFoisNEcritPas(t *testing.T) {
	cfg := Reglages{ClientsExternes: true}

	// THE TYPED CLUSTER IS SEEDED FROM THE MANIFEST ITSELF: `applyService` reads
	// the Services back through the typed client, and an empty fake cluster would
	// fail that read before the second apply even starts.
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	cs := kubefake.NewSimpleClientset()
	for _, doc := range strings.Split(manifesteServices(cfg), "\n---\n") {
		var svc corev1.Service
		if err := yaml.Unmarshal([]byte(doc), &svc); err != nil {
			t.Fatalf("unreadable Service: %v", err)
		}
		if svc.Name == "" {
			continue
		}
		if _, err := cs.CoreV1().Services(svc.Namespace).Create(context.Background(), &svc, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seeding %s: %v", svc.Name, err)
		}
	}
	dyn := dynamicfake.NewSimpleDynamicClient(scheme)

	ancien := clientK8s
	clientK8s = func() (*k8sapi.Client, error) { return k8sapi.PourTest(cs, dyn), nil }
	t.Cleanup(func() { clientK8s = ancien })

	if err := applyService(context.Background(), cfg); err != nil {
		t.Fatalf("first applyService: %v", err)
	}

	// SECOND PASS: the objects now exist, exactly as in a real cluster. The
	// reactors keep the fake honest: a create answers AlreadyExists as the API
	// would, and every update is recorded instead of applied.
	var ecritures []string
	dyn.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		creation := action.(ktesting.CreateAction)
		nom := ""
		if objet, ok := creation.GetObject().(metav1.Object); ok {
			nom = objet.GetName()
		}
		return true, nil, apierrors.NewAlreadyExists(
			schema.GroupResource{Resource: action.GetResource().Resource}, nom)
	})
	dyn.PrependReactor("update", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		ecritures = append(ecritures, action.GetResource().Resource)
		return true, nil, nil
	})

	if err := applyService(context.Background(), cfg); err != nil {
		t.Fatalf("second applyService: %v", err)
	}
	if len(ecritures) != 0 {
		t.Fatalf("the second run updated %v: re-installing must not write", ecritures)
	}
}
