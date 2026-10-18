// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ingressDans construit un Ingress minimal dans un namespace.
func ingressDans(ns string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "sonde-" + ns, Namespace: ns},
	}
}

// TestStateIngressComplet : un Ingress dans CHAQUE namespace de la liste →
// installed. C'est l'état d'une installation qui s'est bien passée, et
// c'est celui que la console doit savoir reconnaître — sinon elle annonce
// « unknown » pour une couche qui a fonctionné, ce qui a été observé sur
// une installation vierge.
func TestStateIngressComplet(t *testing.T) {
	var objets []*networkingv1.Ingress
	for _, ns := range nsIngresses {
		objets = append(objets, ingressDans(ns))
	}
	cli := fake.NewSimpleClientset()
	for _, o := range objets {
		if _, err := cli.NetworkingV1().Ingresses(o.Namespace).Create(
			context.Background(), o, metav1.CreateOptions{}); err != nil {
			t.Fatalf("preparation du faux cluster : %v", err)
		}
	}

	etat := (&ingressModule{}).State(context.Background(), module.Env{Kube: cli})
	if etat.Status != module.Installed {
		t.Errorf("status = %q, attendu %q (detail: %s)", etat.Status, module.Installed, etat.Detail)
	}
}

// TestStateIngressAbsent : aucun Ingress nulle part → absent. La couche n'a
// pas tourné, et l'opérateur doit lire « pas installée », pas « à moitié ».
func TestStateIngressAbsent(t *testing.T) {
	cli := fake.NewSimpleClientset()
	etat := (&ingressModule{}).State(context.Background(), module.Env{Kube: cli})
	if etat.Status != module.Absent {
		t.Errorf("status = %q, attendu %q (detail: %s)", etat.Status, module.Absent, etat.Detail)
	}
}

// TestStateIngressPartiel : un namespace sans Ingress → degraded, et le
// Detail NOMME le namespace manquant. Sans ce nom, l'opérateur sait que
// quelque chose manque sans savoir quoi.
func TestStateIngressPartiel(t *testing.T) {
	cli := fake.NewSimpleClientset()
	// Tous sauf le dernier : c'est celui-là qui doit être nommé.
	for _, ns := range nsIngresses[:len(nsIngresses)-1] {
		o := ingressDans(ns)
		if _, err := cli.NetworkingV1().Ingresses(ns).Create(
			context.Background(), o, metav1.CreateOptions{}); err != nil {
			t.Fatalf("preparation du faux cluster : %v", err)
		}
	}

	manquant := nsIngresses[len(nsIngresses)-1]
	etat := (&ingressModule{}).State(context.Background(), module.Env{Kube: cli})
	if etat.Status != module.Degraded {
		t.Errorf("status = %q, attendu %q", etat.Status, module.Degraded)
	}
	if !strings.Contains(etat.Detail, manquant) {
		t.Errorf("detail = %q, doit nommer le namespace manquant %q", etat.Detail, manquant)
	}
}

// TestStateSansClient : pas de client Kubernetes → unknown, jamais installed.
// Un état qui se déclare installé sans avoir rien lu est le pire des cas :
// il fait croire à une couche saine sur une machine où rien n'a tourné.
func TestStateSansClient(t *testing.T) {
	etat := (&ingressModule{}).State(context.Background(), module.Env{})
	if etat.Status != module.Unknown {
		t.Errorf("status = %q, attendu %q", etat.Status, module.Unknown)
	}
}

// TestASurveillerNeLitQueDuLisible borne la liste des objets observés.
//
// POURQUOI CE TEST : le défaut corrigé ici était un état qui lisait un
// Secret de cert-manager, auquel la console n'a pas droit — elle rapportait
// « unknown » sur toutes les installations. Ce test ne peut pas vérifier les
// droits (il n'a pas de cluster), mais il fige la LISTE des namespaces
// observés, pour que l'ajout de cert-manager à nsIngresses se voie.
func TestASurveillerNeLitQueDuLisible(t *testing.T) {
	for _, ns := range nsIngresses {
		if ns == nsCertMgr {
			t.Errorf("nsIngresses contient %q : ce namespace porte la CA et AUCUN Ingress — "+
				"l'y remettre ferait de nouveau échouer l'état", nsCertMgr)
		}
	}
	if len(nsIngresses) != 7 {
		t.Errorf("nsIngresses porte %d namespaces, attendu 7 (le nombre d'Ingress posés par "+
			"redirectionManifest) : la liste a changé, vérifier qu'elle correspond toujours "+
			"au code qui pose les Ingress", len(nsIngresses))
	}
}
