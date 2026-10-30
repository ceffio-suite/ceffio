// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/sbom"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// TestLesPodsViennentDeLAPI: the command reads pods through the typed client, in
// the namespaces it follows and ONLY those — a fake client proves the wiring
// without a cluster.
func TestLesPodsViennentDeLAPI(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ceffio-files"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ceffio-video"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "nextcloud-0", Namespace: "ceffio-files"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "docker.io/library/nextcloud:34.0.3"}}},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c", ImageID: "docker.io/library/nextcloud@sha256:aaaa"}}}},
		// A pod of a namespace the command does not follow must be ignored.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "coredns-0", Namespace: "kube-system"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "docker.io/library/coredns:1"}}}},
	)

	cli := k8sapi.PourTest(cs, nil)
	pods, err := podsDesNamespaces(context.Background(), cli)
	if err != nil {
		t.Fatalf("reading the pods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != "nextcloud-0" {
		t.Fatalf("pods = %v, expected only nextcloud-0 of ceffio-files", pods)
	}
}

// TestUneImageQuiEchappeAuRegistreEstVue: the deviation kinds come out of the
// real comparison fed by the fake client — the whole chain, not a stub.
func TestUneImageQuiEchappeAuRegistreEstVue(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ceffio-files"}},
		// nextcloud est DÉMANDÉ par digest, et ce n'est pas celui du registre.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "nextcloud-0", Namespace: "ceffio-files"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c",
				Image: "docker.io/library/nextcloud:34.0.3@sha256:cccc"}}}},
		// une image que le registre ne décrit pas.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "intrus-0", Namespace: "ceffio-files"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "docker.io/library/busybox:1.36"}}}},
	)
	cli := k8sapi.PourTest(cs, nil)
	pods, err := podsDesNamespaces(context.Background(), cli)
	if err != nil {
		t.Fatalf("reading the pods: %v", err)
	}

	// Un registre réduit à ce que le test met en jeu : le registre réel
	// produirait une dizaine de « absent » qui masqueraient l'écart cherché.
	doc := sbom.Construire([]version.Composant{
		{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3@sha256:aaaa", Module: "internal/files", Licence: "AGPL-3.0-or-later"},
	})
	// Aucun module n'est « attendu » ici : on isole les écarts de référence.
	ecarts := sbom.Comparer(doc, pods, func(string) bool { return false })
	genres := map[string]int{}
	for _, e := range ecarts {
		genres[e.Genre]++
	}
	if genres["hors-registre"] != 1 {
		t.Errorf("unknown images = %d, expected 1 (%v)", genres["hors-registre"], ecarts)
	}
	if genres["version"] != 1 {
		t.Errorf("reference differences = %d, expected 1 (%v)", genres["version"], ecarts)
	}
	if genres["absent"] != 0 {
		t.Errorf("absent components = %d, expected 0 (%v)", genres["absent"], ecarts)
	}
}

// TestLesNamespacesSuivis: the list is explicit, and a namespace outside it does
// not produce a line.
func TestLesNamespacesSuivis(t *testing.T) {
	for _, ns := range []string{"ceffio-files", "ceffio-video", "longhorn-system", "cert-manager", "cnpg-system"} {
		if !namespaceSuivi(ns) {
			t.Errorf("%s should be followed", ns)
		}
	}
	for _, ns := range []string{"kube-system", "default", "traefik"} {
		if namespaceSuivi(ns) {
			t.Errorf("%s should not be followed", ns)
		}
	}
}

// TestUnModuleCoreEstAttendu: a core module's absence is a difference; an
// optional module's is not.
func TestUnModuleCoreEstAttendu(t *testing.T) {
	if !moduleAttendu("internal/files") {
		t.Error("ceffio-files is a core module: its absence must be reported")
	}
	// Le module capture est optionnel et n'est pas installé par défaut.
	if moduleAttendu("internal/modules/capture") {
		t.Error("an optional module that is not installed is not an anomaly")
	}
}
