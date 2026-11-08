// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"encoding/json"
	"github.com/ceffio-suite/ceffio/internal/version"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestLeSBOMDeLaConsoleEstCeluiDeLaCLI: the console serves the document the
// command writes — same package, so the two cannot disagree.
func TestLeSBOMDeLaConsoleEstCeluiDeLaCLI(t *testing.T) {
	s := &Server{Domain: "exemple.org", kube: fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ceffio-files"}},
	)}
	rec := httptest.NewRecorder()
	s.handleSBOM(rec, httptest.NewRequest(http.MethodGet, "/api/sbom", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var reponse struct {
		SBOM struct {
			BOMFormat   string `json:"bomFormat"`
			SpecVersion string `json:"specVersion"`
			Components  []struct {
				Name       string `json:"name"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"components"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reponse); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if reponse.SBOM.BOMFormat != "CycloneDX" || reponse.SBOM.SpecVersion != "1.6" {
		t.Errorf("format = %q %q", reponse.SBOM.BOMFormat, reponse.SBOM.SpecVersion)
	}
	// Le registre ET la plateforme : un opérateur voit ce qui peut tourner.
	if len(reponse.SBOM.Components) < len(version.Registry) {
		t.Errorf("%d composant(s), moins que le registre", len(reponse.SBOM.Components))
	}
}

// TestLeSBOMAccepteLeCluster: ?cluster=1 compare, et le dit.
func TestLeSBOMAccepteLeCluster(t *testing.T) {
	s := &Server{Domain: "exemple.org", kube: fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ceffio-files"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "intrus", Namespace: "ceffio-files"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "docker.io/library/busybox:1.36"}}},
		},
	)}
	rec := httptest.NewRecorder()
	s.handleSBOM(rec, httptest.NewRequest(http.MethodGet, "/api/sbom?cluster=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var reponse struct {
		Ecarts   []struct{ Genre, Nom string } `json:"ecarts"`
		Conforme *bool                         `json:"conforme"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reponse); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if reponse.Conforme == nil {
		t.Fatal("le champ conforme manque : on ne peut pas dire si l'installation correspond")
	}
	if *reponse.Conforme {
		t.Error("une image inconnue tourne : conforme devrait être faux")
	}
}
