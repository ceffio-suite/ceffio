// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sbom

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// pod construit un pod qui expose une image et le digest réellement démarré.
func pod(ns, nom, image, imageID string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: nom},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c", Image: image, ImageID: imageID},
		}},
	}
}

func docDeTest() Document {
	doc := Construire([]version.Composant{
		{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3@sha256:aaaa", Module: "internal/files", Licence: "AGPL-3.0-or-later"},
		{Nom: "capture", Image: "ghcr.io/ceffio-suite/ceffio-capture:v0.8.3@sha256:bbbb", Module: "internal/modules/capture", Licence: "AGPL-3.0-or-later"},
	})
	return doc
}

func toutAttendu(string) bool        { return true }
func seulFilesAttendu(m string) bool { return m == "internal/files" }

// TestLesTroisEcarts: the three cases the command has to report — and one that
// it must NOT report.
func TestLesTroisEcarts(t *testing.T) {
	doc := docDeTest()

	pods := []corev1.Pod{
		// nextcloud tourne, avec un AUTRE digest que celui du registre.
		pod("ceffio-files", "nextcloud-0",
			"docker.io/library/nextcloud:34.0.3@sha256:cccc",
			"docker.io/library/nextcloud@sha256:cccc"),
		// une image que le registre ne décrit pas.
		pod("ceffio-video", "intrus-0",
			"docker.io/library/busybox:1.36",
			"docker.io/library/busybox@sha256:dddd"),
	}

	ecarts := Comparer(doc, pods, seulFilesAttendu)
	genres := map[string]int{}
	for _, e := range ecarts {
		genres[e.Genre]++
	}
	if genres["version"] != 1 {
		t.Errorf("reference mismatches = %d, expected 1 (%v)", genres["version"], ecarts)
	}
	if genres["hors-registre"] != 1 {
		t.Errorf("unknown images = %d, expected 1 (%v)", genres["hors-registre"], ecarts)
	}
	// capture n'est pas attendu (module optionnel non installé) : pas d'écart.
	for _, e := range ecarts {
		if e.Genre == "absent" && e.Nom == "capture" {
			t.Errorf("capture is optional and not installed, it must not be reported as absent: %v", e)
		}
	}
}

// TestUnComposantAttenduQuiNeTournePas: an expected component that runs nowhere
// IS a difference.
func TestUnComposantAttenduQuiNeTournePas(t *testing.T) {
	doc := docDeTest()
	ecarts := Comparer(doc, nil, toutAttendu)
	if len(ecarts) != 2 {
		t.Fatalf("%d difference(s), expected 2 (both components absent): %v", len(ecarts), ecarts)
	}
	for _, e := range ecarts {
		if e.Genre != "absent" {
			t.Errorf("genre = %q, expected absent", e.Genre)
		}
	}
}

// TestUnPodParEtiquetteNEstPasCompareParDigest: the registry pins an INDEX
// digest, the pod status reports the PLATFORM manifest digest. For a correct
// installation those differ, so a pod asking for a tag must be compared by tag —
// otherwise every image would be reported as drifted.
func TestUnPodParEtiquetteNEstPasCompareParDigest(t *testing.T) {
	doc := docDeTest()
	p := pod("ceffio-files", "nextcloud-0",
		"docker.io/library/nextcloud:34.0.3",
		"docker.io/library/nextcloud@sha256:eeee")
	ecarts := Comparer(doc, []corev1.Pod{p}, seulFilesAttendu)
	for _, e := range ecarts {
		if e.Genre == "version" {
			t.Errorf("a pod asking for the registry's tag must not be reported (%v)", e)
		}
	}
}

// TestUnPodParUnAutreTagEstSignale: the same component, another version: that is
// the drift an operator has to see.
func TestUnPodParUnAutreTagEstSignale(t *testing.T) {
	doc := docDeTest()
	p := pod("ceffio-files", "nextcloud-0",
		"docker.io/library/nextcloud:33.0.0",
		"docker.io/library/nextcloud@sha256:eeee")
	ecarts := Comparer(doc, []corev1.Pod{p}, seulFilesAttendu)
	var versions []Ecart
	for _, e := range ecarts {
		if e.Genre == "version" {
			versions = append(versions, e)
		}
	}
	if len(versions) != 1 {
		t.Fatalf("%d version difference(s), expected 1 (%v)", len(versions), ecarts)
	}
}

// TestUneRepliqueNEstPasUnEcart: three replicas of the same image are one
// observation, not three findings.
func TestUneRepliqueNEstPasUnEcart(t *testing.T) {
	doc := docDeTest()
	var pods []corev1.Pod
	for i := 0; i < 3; i++ {
		pods = append(pods, pod("ceffio-files", "nextcloud-"+string(rune('a'+i)),
			"docker.io/library/nextcloud:34.0.3",
			"docker.io/library/nextcloud@sha256:aaaa"))
	}
	ecarts := Comparer(doc, pods, seulFilesAttendu)
	for _, e := range ecarts {
		if e.Genre == "hors-registre" || e.Genre == "digest" {
			t.Errorf("replicas of the same image must not produce %v", e)
		}
	}
}
