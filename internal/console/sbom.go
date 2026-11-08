// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"net/http"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/sbom"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// handleSBOM serves the installation's bill of materials.
//
// SAME DOCUMENT AS `ceffio sbom`, from the same package: a console that built
// its own would be a second truth, and the first thing to drift.
//
// `?cluster=1` adds the comparison with what runs. It is opt-in because it costs
// a pod listing, and because an operator reading the document usually wants the
// document — the differences are the next question, not the same one.
func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request) {
	doc := sbom.Construire(version.Registry)
	sbom.AjouteLeBinaire(&doc)
	sbom.AjouteLaPlateforme(&doc, version.Plateforme)

	reponse := map[string]any{"sbom": doc}
	if r.URL.Query().Get("cluster") != "" {
		ecarts, err := s.ecartsCluster(r)
		if err != nil {
			// THE DOCUMENT IS STILL VALID WITHOUT THE COMPARISON: failing the
			// whole answer because the cluster did not answer would hide what we
			// do know behind what we do not.
			reponse["cluster_error"] = err.Error()
		} else {
			reponse["ecarts"] = ecarts
			reponse["conforme"] = len(ecarts) == 0
		}
	}
	writeJSON(w, http.StatusOK, reponse)
}

// ecartsCluster compares the document with the pods in the namespaces we follow.
//
// THE DOCUMENT IS THE SAME ONE `ceffio sbom` WRITES: same package, same rules.
// A console that built its own would be a second truth, and the first thing to
// drift.
func (s *Server) ecartsCluster(r *http.Request) ([]sbom.Ecart, error) {
	ctx := r.Context()
	doc := sbom.Construire(version.Registry)
	sbom.AjouteLaPlateforme(&doc, version.Plateforme)

	var pods []corev1.Pod
	for _, ns := range registryNamespaces() {
		pl, err := s.kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, p := range pl.Items {
			if p.DeletionTimestamp != nil {
				continue
			}
			pods = append(pods, p)
		}
	}
	return sbom.Comparer(doc, pods, sbom.ModuleAttendu), nil
}
