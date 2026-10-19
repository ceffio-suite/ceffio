// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// The monitoring route: GET /api/monitoring.
//
// WHY A SEPARATE ROUTE AND NOT AN EXTENSION OF /api/status: status answers
// "what is deployed and is it healthy", which is the registry walk and does not
// touch the machine. This one reads the node's live consumption and the volumes,
// which means different API groups and different rights. Merging them would make
// one slow source delay the whole console's first paint, and would force a
// reader of the status code to learn about metrics and storage.
//
// NO WRITE, NO ACTION: this route reads. A monitoring page that could act would
// be one more way to break a cluster from a browser tab.

import (
	"net/http"
)

// handleMonitoring serves the machine's state as JSON.
//
// IT NEVER ANSWERS 500. A source that did not reply is reported in
// `warnings`, and the rest is served: an operator opening this page during an
// incident must see what IS readable, not an error page. The one thing it must
// never do is present an unread value as a zero — hence the warnings, and hence
// `usedKnown` on every volume.
func (s *Server) handleMonitoring(w http.ResponseWriter, r *http.Request) {
	m := s.CollecterMonitoring(r.Context())

	// The volumes are flattened into the shape the page draws, with the derived
	// percentages computed HERE rather than in JavaScript: two implementations of
	// a ratio drift, and the badge on the page must agree with the number in the
	// table.
	type volumeVue struct {
		Namespace string  `json:"namespace"`
		Name      string  `json:"name"`
		Class     string  `json:"class"`
		Phase     string  `json:"phase"`
		Requested int64   `json:"requested"`
		Used      int64   `json:"used"`
		UsedKnown bool    `json:"usedKnown"`
		UsedPct   float64 `json:"usedPct"` // -1 when unknown
	}

	volumes := make([]volumeVue, 0, len(m.Volumes))
	for _, v := range m.Volumes {
		volumes = append(volumes, volumeVue{
			Namespace: v.Namespace,
			Name:      v.Nom,
			Class:     v.Classe,
			Phase:     v.Etat,
			Requested: v.Demande,
			Used:      v.Utilise,
			UsedKnown: v.UtiliseConnu,
			UsedPct:   v.PctUtilise(),
		})
	}

	type noeudVue struct {
		Name      string  `json:"name"`
		CPUUsed   float64 `json:"cpuUsed"`
		CPUTotal  float64 `json:"cpuTotal"`
		CPUPct    float64 `json:"cpuPct"`
		MemUsed   int64   `json:"memUsed"`
		MemTotal  int64   `json:"memTotal"`
		MemPct    float64 `json:"memPct"`
		MetricsOK bool    `json:"metricsOk"`
	}

	noeuds := make([]noeudVue, 0, len(m.Noeuds))
	for _, n := range m.Noeuds {
		noeuds = append(noeuds, noeudVue{
			Name:     n.Nom,
			CPUUsed:  n.CPUUtilise,
			CPUTotal: n.CPUTotal,
			CPUPct:   n.PctCPU(),
			MemUsed:  n.MemUtilise,
			MemTotal: n.MemTotal,
			MemPct:   n.PctMem(),
			// A capacity with no consumption means the metrics API did not
			// answer: the page draws "—" instead of "0 %", which would look
			// like an idle machine during an outage.
			MetricsOK: n.MemUtilise > 0 || n.CPUUtilise > 0,
		})
	}

	type disqueVue struct {
		Path        string  `json:"path"`
		Maximum     int64   `json:"maximum"`
		Available   int64   `json:"available"`
		Committed   int64   `json:"committed"`
		UsedPct     float64 `json:"usedPct"`
		Provisioner string  `json:"provisioner"`
	}

	disques := make([]disqueVue, 0, len(m.Disques))
	for _, d := range m.Disques {
		disques = append(disques, disqueVue{
			Path:        d.Chemin,
			Maximum:     d.Maximum,
			Available:   d.Disponible,
			Committed:   d.Programme,
			UsedPct:     d.PctUtilise(),
			Provisioner: d.Provisioner,
		})
	}

	type repliqueVue struct {
		Volume string `json:"volume"`
		Node   string `json:"node"`
		State  string `json:"state"`
	}

	repliques := make([]repliqueVue, 0, len(m.Repliques))
	for _, r := range m.Repliques {
		repliques = append(repliques, repliqueVue{
			Volume: r.Volume, Node: r.Noeud, State: r.Etat,
		})
	}

	type conditionVue struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}

	conditions := make([]conditionVue, 0, len(m.Conditions))
	for _, c := range m.Conditions {
		conditions = append(conditions, conditionVue{
			Type: c.Type, Status: c.Statut, Reason: c.Raison,
		})
	}

	reponse := map[string]interface{}{
		"nodes":      noeuds,
		"conditions": conditions,
		"volumes":    volumes,
		"disks":      disques,
		"replicas":   repliques,
		// The alert is computed HERE, from the same figures the page displays:
		// a badge derived a second time in JavaScript would eventually disagree
		// with the table under it.
		"alert":    m.SouciSante(),
		"warnings": m.Avertissements,
	}
	if reponse["warnings"] == nil {
		reponse["warnings"] = []string{}
	}

	// The figures change every few seconds: a cache would show a stale machine,
	// and an operator reading "5 % CPU" from ten minutes ago would draw the
	// wrong conclusion about the incident they are in.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, reponse)
}
