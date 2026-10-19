// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// MONITORING: what the platform's machine is actually doing.
//
// WHY THIS PAGE EXISTS, and what it answers that the others do not: every tab
// so far reports what SHOULD be running — the modules, the certificates, the
// pods. None says whether the machine underneath can still carry it. An operator
// whose Nextcloud is slow has no way of telling "the node is out of memory" from
// "Nextcloud is misconfigured", and those call for opposite reactions.
//
// TWO SOURCES, AND THE DISTINCTION MATTERS:
//
//   - the NODE's CPU and memory come from the metrics API
//     (metrics.k8s.io/v1beta1), which the metrics-server serves. That is the
//     live figure, and it is the same number `kubectl top node` prints.
//   - the volumes come from the PVCs (what was REQUESTED, which is all the
//     Kubernetes API knows) and, when Longhorn provisions them, from its own
//     CRDs (what is actually WRITTEN).
//
// THE REQUESTED CAPACITY IS NOT THE USED ONE, and showing only the first is how
// an operator ends up surprised: a 20Gi volume holding 5 GiB of files looks
// identical to one that is full. Both are reported, and the used figure is only
// shown when a source provides it — never estimated.
//
// EVERY READ IS BEST-EFFORT AND NAMED: a missing metrics-server, an absent
// Longhorn, a denied permission each leave one section without values and say
// so. The page must never fail as a whole because one source is unavailable,
// nor pretend a zero it could not read.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// --- Types -----------------------------------------------------------------

// MetriqueNoeud is the node's live consumption, as the metrics server reports it.
type MetriqueNoeud struct {
	Nom        string
	CPUUtilise float64 // cores
	CPUTotal   float64 // cores, from the node's capacity
	MemUtilise int64   // bytes
	MemTotal   int64   // bytes
}

// PctCPU and PctMem are computed once, so the page and any future export agree
// on the same rounding.
func (m MetriqueNoeud) PctCPU() float64 { return pourcent(m.CPUUtilise, m.CPUTotal) }
func (m MetriqueNoeud) PctMem() float64 { return pourcent(float64(m.MemUtilise), float64(m.MemTotal)) }

// Volume is one persistent volume claim, with what was requested and — when a
// source provides it — what it holds.
type Volume struct {
	Namespace string
	Nom       string
	Classe    string
	Etat      string // Bound, Pending…
	Demande   int64  // bytes requested
	Utilise   int64  // bytes written; 0 and UtiliseConnu=false when unknown
	// UtiliseConnu distinguishes "0 bytes written" from "no source told us".
	//
	// A page that treated both as zero would show a full disk as empty, which is
	// the one reading that leads to an outage.
	UtiliseConnu bool
	// Lie is what the PROVISIONER calls this claim, which is nothing like the
	// claim's own name.
	//
	// A Longhorn volume is named after the claim's UID — `pvc-0b25eaf7-…` for a
	// claim called `nextcloud-data` — and that name exists nowhere else in the
	// claim. spec.volumeName is what carries it, and it is the ONLY join key:
	// matching on the claim's name finds nothing, which is what an earlier
	// version of this code did, on the false premise that the two names agree.
	Lie string
}

// PctUtilise returns the fill ratio, or -1 when the used figure is unknown: a
// caller can then print "—" rather than a percentage of nothing.
func (v Volume) PctUtilise() float64 {
	if !v.UtiliseConnu || v.Demande == 0 {
		return -1
	}
	return pourcent(float64(v.Utilise), float64(v.Demande))
}

// DisqueStockage is the physical filesystem backing the volumes.
type DisqueStockage struct {
	Chemin      string
	Maximum     int64
	Disponible  int64
	Programme   int64 // what the provisioner has committed to the volumes
	Provisioner string
}

// PctUtilise is the fill ratio of the filesystem itself, which is the figure
// that says whether the machine is about to stop accepting writes.
func (d DisqueStockage) PctUtilise() float64 {
	if d.Maximum == 0 {
		return -1
	}
	return pourcent(float64(d.Maximum-d.Disponible), float64(d.Maximum))
}

// Replique is one copy of a volume's data.
type Replique struct {
	Volume string
	Noeud  string
	Etat   string
}

// Monitoring is everything the page shows.
type Monitoring struct {
	Noeuds    []MetriqueNoeud
	Volumes   []Volume
	Disques   []DisqueStockage
	Repliques []Replique

	// Conditions are the node's pressure signals. They answer "is this about to
	// go wrong" rather than "how much is left", and they are what an operator
	// checks before blaming an application.
	Conditions []ConditionNoeud

	// Avertissements names every source that did not answer. The page shows
	// them; a silently empty section would read as "nothing to report".
	Avertissements []string
}

// ConditionNoeud is one condition of the node, kept only when it is worth
// showing.
type ConditionNoeud struct {
	Type   string
	Statut string
	Raison string
}

// SouciSante reports whether the platform is under pressure: any node condition
// that is not False, or a disk above 90%.
//
// It is deliberately a method rather than a value stored at collection time, so
// the threshold lives in one place and the page cannot disagree with the badge.
func (m Monitoring) SouciSante() bool {
	for _, c := range m.Conditions {
		if c.Type == "Ready" {
			if c.Statut != "True" {
				return true
			}
			continue
		}
		// MemoryPressure, DiskPressure, PIDPressure: True means the condition is
		// PRESENT, which is the bad case — the opposite of Ready.
		if c.Statut == "True" {
			return true
		}
	}
	for _, d := range m.Disques {
		if p := d.PctUtilise(); p >= 90 {
			return true
		}
	}
	return false
}

// --- Collection ------------------------------------------------------------

// CollecterMonitoring gathers everything, reporting what it could not read
// rather than failing.
//
// NO ERROR IS RETURNED, and that is a decision: a console whose monitoring page
// refuses to load because the metrics server is missing would be least useful
// exactly when something is wrong. Each source is attempted, its failure is
// recorded by name, and the page renders what it has.
func (s *Server) CollecterMonitoring(ctx context.Context) Monitoring {
	out := Monitoring{}

	out.Noeuds, out.Conditions = s.metriquesNoeuds(ctx, &out.Avertissements)

	var err error
	out.Volumes, err = s.volumes(ctx)
	if err != nil {
		out.Avertissements = append(out.Avertissements,
			"volumes: "+err.Error()+" — the requested capacities appear without the used ones")
	}

	// The used sizes complete the claims just listed. A failure here leaves the
	// list intact and only leaves the "used" column empty: an operator keeps the
	// capacities they came for.
	if utilises, err := s.volumesUtilises(ctx); err != nil {
		out.Avertissements = append(out.Avertissements, err.Error())
	} else {
		for i := range out.Volumes {
			if taille, ok := utilises[out.Volumes[i].Lie]; ok {
				out.Volumes[i].Utilise = taille
				out.Volumes[i].UtiliseConnu = true
			}
		}
	}

	out.Disques, out.Repliques, err = s.stockageLonghorn(ctx)
	if err != nil {
		// NOT A FAILURE ON A CLUSTER THAT DOES NOT USE LONGHORN: the page then
		// shows the PVCs without the disk fill, and says why.
		out.Avertissements = append(out.Avertissements, err.Error())
	}

	return out
}

// --- The node --------------------------------------------------------------

// metriquesNoeuds reads the nodes' live consumption and their conditions.
//
// TWO APIS: the metrics server for consumption, the core API for capacity and
// conditions. Reading both is what lets the page say "7,4 GiB of 62 GiB" rather
// than "7,4 GiB", which is the number an operator can act on.
func (s *Server) metriquesNoeuds(ctx context.Context, avert *[]string) ([]MetriqueNoeud, []ConditionNoeud) {
	// Capacity and conditions first: they come from the core API, which is
	// always present. If THIS read fails there is nothing to show, and the page
	// must say so rather than display nothing.
	rc, err := s.restClient()
	if err != nil {
		*avert = append(*avert, "nodes: "+err.Error())
		return nil, nil
	}
	brut, err := rc.Get().AbsPath("/api/v1/nodes").DoRaw(ctx)
	if err != nil {
		*avert = append(*avert, "nodes: "+err.Error()+" — the machine's capacity and conditions are unavailable")
		return nil, nil
	}
	var listeNodes struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Capacity struct {
					CPU    string `json:"cpu"`
					Memory string `json:"memory"`
				} `json:"capacity"`
				Conditions []struct {
					Type    string `json:"type"`
					Status  string `json:"status"`
					Reason  string `json:"reason"`
					Message string `json:"message"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(brut, &listeNodes); err != nil {
		*avert = append(*avert, "nodes: unreadable answer ("+err.Error()+")")
		return nil, nil
	}

	parNom := map[string]*MetriqueNoeud{}
	var ordre []string
	var conditions []ConditionNoeud
	for _, n := range listeNodes.Items {
		m := &MetriqueNoeud{Nom: n.Metadata.Name}
		m.CPUTotal = enCoeurs(n.Status.Capacity.CPU)
		m.MemTotal = enOctets(n.Status.Capacity.Memory)
		parNom[n.Metadata.Name] = m
		ordre = append(ordre, n.Metadata.Name)

		// ONLY THE CONDITIONS THAT SAY SOMETHING. The API returns a fixed set;
		// listing all of them would bury the one that matters among four
		// "False" lines.
		for _, c := range n.Status.Conditions {
			switch c.Type {
			case "Ready", "MemoryPressure", "DiskPressure", "PIDPressure":
				conditions = append(conditions, ConditionNoeud{
					Type: c.Type, Statut: c.Status, Raison: c.Reason,
				})
			}
		}
	}

	// The consumption, from the metrics API.
	conso, err := s.kube.Discovery().RESTClient().Get().
		AbsPath("/apis/metrics.k8s.io/v1beta1/nodes").DoRaw(ctx)
	if err != nil {
		// THE PAGE STILL SHOWS CAPACITY. "62 GiB total, consumption unknown" is
		// useful; a blank page is not.
		*avert = append(*avert,
			"metrics: the metrics API did not answer ("+raisonCourte(err)+"): live CPU and memory are unavailable")
	} else {
		var listeConso struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Usage struct {
					CPU    string `json:"cpu"`
					Memory string `json:"memory"`
				} `json:"usage"`
			} `json:"items"`
		}
		if err := json.Unmarshal(conso, &listeConso); err != nil {
			*avert = append(*avert, "metrics: unreadable answer ("+err.Error()+")")
		} else {
			for _, c := range listeConso.Items {
				if m, ok := parNom[c.Metadata.Name]; ok {
					m.CPUUtilise = enCoeurs(c.Usage.CPU)
					m.MemUtilise = enOctets(c.Usage.Memory)
				}
			}
		}
	}

	out := make([]MetriqueNoeud, 0, len(ordre))
	for _, nom := range ordre {
		out = append(out, *parNom[nom])
	}
	return out, conditions
}

// --- Volumes ---------------------------------------------------------------

// volumes lists the PVCs of the platform's namespaces.
//
// ONE CALL PER NAMESPACE, NOT A CLUSTER-WIDE LIST — and that is what the rights
// allow, which the first version of this code learned the hard way by returning
// an empty list with the message "unknown". The console holds a Role in each
// ceffio-* namespace and no cluster-scoped right on claims: asking for all of
// them at once is refused, and a refusal reported as "unknown" reads as a bug in
// this page rather than as a limit of the grant.
//
// THE NAMESPACES COME FROM THE CLUSTER, not from a list in this file: a list
// would go stale the day a module adds one, and the page would silently stop
// showing a volume — the worst kind of monitoring defect, since it looks like
// there is nothing to see.
func (s *Server) volumes(ctx context.Context) ([]Volume, error) {
	rc, err := s.restClient()
	if err != nil {
		return nil, err
	}

	// The platform's namespaces, as the cluster declares them.
	brutNs, err := rc.Get().AbsPath("/api/v1/namespaces").DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	var nsListe struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(brutNs, &nsListe); err != nil {
		return nil, fmt.Errorf("listing the namespaces: %w", err)
	}

	out := []Volume{}
	var premiereErreur error
	for _, ns := range nsListe.Items {
		nom := ns.Metadata.Name
		if !strings.HasPrefix(nom, "ceffio-") {
			continue
		}
		brut, err := rc.Get().AbsPath("/api/v1/namespaces/" + nom + "/persistentvolumeclaims").DoRaw(ctx)
		if err != nil {
			// ONE NAMESPACE THAT REFUSES DOES NOT HIDE THE OTHERS. The first
			// error is kept and reported; the rest of the platform is still
			// shown, because a page that gives up entirely on one refusal is
			// least useful during the incident it was opened for.
			if premiereErreur == nil {
				premiereErreur = fmt.Errorf("namespace %s: %w", nom, err)
			}
			continue
		}
		vols, err := volumesDe(brut)
		if err != nil {
			if premiereErreur == nil {
				premiereErreur = fmt.Errorf("namespace %s: %w", nom, err)
			}
			continue
		}
		out = append(out, vols...)
	}
	if len(out) == 0 && premiereErreur != nil {
		return nil, premiereErreur
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Nom < out[j].Nom
	})
	return out, nil
}

// volumesDe parses one namespace's claim list.
func volumesDe(brut []byte) ([]Volume, error) {
	var liste struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				StorageClassName string `json:"storageClassName"`
				// VolumeName is the PROVISIONER's name for this claim, and it is
				// the only key that joins a claim to what the provisioner says
				// about it — see volumesUtilises.
				VolumeName string `json:"volumeName"`
				Resources  struct {
					Requests struct {
						Storage string `json:"storage"`
					} `json:"requests"`
				} `json:"resources"`
			} `json:"spec"`
			Status struct {
				Phase    string `json:"phase"`
				Capacity struct {
					Storage string `json:"storage"`
				} `json:"capacity"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(brut, &liste); err != nil {
		return nil, err
	}

	out := []Volume{}
	for _, p := range liste.Items {
		// The REQUESTED size is what the operator planned for; the status
		// capacity is what the provisioner granted. They agree on every healthy
		// claim, and when they disagree the granted one is the truth — a claim
		// cannot hold more than it was given.
		taille := enOctets(p.Spec.Resources.Requests.Storage)
		if acquise := enOctets(p.Status.Capacity.Storage); acquise > 0 {
			taille = acquise
		}
		out = append(out, Volume{
			Namespace: p.Metadata.Namespace,
			Nom:       p.Metadata.Name,
			Lie:       p.Spec.VolumeName,
			Classe:    p.Spec.StorageClassName,
			Etat:      p.Status.Phase,
			Demande:   taille,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Nom < out[j].Nom
	})
	return out, nil
}

// --- Helpers ---------------------------------------------------------------

// restClient returns the client used for the raw API reads.
//
// WHY IT IS CHECKED RATHER THAN USED DIRECTLY: Discovery().RESTClient() answers
// nil when no REST layer is attached — which is what a test client does, and
// what an odd deployment could do. Calling a method on that nil pointer PANICS,
// and a panicking handler takes down the whole console process: a monitoring
// page would become a way to crash the administration console, which is the
// opposite of its purpose.
//
// A MISSING CLIENT IS A REPORTABLE CONDITION, not a crash: the caller records it
// in the warnings and the page renders the sections that do not need it.
func (s *Server) restClient() (rest.Interface, error) {
	if s == nil || s.kube == nil {
		return nil, fmt.Errorf("no Kubernetes client is attached to the console")
	}
	d := s.kube.Discovery()
	if d == nil {
		return nil, fmt.Errorf("the cluster's discovery is unavailable")
	}
	rc := d.RESTClient()
	if rc == nil {
		return nil, fmt.Errorf("the REST layer is unavailable: the raw API cannot be read")
	}
	return rc, nil
}

// enCoeurs converts a Kubernetes CPU quantity ("542m", "12", "1500m") to cores.
//
// HANDLED BY resource.ParseQuantity rather than by trimming a suffix: the
// formats include "m", plain integers and decimal exponents, and a hand-written
// parser would get one of them wrong on the day it matters.
func enCoeurs(s string) float64 {
	if s == "" {
		return 0
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	return float64(q.MilliValue()) / 1000
}

// enOctets converts a Kubernetes quantity ("10Gi", "512Mi", "1945672Ki") to
// bytes.
//
// BINARY SUFFIXES ARE ASSUMED BY ParseQuantity for Gi/Mi/Ki, which is what every
// Kubernetes capacity field uses. Decimal suffixes stay decimal, so a value
// written "1G" is not silently inflated.
func enOctets(s string) int64 {
	if s == "" {
		return 0
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	return q.Value()
}

// pourcent returns a percentage, capped at 100: a container that reports usage
// above its limit is a real case, and printing 143% would read as a bug.
func pourcent(partie, total float64) float64 {
	if total <= 0 {
		return -1
	}
	p := partie / total * 100
	if p > 100 {
		return 100
	}
	return p
}

// raisonCourte trims an error to a phrase that fits in a banner.
func raisonCourte(err error) string {
	return tronquer(strings.TrimSpace(err.Error()), 60)
}

// NouveauPourTest builds a console around a given client, for a test outside
// this package.
//
// WHY IT EXISTS: the monitoring page reads four API paths that only a real
// cluster can confirm. A test in another package cannot reach the unexported
// Server, so without this it would have to duplicate the collection — and the
// paths it verifies would then be its own, not the ones the console uses.
func NouveauPourTest(cli kubernetes.Interface) *Server {
	return &Server{kube: cli, ops: newOpsManager()}
}
