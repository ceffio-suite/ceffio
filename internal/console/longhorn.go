// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

// LONGHORN: the used space, which the Kubernetes API does not know.
//
// WHY IT IS NEEDED AT ALL. A PersistentVolumeClaim reports only what was
// REQUESTED — "20Gi" — and never what it holds. An operator reading that sees a
// volume at 4 GiB and one at 19,8 GiB as identical, and finds out which was
// which only when writes start failing. Longhorn keeps the real figure, and its
// CRDs are the only place it exists.
//
// WHY LONGHORN AND NOT A GENERIC PATH: nothing in core Kubernetes exposes
// per-volume consumption; every provisioner answers differently or not at all.
// Longhorn is what this platform uses, so reading it is reading the truth for
// these volumes. The code is written to DETECT it rather than assume it: on a
// cluster that does not have the CRDs, the section reports why and the page
// still shows the requested capacities.
//
// THE READ IS READ-ONLY, and on four resource types exactly:
//
//   - volumes.longhorn.io     the used size of each volume
//   - nodes.longhorn.io       the filesystem's maximum, available and committed
//   - replicas.longhorn.io    where each copy of the data lives
//   - engines.longhorn.io     which volume is currently attached, and where
//
// NO CREATE, NO UPDATE, NO DELETE, and nothing on the other twenty-four CRDs:
// the console displays the platform's storage, it does not administer it.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// cheminCRDLonghorn is the API base of the Longhorn resources.
const cheminCRDLonghorn = "/apis/longhorn.io/v1beta2"

// groupeCRDLonghorn is the group in which the resource is registered.
const groupeCRDLonghorn = "longhorn.io"

// stockageLonghorn reads the disk's fill and the volumes' real consumption.
//
// One error for the whole read, and the caller records it as a warning: the
// three parts come from the same API, and a cluster without Longhorn fails all
// of them at once. Splitting them would produce three identical complaints.
func (s *Server) stockageLonghorn(ctx context.Context) ([]DisqueStockage, []Replique, error) {
	partenaires, err := s.lireCRDLonghorn(ctx, "nodes")
	if err != nil {
		return nil, nil, err
	}

	// --- The disk ---------------------------------------------------------
	//
	// THE FIELD NAMES DIFFER BETWEEN LINES of the type, and reading them
	// defensively is not laziness: a name read from the wrong path yields a zero,
	// and a zero-capacity disk is displayed as "0%" full — the one wrong reading
	// that looks reassuring. Each field is therefore taken from where it exists
	// and left at zero when it does not, and PctUtilise answers -1 rather than a
	// percentage when the maximum is unknown.
	var disques []DisqueStockage
	for _, n := range partenaires {
		diskStatus, _ := n["status"].(map[string]interface{})
		if diskStatus == nil {
			continue
		}
		statuts, _ := diskStatus["diskStatus"].(map[string]interface{})
		spec, _ := n["spec"].(map[string]interface{})
		disks, _ := spec["disks"].(map[string]interface{})

		for nomDisque, v := range statuts {
			st, _ := v.(map[string]interface{})
			if st == nil {
				continue
			}
			d := DisqueStockage{
				Chemin:      texte(st["diskPath"]),
				Maximum:     entier(st["storageMaximum"]),
				Disponible:  entier(st["storageAvailable"]),
				Provisioner: "longhorn",
			}
			// The RESERVED space is declared in the spec, not in the status: it
			// is the operator's setting, and looking for it in the status would
			// find nothing.
			if dm, ok := disks[nomDisque].(map[string]interface{}); ok {
				d.Programme = entier(dm["storageReserved"])
			}
			// A disk with no path is a template entry, not a mounted filesystem.
			if d.Chemin == "" || d.Maximum == 0 {
				continue
			}
			disques = append(disques, d)
		}

		// The COMMITTED space is per node as well, and it is what the volumes
		// have reserved here — distinct from the operator's global setting.
		for i := range disques {
			if disques[i].Programme == 0 {
				disques[i].Programme = entier(diskStatus["storageScheduled"])
			}
		}
	}

	// --- The replicas ------------------------------------------------------
	//
	// WHY THEY MATTER ON A PAGE ABOUT SPACE: with a single node, every copy
	// lives on the same disk — so losing that disk loses the volume, and a page
	// showing "healthy" without saying where the copies are would suggest a
	// redundancy that does not exist.
	var repListe []Replique
	brutRepl, err := s.lireCRDLonghorn(ctx, "replicas")
	if err == nil {
		for _, r := range brutRepl {
			st, _ := r["status"].(map[string]interface{})
			sp, _ := r["spec"].(map[string]interface{})
			if st == nil {
				continue
			}
			repListe = append(repListe, Replique{
				Volume: texte(sp["volumeName"]),
				Noeud:  texte(st["currentState"]),
				Etat:   texte(sp["nodeID"]),
			})
		}
	}

	return disques, repListe, nil
}

// volumesUtilises returns, per volume name, the bytes actually written.
//
// SEPARATE FROM stockageLonghorn because the caller needs it to complete the
// PVCs it has already listed, and because a failure here must leave the PVC list
// intact rather than empty.
func (s *Server) volumesUtilises(ctx context.Context) (map[string]int64, error) {
	vols, err := s.lireCRDLonghorn(ctx, "volumes")
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, v := range vols {
		meta, _ := v["metadata"].(map[string]interface{})
		st, _ := v["status"].(map[string]interface{})
		if meta == nil || st == nil {
			continue
		}
		nom := texte(meta["name"])
		// THE NAME IS THE PROVISIONER'S, NOT THE CLAIM'S — established by running
		// this against a real cluster after the first version assumed they agreed
		// and joined on nothing. A Longhorn volume is named after the CLAIM'S UID
		// (`pvc-0b25eaf7-…`), while the claim is called `nextcloud-data`; the only
		// place the two meet is the claim's spec.volumeName, which is what the
		// caller matches on.
		//
		// The initialSize is deliberately NOT used: it is the size at creation
		// time, not the current one.
		if nom == "" {
			continue
		}
		if taille := entier(st["actualSize"]); taille > 0 {
			out[nom] = taille
		}
	}
	return out, nil
}

// lireCRDLonghorn reads one Longhorn resource type, cluster-wide.
//
// IT DOES NOT FAIL ON A MISSING CRD, and that is the point of returning the raw
// error: the caller distinguishes "Longhorn is not installed" (a 404, expected on
// another provisioning setup) from "the console is not allowed to read it" (a
// 403, a deployment defect). Both end as a warning on the page, but the two
// messages send an operator to different places.
func (s *Server) lireCRDLonghorn(ctx context.Context, ressource string) ([]map[string]interface{}, error) {
	chemin := fmt.Sprintf("%s/%s", cheminCRDLonghorn, ressource)
	brut, err := s.kube.Discovery().RESTClient().Get().AbsPath(chemin).DoRaw(ctx)
	if err != nil {
		return nil, traduireErreurLonghorn(err, ressource)
	}
	var liste struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(brut, &liste); err != nil {
		return nil, fmt.Errorf("storage: the %s answer is unreadable (%w)", ressource, err)
	}
	return liste.Items, nil
}

// traduireErreurLonghorn turns a Kubernetes error into something an operator can
// act on.
//
// THE DISTINCTION IS THE WHOLE POINT: "not installed" is normal on another
// provisioning setup and needs no action, while "forbidden" means the console's
// rights are incomplete — a defect in the deployment, which no amount of
// reinstalling Longhorn will fix. Reporting "the metrics CRDs did not answer"
// for both would send an operator down the wrong path, and the second case is
// the one this code introduces.
func traduireErreurLonghorn(err error, ressource string) error {
	msg := err.Error()
	switch {
	case contient(msg, "404") || contient(msg, "not found") || contient(msg, "the server could not find"):
		return fmt.Errorf("the %s resource is absent: this cluster does not use Longhorn "+
			"(requested capacities are shown; used space is not available)", ressource)
	case contient(msg, "403") || contient(msg, "forbidden"):
		return fmt.Errorf("the console is not allowed to read %s (%s). This is a deployment defect: "+
			"the Role granting %s read access is missing", ressource, groupeCRDLonghorn, ressource)
	case contient(msg, "401") || contient(msg, "unauthorized"):
		return fmt.Errorf("the console could not authenticate against %s: its ServiceAccount "+
			"token is invalid or expired", ressource)
	default:
		return fmt.Errorf("reading %s: %w", ressource, err)
	}
}

// --- Small helpers ---------------------------------------------------------

// texte returns a string field, or "" — never "<nil>".
func texte(v interface{}) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// entier returns a numeric field as int64, whatever JSON type carried it.
//
// JSON DECODES NUMBERS AS float64, and a size above 2^53 would lose precision
// if converted through float — not a case today, and the reason the conversion
// is explicit here rather than implicit at every call site.
func entier(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0
		}
		return i
	default:
		return 0
	}
}

// contient is a case-insensitive substring test, for matching API error text
// whose casing varies between client versions.
func contient(s, motif string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(motif))
}
