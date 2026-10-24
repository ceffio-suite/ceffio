// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package upgrade upgrades a Ceffio installation.
//
// An upgrade is only acceptable if it is reversible. This package therefore
// imposes three steps before any modification:
//
//  1. a preflight — is the target healthy, and what is actually running
//     (compared against the version registry, not a guess);
//  2. a backup — mandatory, and verified: without a usable archive, no
//     rollback is possible;
//  3. a plan — what would change, displayed before acting.
//
// Without these three steps, an `upgrade` is a gamble.
package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// Etat describes what is running, per component.
type Etat struct {
	Nom       string `json:"nom"`
	Installee string `json:"installee"`
	Cible     string `json:"cible"`
	Ecart     bool   `json:"ecart"`
	Depuis    string `json:"depuis,omitempty"` // image actually in service
}

// Plan is the result of the preflight: what would change, and the blockers.
type Plan struct {
	Etats       []Etat   `json:"etats"`
	Changements []Etat   `json:"changements"`
	Blocages    []string `json:"blocages"`
	Alertes     []string `json:"alertes"`
	Pret        bool     `json:"pret"`
	ClusterOK   bool     `json:"cluster_ok"`
	NoeudsPrets int      `json:"noeuds_prets"`
	NoeudsTotal int      `json:"noeuds_total"`
}

// Preparer builds the upgrade plan.
//
// It modifies NOTHING: it is a diagnostic. `upgrade` must never touch an
// installation before showing what it will do.
func Preparer(ctx context.Context, cible []version.Composant) *Plan {
	p := &Plan{Etats: []Etat{}, Changements: []Etat{}, Blocages: []string{}, Alertes: []string{}}

	// 1. Does the cluster respond, and is it healthy? Upgrading a version on
	//    a degraded cluster makes it impossible to tell the original outage
	//    from the one we just introduced.
	nodes := imagesEnService(ctx)
	p.NoeudsTotal, p.NoeudsPrets = noeuds(ctx)
	if p.NoeudsTotal == 0 {
		p.Blocages = append(p.Blocages, "Cluster unreachable: cannot prepare an upgrade.")
		return p
	}
	p.ClusterOK = true
	if p.NoeudsPrets < p.NoeudsTotal {
		p.Blocages = append(p.Blocages,
			fmt.Sprintf("Nodes not ready (%d/%d): fix the cluster state before upgrading.",
				p.NoeudsPrets, p.NoeudsTotal))
	}

	// 2. Pods in trouble: an upgrade on an unstable base does not allow
	//    attributing an outage to its cause.
	if noms := podsEnDifficulte(ctx); len(noms) > 0 {
		p.Blocages = append(p.Blocages,
			fmt.Sprintf("%d pod(s) in trouble: %s — stabilize first.",
				len(noms), strings.Join(noms, ", ")))
	}

	// 3. Registry consistency: an image without a pinned tag forbids any
	//    version comparison (we would not know what we are installing).
	for _, pb := range version.VerifierCoherence() {
		p.Blocages = append(p.Blocages, pb)
	}

	// 4. Component-by-component comparison: what is running vs the target.
	for _, c := range cible {
		e := Etat{Nom: c.Nom, Cible: c.Version}
		if img, ok := nodes[c.Nom]; ok {
			e.Installee = version.TagDe(img)
			e.Depuis = img
		}
		// A missing component is not a drift: it is an uninstalled layer
		// (video without --video). Report it without blocking — but ALWAYS
		// report it: a component we cannot read must not pass as compliant
		// (that was the flaw of the first version, which reported "no
		// drift" while a different image was running).
		if e.Installee == "" {
			// NOTHING WAS FOUND FOR THIS REPOSITORY: the layer is absent (an
			// installation without Talk, for instance). Naming the repository
			// says what was looked for, which a bare "not deployed" does not.
			p.Alertes = append(p.Alertes, fmt.Sprintf("%s : no running image from %s", c.Nom, depotDe(c.Image)))
		} else if e.Installee != e.Cible {
			e.Ecart = true
			p.Changements = append(p.Changements, e)
		}
		p.Etats = append(p.Etats, e)
	}

	sort.Slice(p.Etats, func(i, j int) bool { return p.Etats[i].Nom < p.Etats[j].Nom })
	p.Pret = len(p.Blocages) == 0
	return p
}

// imagesEnService reads, for each registry component, the image actually used
// by the running pods.
//
// WHY BY REPOSITORY AND NOT BY SUBSTRING. The first version matched a
// hand-written fragment against every running image ("nextcloud", "redis:").
// On a real installation it associated the `nextcloud` component with
// docker.io/nextcloud/aio-talk-recording:20261014_095932 — a different product
// whose repository merely STARTS with the same word — and reported a drift
// that did not exist. The same table covered six components out of twelve:
// janus, coturn, nats, stalwart, openbao and the others were declared "not
// deployed" while they were serving traffic.
//
// The registry already carries the answer: every component pins a FULL image
// reference. Two images belong to the same component when their REPOSITORY is
// the same, whatever the tag — the tag is precisely what is being compared.
func imagesEnService(ctx context.Context) map[string]versionImage {
	var images []string
	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return map[string]versionImage{}
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return map[string]versionImage{}
	}
	for _, p := range doc.Items {
		ns := p.Metadata.Namespace
		if !strings.HasPrefix(ns, "ceffio-") && ns != "cnpg-system" && ns != "cert-manager" {
			continue
		}
		for _, c := range p.Spec.Containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	return associer(images, version.Registry)
}

// depotsAlias lists, per component, the repositories a PREVIOUS version of the
// product used. Without it, an installation still running the old image would
// be reported "not deployed" instead of "to upgrade" — the very mistake this
// file exists to avoid (Valkey replaced Redis on the licence migration).
var depotsAlias = map[string][]string{
	"valkey": {"docker.io/valkey/valkey", "docker.io/library/redis"},
}

// associer maps each component to a running image of the same repository.
// It is pure, so the rule is testable without a cluster.
func associer(images []string, composants []version.Composant) map[string]versionImage {
	parDepot := map[string][]string{}
	for _, img := range images {
		if d := depotDe(img); d != "" {
			parDepot[d] = append(parDepot[d], img)
		}
	}

	trouvees := map[string]versionImage{}
	for _, c := range composants {
		candidats := append([]string(nil), parDepot[depotDe(c.Image)]...)
		for _, d := range depotsAlias[c.Nom] {
			candidats = append(candidats, parDepot[d]...)
		}
		if img := plusFrequent(candidats); img != "" {
			trouvees[c.Nom] = img
		}
	}
	return trouvees
}

// plusFrequent picks the image carried by the most pods. During a rollout two
// tags coexist: counting says which one the installation is actually running,
// and the sort makes the answer deterministic when they are equally frequent.
func plusFrequent(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	compte := map[string]int{}
	for _, r := range refs {
		compte[r]++
	}
	meilleur, n := "", 0
	for r, c := range compte {
		if c > n || (c == n && r < meilleur) {
			meilleur, n = r, c
		}
	}
	return meilleur
}

// depotDe returns the repository of an image reference, without tag or digest,
// with the short Docker form expanded: kubelet may report `nextcloud:34.0.3`
// where the registry says `docker.io/library/nextcloud:34.0.3`, and the two
// must compare equal.
func depotDe(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	if ref == "" {
		return ""
	}
	premier := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		premier = ref[:i]
	} else {
		return "docker.io/library/" + ref
	}
	if strings.ContainsAny(premier, ".:") || premier == "localhost" {
		return ref
	}
	return "docker.io/" + ref
}

// versionImage is a string alias, for signature readability.
type versionImage = string

func noeuds(ctx context.Context) (total, prets int) {
	raw, err := kubectl(ctx, "get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}")
	if err != nil {
		return 0, 0
	}
	for _, l := range strings.Split(raw, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		total++
		if f[1] == "True" {
			prets++
		}
	}
	return total, prets
}

func podsEnDifficulte(ctx context.Context) []string {
	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return nil
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Ready        bool `json:"ready"`
					RestartCount int  `json:"restartCount"`
					State        struct {
						Waiting struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil
	}
	var out []string
	for _, p := range doc.Items {
		if !strings.HasPrefix(p.Metadata.Namespace, "ceffio-") {
			continue
		}
		// A finished job is not trouble.
		if p.Status.Phase == "Succeeded" {
			continue
		}
		enDifficulte := false
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting.Reason == "CrashLoopBackOff" ||
				cs.State.Waiting.Reason == "ImagePullBackOff" ||
				cs.State.Waiting.Reason == "CreateContainerConfigError" {
				enDifficulte = true
			}
			if !cs.Ready && p.Status.Phase == "Running" && cs.State.Waiting.Reason != "" {
				enDifficulte = true
			}
		}
		if p.Status.Phase == "Failed" {
			enDifficulte = true
		}
		if enDifficulte {
			out = append(out, p.Metadata.Namespace+"/"+p.Metadata.Name)
		}
	}
	sort.Strings(out)
	return out
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := k8s.Command(ctx, "kubectl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
