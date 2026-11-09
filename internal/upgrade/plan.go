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
	"strconv"
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
	// Arrete says the component is INSTALLED but runs nothing: its workload is
	// scaled to zero. Its image is still read (from the workload, since no pod
	// carries it) and compared, and the replay starts it again — see
	// imagesDesWorkloads.
	Arrete bool `json:"arrete,omitempty"`
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
	// MigrationsMajeures names the components blocked by an offline migration
	// (see blocageMigrationMajeure). Empty in the normal case; filled, it is
	// what `--allow-major-migration` lifts — and nothing else.
	MigrationsMajeures []string `json:"migrations_majeures,omitempty"`
}

// migrationsImposees lists the components whose MAJOR version bump cannot be
// applied as-is, with the document that describes the data migration.
//
// ONLY STALWART IS LISTED, for a measured reason: 1.0 refuses to open a store
// created before it ("The data store was created by a Stalwart version prior
// to 1.0 and cannot be opened by this version") and the pod loops in
// CrashLoopBackOff. An upgrade going straight through would take mail down
// while reporting success on every other layer. The other components either
// have not left 0.x or migrate their schema on startup.
var migrationsImposees = map[string]string{
	"stalwart": "docs/stalwart-1.0.md",
}

// blocageMigrationMajeure reports whether this change crosses a major version
// of a component that requires an offline migration, and returns the blocker.
//
// It is a PURE function of the three strings, so the rule is testable without
// a cluster: the versions come from the registry and from Kubernetes, never
// from a file.
func blocageMigrationMajeure(e Etat) (string, bool) {
	doc, suivi := migrationsImposees[e.Nom]
	if !suivi || !e.Ecart {
		return "", false
	}
	avant, apres := majeur(e.Installee), majeur(e.Cible)
	// An unknown version (unreadable image, "-1") does not authorize anything:
	// we do not know what is in the store, so we do not overwrite it silently.
	if avant < 0 || apres < 0 || avant == apres {
		return "", false
	}
	return fmt.Sprintf("%s %s → %s crosses a major version whose data store is "+
		"incompatible: migrate the data offline first (%s), then re-run the "+
		"upgrade with --allow-major-migration.", e.Nom, e.Installee, e.Cible, doc), true
}

// majeur extracts the major number of a tag: "v1.0.3" and "1.0.3" give 1,
// "v0.16.27" gives 0, anything unreadable gives -1.
func majeur(tag string) int {
	tag = strings.TrimPrefix(strings.TrimSpace(tag), "v")
	avant, _, _ := strings.Cut(tag, ".")
	n, err := strconv.Atoi(avant)
	if err != nil {
		return -1
	}
	return n
}

// Preparer builds the upgrade plan.
//
// It modifies NOTHING: it is a diagnostic. `upgrade` must never touch an
// installation before showing what it will do.
func Preparer(ctx context.Context, cible []version.Composant) *Plan {
	return preparer(ctx, cible, false)
}

// preparerSansMajeures is the same preflight with the major-version migration
// blockers lifted — and ONLY those. The other refusals (degraded cluster,
// inconsistent registry, missing pin) stay absolute: the flag authorizes a
// data migration, it does not authorize upgrading an unhealthy installation.
func preparerSansMajeures(ctx context.Context, cible []version.Composant) *Plan {
	return preparer(ctx, cible, true)
}

func preparer(ctx context.Context, cible []version.Composant, ignorerMajeures bool) *Plan {
	p := &Plan{Etats: []Etat{}, Changements: []Etat{}, Blocages: []string{}, Alertes: []string{},
		MigrationsMajeures: []string{}}

	// 1. Does the cluster respond, and is it healthy? Upgrading a version on
	//    a degraded cluster makes it impossible to tell the original outage
	//    from the one we just introduced.
	// LA CIBLE, PAS SEULEMENT LE REGISTRE : le binaire lui-même est un composant
	// de l'installation (console, relais, rapporteur d'IP), et l'oublier ici est
	// ce qui fait répondre « rien à faire » à une installation qui tourne en
	// 0.8.4.
	enService := imagesEnService(ctx, cible)
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
		if img, ok := enService.images[c.Nom]; ok {
			e.Installee = version.TagDe(img)
			e.Depuis = img
			e.Arrete = enService.arretes[c.Nom]
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
		}
		// UN COMPOSANT ARRÊTÉ N'EST PAS UN COMPOSANT ABSENT, et le taire est
		// exactement ce qui s'est produit pendant la bascule Stalwart : le plan
		// affichait « not deployed » alors que le Deployment existait, à zéro
		// réplica. Le rejeu, lui, applique `replicas: 1` sur chaque couche :
		// il le redémarre. Le plan doit le dire AVANT, pas l'apprendre après.
		if e.Arrete {
			p.Alertes = append(p.Alertes, fmt.Sprintf(
				"%s : stopped (its workload is at 0 replicas, image %s) — "+
					"the replay will start it again at %s", e.Nom, e.Depuis, e.Cible))
		}
		if e.Installee != "" && e.Installee != e.Cible {
			e.Ecart = true
			p.Changements = append(p.Changements, e)
			// A MAJOR BUMP IS NOT AN ORDINARY UPGRADE when the data store
			// format changed: see migrationsImposees.
			if pb, ok := blocageMigrationMajeure(e); ok && !ignorerMajeures {
				p.Blocages = append(p.Blocages, pb)
				p.MigrationsMajeures = append(p.MigrationsMajeures, e.Nom)
			}
		}
		p.Etats = append(p.Etats, e)
	}

	sort.Slice(p.Etats, func(i, j int) bool { return p.Etats[i].Nom < p.Etats[j].Nom })
	p.Pret = len(p.Blocages) == 0
	return p
}

// enService is what the cluster says about the installation: the image of each
// component, and whether that component is stopped.
type enService struct {
	images  map[string]versionImage
	arretes map[string]bool
}

// imagesEnService reads, for each registry component, the image the
// installation uses.
//
// TWO SOURCES, IN THIS ORDER. The WORKLOAD (deployment, statefulset) comes
// first: its spec is what the installation declares, it survives a scale to
// zero, and a stray pod cannot overwrite it. The PODS come second, as a
// fallback for components that Kubernetes deploys through something else (the
// operators behind cnpg-system and cert-manager, a daemonset — those have no
// replica count to read).
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
//
// MEASURED FAILURES THIS ORDER FIXES (2026-11-09, Stalwart 1.0 window): a
// throwaway pod labelled app=stalwart running 1.0.3 made the plan report
// `= stalwart v1.0.3` while the deployment still pinned 0.16.27 — the exact
// drift the plan exists to catch; and a deployment scaled to zero (the
// migration procedure does that) made it report "not deployed", which also
// meant the major-version blocker could not fire: it needs a version to
// compare. Reading the workload first answers both.
func imagesEnService(ctx context.Context, composants []version.Composant) enService {
	specs, arretes := imagesDesWorkloads(ctx)
	return associerTout(specs, imagesDesPods(ctx), arretes, composants)
}

// imagesDesWorkloads reads the image each deployment or statefulset DECLARES,
// and remembers the ones scaled to zero.
//
// Daemonsets are left to the pod scan on purpose: they have no replica count,
// so "stopped" is not a state they can be in.
func imagesDesWorkloads(ctx context.Context) (images []string, arretes map[string]bool) {
	arretes = map[string]bool{}
	raw, err := kubectl(ctx, "get", "deploy,statefulset", "-A", "-o", "json")
	if err != nil {
		return nil, arretes
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Replicas *int `json:"replicas"`
				Template struct {
					Spec struct {
						Containers []struct {
							Image string `json:"image"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil, arretes
	}
	for _, w := range doc.Items {
		if !namespaceSuivi(w.Metadata.Namespace) {
			continue
		}
		// nil means "not set", which the API defaults to 1: only an explicit
		// zero means the operator stopped this workload.
		arrete := w.Spec.Replicas != nil && *w.Spec.Replicas == 0
		for _, c := range w.Spec.Template.Spec.Containers {
			if c.Image == "" {
				continue
			}
			images = append(images, c.Image)
			if arrete {
				arretes[depotDe(c.Image)] = true
			}
		}
	}
	return images, arretes
}

// imagesDesPods reads the image carried by every pod of the installation.
func imagesDesPods(ctx context.Context) []string {
	var images []string
	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return nil
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
		return nil
	}
	for _, p := range doc.Items {
		if !namespaceSuivi(p.Metadata.Namespace) {
			continue
		}
		for _, c := range p.Spec.Containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	return images
}

// namespaceSuivi decides which namespaces belong to the installation.
func namespaceSuivi(ns string) bool {
	return strings.HasPrefix(ns, "ceffio-") || ns == "cnpg-system" || ns == "cert-manager"
}

// depotsAlias lists, per component, the repositories a PREVIOUS version of the
// product used. Without it, an installation still running the old image would
// be reported "not deployed" instead of "to upgrade" — the very mistake this
// file exists to avoid (Valkey replaced Redis on the licence migration).
var depotsAlias = map[string][]string{
	"valkey": {"docker.io/valkey/valkey", "docker.io/library/redis"},
}

// associerTout maps each component to an image of the same repository,
// preferring what the workloads declare over what the pods carry.
//
// It is pure, so the rule is testable without a cluster.
func associerTout(specs, pods []string, arretes map[string]bool, composants []version.Composant) enService {
	parDepotSpecs := indexer(specs)
	parDepotPods := indexer(pods)

	out := enService{images: map[string]versionImage{}, arretes: map[string]bool{}}
	for _, c := range composants {
		depots := append([]string{depotDe(c.Image)}, depotsAlias[c.Nom]...)

		img := ""
		// THE WORKLOAD FIRST: its spec is the installation's declared state.
		for _, d := range depots {
			if img = plusFrequent(parDepotSpecs[d]); img != "" {
				break
			}
		}
		if img == "" {
			// No workload to read (a pod deployed by an operator, a daemonset):
			// fall back to what is running.
			for _, d := range depots {
				if img = plusFrequent(parDepotPods[d]); img != "" {
					break
				}
			}
		}
		if img == "" {
			continue
		}
		out.images[c.Nom] = img
		// The stopped state belongs to the workload the image came from: a
		// pod cannot come from a deployment at zero replicas.
		out.arretes[c.Nom] = arretes[depotDe(img)]
	}
	return out
}

// associer keeps the pod-only mapping, for the callers and tests that only
// care about "which image carries this repository".
func associer(images []string, composants []version.Composant) map[string]versionImage {
	return associerTout(nil, images, nil, composants).images
}

// indexer groups image references by repository.
func indexer(images []string) map[string][]string {
	parDepot := map[string][]string{}
	for _, img := range images {
		if d := depotDe(img); d != "" {
			parDepot[d] = append(parDepot[d], img)
		}
	}
	return parDepot
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
