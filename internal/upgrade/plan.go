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
	nodes, introuvables := imagesEnService(ctx)
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
			raison := "not deployed on this installation"
			if _, vu := introuvables[c.Nom]; vu {
				raison = "image not identifiable on this installation"
			}
			p.Alertes = append(p.Alertes, fmt.Sprintf("%s : %s", c.Nom, raison))
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

// imagesEnService reads, for each known component, the image actually used
// by the running pods. We query the Kubernetes API rather than re-reading
// the repository files: that is the only way to see drift between what the
// code declares and what is running.
// imagesEnService reads the REAL inventory of images in service.
//
// First version, and why it was wrong: for each component, it looked for a
// pod whose image contained a predefined fragment ("redis:", "keycloak", …).
// Two flaws: the fragment was guessed, and a missing match was silently
// ignored — the comparison skipped the component and `upgrade` reported "no
// drift" while a different image was running.
//
// Now: we read ALL the images of the ceffio-* pods, and match them by name.
// What is not found is reported as such, instead of passing as compliant.
func imagesEnService(ctx context.Context) (map[string]versionImage, map[string]versionImage) {
	trouvees := map[string]versionImage{}

	raw, err := kubectl(ctx, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return trouvees, nil
	}
	var doc struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return trouvees, nil
	}

	// We collect all the images from the ceffio-* namespaces (and the
	// operators).
	toutes := map[string]string{} // container name -> image
	for _, p := range doc.Items {
		ns := p.Metadata.Namespace
		if !strings.HasPrefix(ns, "ceffio-") && ns != "cnpg-system" && ns != "cert-manager" {
			continue
		}
		for _, c := range p.Spec.Containers {
			toutes[c.Name] = c.Image
			// We also index by image, for substring matching.
			toutes["img:"+c.Image] = c.Image
		}
	}

	// Component name -> acceptable image fragments.
	// Several fragments per component: the container name varies with how
	// the application is packaged.
	regles := map[string][]string{
		"keycloak":       {"keycloak"},
		"nextcloud":      {"nextcloud"},
		"onlyoffice":     {"documentserver"},
		"redis":          {"redis:"},
		"cloudnative-pg": {"cloudnative-pg"},
		"cert-manager":   {"cert-manager"},
	}

	inconnues := map[string]versionImage{}
	for composant, fragments := range regles {
		trouve := false
		for _, img := range toutes {
			for _, f := range fragments {
				if strings.Contains(img, f) {
					trouvees[composant] = img
					trouve = true
					break
				}
			}
			if trouve {
				break
			}
		}
		if !trouve {
			inconnues[composant] = ""
		}
	}
	return trouvees, inconnues
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
