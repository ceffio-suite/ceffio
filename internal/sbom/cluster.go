// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sbom

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Ecart is a difference between the registry and what actually runs.
//
// WHY THREE KINDS AND NOT ONE: the operator's next gesture differs for each.
// "hors-registre" means something runs that Ceffio does not describe — an
// operator's own container, or a drift to explain. "version" means the right
// component, but not the reference the registry pins. "absent" means a component
// the registry expects is nowhere to be seen.
type Ecart struct {
	Genre  string // "hors-registre", "version", "absent"
	Nom    string // the component or the image
	Detail string // what was expected, what was found
}

func (e Ecart) String() string {
	return fmt.Sprintf("%-14s %-24s %s", e.Genre, e.Nom, e.Detail)
}

// reference is what a pod asked for, and what the registry pins.
type reference struct {
	repo   string // "docker.io/library/nextcloud"
	tag    string // "34.0.3", empty when pinned by digest only
	digest string // "sha256:…", empty when pinned by tag only
}

// Comparer compares the document with the pods observed in the cluster.
//
// moduleInstalle answers, for the Go package that deploys a component, whether
// that module is expected to run on this installation. It is a parameter and not
// a lookup here: the module registry is a deployment concern, and this package
// has to stay testable without it.
//
// WHAT IS COMPARED, AND WHAT IS NOT: the registry pins the digest of the
// multi-architecture INDEX; a pod running by tag reports, in its status, the
// manifest digest of its OWN PLATFORM. For a perfectly correct installation those
// two digests differ — comparing them would report every image as drifted. The
// comparison therefore reads, from the pod's SPEC, the reference the operator
// asked for: a pod pinned by digest is compared by digest, a pod asking for a
// tag is compared by tag, and the two cases never mix.
func Comparer(doc Document, pods []corev1.Pod, moduleInstalle func(module string) bool) []Ecart {
	// One observation per repository: three replicas of the same image are one
	// fact, not three findings.
	observes := map[string]reference{}
	for _, pod := range pods {
		for _, conteneur := range pod.Spec.Containers {
			ref := decoupe(conteneur.Image)
			if ref.repo == "" {
				continue
			}
			if _, vu := observes[ref.repo]; !vu {
				observes[ref.repo] = ref
			}
		}
	}

	var ecarts []Ecart
	vus := map[string]bool{}

	for _, c := range doc.Components {
		image := propriete(c, "ceffio:image")
		if image == "" {
			continue
		}
		attendu := decoupe(image)
		vu, tourne := observes[attendu.repo]
		if !tourne {
			// UN COMPOSANT CONDITIONNEL N'EST PAS UN COMPOSANT MANQUANT : le
			// solveur DNS ne tourne que pour les fournisseurs hors catalogue.
			if propriete(c, "ceffio:optional") != "true" && moduleInstalle(propriete(c, "ceffio:module")) {
				ecarts = append(ecarts, Ecart{
					Genre: "absent", Nom: c.Name,
					Detail: "the registry has it, no pod runs it",
				})
			}
			continue
		}
		vus[attendu.repo] = true

		// DIGEST AGAINST DIGEST, TAG AGAINST TAG — never one against the other.
		if attendu.digest != "" && vu.digest != "" && attendu.digest != vu.digest {
			ecarts = append(ecarts, Ecart{
				Genre: "version", Nom: c.Name,
				Detail: fmt.Sprintf("running %s, registry pins %s", court(vu.digest), court(attendu.digest)),
			})
			continue
		}
		if attendu.tag != "" && vu.tag != "" && attendu.tag != vu.tag {
			ecarts = append(ecarts, Ecart{
				Genre: "version", Nom: c.Name,
				Detail: fmt.Sprintf("running tag %s, registry pins %s", vu.tag, attendu.tag),
			})
		}
	}

	// Images that run and that the registry does not describe. An operator's own
	// sidecar and a component Ceffio deploys without listing both have to be
	// visible.
	var inattendus []string
	for repo := range observes {
		if !vus[repo] {
			inattendus = append(inattendus, repo)
		}
	}
	sort.Strings(inattendus)
	for _, repo := range inattendus {
		ecarts = append(ecarts, Ecart{
			Genre: "hors-registre", Nom: repo,
			Detail: "runs in the cluster, absent from the registry",
		})
	}

	sort.SliceStable(ecarts, func(i, j int) bool {
		if ecarts[i].Genre != ecarts[j].Genre {
			return ecarts[i].Genre < ecarts[j].Genre
		}
		return ecarts[i].Nom < ecarts[j].Nom
	})
	return ecarts
}

// decoupe splits "docker.io/library/nextcloud:34.0.3@sha256:…" into its parts.
//
// THE ':' OF A REGISTRY PORT IS NOT A TAG SEPARATOR: "registry.local:5000/x"
// has no tag, and cutting at its last ':' would produce a nonsense version.
func decoupe(image string) reference {
	ref, digest, _ := strings.Cut(image, "@")
	ref = strings.TrimSpace(ref)
	tag := ""
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		tag = ref[i+1:]
		ref = ref[:i]
	}
	return reference{repo: ref, tag: tag, digest: digest}
}

func propriete(c Component, nom string) string {
	for _, p := range c.Properties {
		if p.Name == nom {
			return p.Value
		}
	}
	return ""
}

// court renders a digest in a form a human can compare by eye.
func court(digest string) string {
	if i := strings.Index(digest, ":"); i >= 0 {
		digest = digest[i+1:]
	}
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
