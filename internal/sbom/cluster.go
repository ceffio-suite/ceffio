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
//
// A COMPONENT THE DOCUMENT MARKS `ceffio:pinned=false` IS NEVER COMPARED: its
// version belongs to a chart Ceffio does not control. It is only counted as
// known, and it is still subject to the divergence check below.
func Comparer(doc Document, pods []corev1.Pod, moduleInstalle func(module string) bool) []Ecart {
	// repositif → the references actually running. A repository can run several
	// at once, and that is a finding of its own.
	observes := map[string]map[string]reference{}
	for _, pod := range pods {
		for _, conteneur := range pod.Spec.Containers {
			ref := decoupe(conteneur.Image)
			if ref.repo == "" {
				continue
			}
			if observes[ref.repo] == nil {
				observes[ref.repo] = map[string]reference{}
			}
			observes[ref.repo][ref.String()] = ref
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
		refs, tourne := observes[attendu.repo]
		if !tourne {
			// UN COMPOSANT CONDITIONNEL N'EST PAS UN COMPOSANT MANQUANT : le
			// solveur DNS ne tourne que pour les fournisseurs hors catalogue.
			// ET UN COMPOSANT NON ÉPINGLÉ N'EST PAS ATTENDU : la couche de
			// stockage peut ne pas être utilisée.
			if propriete(c, "ceffio:pinned") != "false" &&
				propriete(c, "ceffio:optional") != "true" &&
				moduleInstalle(propriete(c, "ceffio:module")) {
				ecarts = append(ecarts, Ecart{
					Genre: "absent", Nom: c.Name,
					Detail: "the registry has it, no pod runs it",
				})
			}
			continue
		}
		vus[attendu.repo] = true

		if propriete(c, "ceffio:pinned") == "false" {
			// Sa version appartient au chart : rien à comparer.
			continue
		}

		// DIGEST AGAINST DIGEST, TAG AGAINST TAG — never one against the other.
		// A component corresponds as soon as ONE of the references running for
		// its repository corresponds; a pod that asks for the registry's tag is
		// not drifted because the registry also documents a digest.
		correspond := false
		for _, vu := range refs {
			if referencesCorrespondent(vu, attendu) {
				correspond = true
			}
		}
		if !correspond {
			ecarts = append(ecarts, Ecart{
				Genre: "version", Nom: c.Name,
				Detail: fmt.Sprintf("running %s, registry pins %s", listeRefs(refs), attendu.String()),
			})
		}
	}

	// Images that run and that the document does not describe.
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

	// TWO VERSIONS OF THE SAME IMAGE AT ONCE. A rolling update shows this
	// briefly and it is normal; an installation that sits in it is not — this
	// is how a component deployed once and never refreshed is found.
	for repo, refs := range observes {
		if len(refs) > 1 {
			ecarts = append(ecarts, Ecart{
				Genre: "divergence", Nom: repo,
				Detail: fmt.Sprintf("%d références tournent ensemble : %s", len(refs), listeRefs(refs)),
			})
		}
	}

	sort.SliceStable(ecarts, func(i, j int) bool {
		if ecarts[i].Genre != ecarts[j].Genre {
			return ecarts[i].Genre < ecarts[j].Genre
		}
		return ecarts[i].Nom < ecarts[j].Nom
	})
	return ecarts
}

// referencesCorrespondent compares what is comparable: a digest when both sides
// have one, a tag when neither does. Absent on one side means "no claim", not
// "mismatch".
func referencesCorrespondent(vu, attendu reference) bool {
	switch {
	case vu.digest != "" && attendu.digest != "":
		return vu.digest == attendu.digest
	case vu.tag != "" && attendu.tag != "":
		return vu.tag == attendu.tag
	default:
		return true
	}
}

// listeRefs renders the references observed for one repository, shortened.
func listeRefs(refs map[string]reference) string {
	var noms []string
	for _, r := range refs {
		noms = append(noms, r.String())
	}
	sort.Strings(noms)
	return strings.Join(noms, ", ")
}

// listeTags renders only the tags, for the message of a tag comparison.
func listeTags(refs map[string]reference) string {
	var noms []string
	for _, r := range refs {
		if r.tag != "" {
			noms = append(noms, r.tag)
		} else {
			noms = append(noms, court(r.digest))
		}
	}
	sort.Strings(noms)
	return strings.Join(noms, ", ")
}

// String renders a reference the way an operator reads it: tag and short
// digest, one or the other.
func (r reference) String() string {
	switch {
	case r.tag != "" && r.digest != "":
		return r.tag + "@" + court(r.digest)
	case r.tag != "":
		return r.tag
	default:
		return court(r.digest)
	}
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
