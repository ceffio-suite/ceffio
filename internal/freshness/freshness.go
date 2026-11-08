// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package freshness answers a question the registry cannot: is the version we
// pin still the one the upstream project publishes?
//
// WHY IT EXISTS. Every image in internal/version is pinned by digest, and that
// pin is what makes the SBOM true. But a pin is a photograph: nothing in the
// repository notices when upstream moves on, so an installation can run a
// component two years behind without a single warning. `make pin-digests`
// re-pins when somebody asks; this package is what asks.
package freshness

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// Source lists the tags a registry publishes for one repository.
//
// An interface, so the comparison below is testable without a network, and so
// a registry that needs a token is one implementation, not a change in the
// logic.
type Source interface {
	Tags(ctx context.Context, repository string) ([]string, error)
}

// Observation is one component, compared with what upstream publishes.
type Observation struct {
	Nom         string // the registry name
	Depot       string // the repository, without tag or digest
	Courante    string // the tag the registry pins
	Recente     string // the newest comparable tag upstream publishes
	PlusRecente bool   // true when Recente is newer than Courante
	Note        string // why there is no comparison, when there is none
}

// Action is what a maintainer should do about it.
func (o Observation) Action() string {
	switch {
	case o.PlusRecente:
		return "bump"
	case o.Note != "":
		return "manual"
	default:
		return "up to date"
	}
}

// Comparer walks the components and asks the source for each repository.
//
// A FAILURE ON ONE COMPONENT DOES NOT STOP THE OTHERS: a registry that answers
// 429 for one repository must not hide the twelve others; the failure becomes
// the Note of that line, which is exactly what the reader needs to see.
func Comparer(ctx context.Context, src Source, composants []version.Composant) []Observation {
	var sorties []Observation
	for _, c := range composants {
		o := Observation{Nom: c.Nom, Depot: DepotDe(c.Image)}
		o.Courante = version.TagDe(c.Image)
		o.Recente, o.Note = plusRecente(ctx, src, o.Depot, o.Courante)
		o.PlusRecente = o.Note == "" && o.Recente != "" && o.Recente != o.Courante
		sorties = append(sorties, o)
	}
	sort.SliceStable(sorties, func(i, j int) bool { return sorties[i].Nom < sorties[j].Nom })
	return sorties
}

// plusRecente asks the source and picks the highest tag of the SAME SHAPE.
//
// THE SHAPE IS THE WHOLE DIFFICULTY. A registry publishes one repository with
// many flavours: nextcloud 34.0.3 and 35.0.2-fpm-alpine are the same project but
// not the same image; oauth2-proxy publishes -s390x; nats publishes -scratch;
// valkey publishes -rc2-trixie. Comparing across flavours produces findings that
// are not wrong about the registry and are useless to the maintainer — the
// failure mode of a check nobody reads.
//
// So a candidate is comparable only when its suffix (everything from the first
// '-') is exactly the pinned tag's suffix. "4.18" against "4.18.0" is a bump of
// zero: the numbers are padded before comparing, so a trailing zero is not a
// release.
func plusRecente(ctx context.Context, src Source, depot, courante string) (string, string) {
	if depot == "" {
		return "", "no repository"
	}
	noyau, suffixe, comparable := decoupe(courante)
	if !comparable {
		return "", "étiquette non comparable : " + courante
	}
	tags, err := src.Tags(ctx, depot)
	if err != nil {
		return "", "registry: " + err.Error()
	}
	meilleur := courante
	for _, t := range tags {
		n, sfx, ok := decoupe(t)
		if !ok || sfx != suffixe {
			continue
		}
		if plusGrand(n, noyau) {
			meilleur, noyau = t, n
		}
	}
	if meilleur == courante {
		return courante, ""
	}
	return meilleur, ""
}

// decoupe separates the numeric core from the flavour suffix.
//
//	"34.0.3"          → [34 0 3],      "",        true
//	"1.4.3-1"         → [1 4 3],       "-1",      true
//	"v7.15.5"         → [7 15 5],      "",        true
//	"20261014_095932" → [20261014 95932], "",     true
//	"8703323"         → not comparable: a commit hash, not a version
//	"release"         → not comparable: a name
func decoupe(tag string) ([]int, string, bool) {
	ref := strings.TrimLeft(tag, "vV")
	noyau, suffixe, _ := strings.Cut(ref, "-")
	if suffixe != "" {
		suffixe = "-" + suffixe
		// UN SUFFIXE PUREMENT NUMÉRIQUE EST UN NUMÉRO DE BUILD, PAS UNE VARIANTE :
		// janus publie 1.4.3, nous publions 1.4.3-1 puis 1.4.3-2. Le traiter comme
		// une saveur rendrait nos propres builds incomparables.
		if n, err := strconv.Atoi(suffixe[1:]); err == nil {
			noyau = noyau + "." + strconv.Itoa(n)
			suffixe = ""
		}
	}
	var nombres []int
	for _, champ := range strings.Split(noyau, ".") {
		n, err := strconv.Atoi(champ)
		if err != nil {
			return nil, "", false
		}
		nombres = append(nombres, n)
	}
	if len(nombres) == 0 {
		return nil, "", false
	}
	// UN HACHAGE DE COMMIT N'EST PAS UNE VERSION : un seul nombre, très grand.
	if len(nombres) == 1 && nombres[0] >= 1_000_000 {
		return nil, "", false
	}
	return nombres, suffixe, true
}

// plusGrand compares two numeric cores, padding the shorter with zeros: 4.18
// and 4.18.0 are the same release, not two.
func plusGrand(candidat, reference []int) bool {
	n := len(candidat)
	if len(reference) > n {
		n = len(reference)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(candidat) {
			a = candidat[i]
		}
		if i < len(reference) {
			b = reference[i]
		}
		if a != b {
			return a > b
		}
	}
	return false
}

// DepotDe strips the tag and the digest from an image reference.
//
// The ':' of a registry PORT is not a tag separator: "registry.local:5000/x"
// has no tag, and cutting at its last ':' would invent one.
func DepotDe(image string) string {
	ref, _, _ := strings.Cut(image, "@")
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	return ref
}

// "release", "latest" and the date stamps some projects use are not versions:
// pretending to compare them would produce a verdict that means nothing.
func Comparable(tag string) bool {
	return premierSegmentNumerique(tag) >= 0
}

// WHY NOT semver: the registry contains 9.4.0.1 (four segments), 1.4.3-1 (a
// build suffix) and 34.0.3 — a strict semver parser would reject most of them
// and call them "not comparable", which is the opposite of what is wanted here.
func plusGrande(candidate, reference string) bool {
	a := segments(candidate)
	b := segments(reference)
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return len(a) > len(b)
}

func segments(tag string) []int {
	var out []int
	for _, champ := range strings.FieldsFunc(tag, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+' || r == 'v' || r == 'V'
	}) {
		n, err := strconv.Atoi(champ)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func premierSegmentNumerique(tag string) int {
	for i, champ := range strings.FieldsFunc(tag, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+' || r == 'v' || r == 'V'
	}) {
		if _, err := strconv.Atoi(champ); err == nil {
			return i
		}
	}
	return -1
}

// Rapport renders the observations as the table the reviewer reads.
func Rapport(obs []Observation) string {
	var b strings.Builder
	b.WriteString("| Composant | Épinglé | Publie | Verdict |\n|---|---|---|---|\n")
	for _, o := range obs {
		verdict := o.Action()
		if o.Note != "" {
			verdict = "à décider — " + o.Note
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", o.Nom, o.Courante, o.Recente, verdict)
	}
	return b.String()
}

// AChanger returns the observations that need a human: a newer version, or a
// repository we could not compare.
func AChanger(obs []Observation) []Observation {
	var out []Observation
	for _, o := range obs {
		if o.PlusRecente || o.Note != "" {
			out = append(out, o)
		}
	}
	return out
}
