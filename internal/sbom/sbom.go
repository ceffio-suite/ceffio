// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package sbom describes, in CycloneDX, what an installation of Ceffio runs.
//
// WHY CYCLONEDX AND NOT A HOUSE FORMAT: the document has to be readable by
// Grype, by a buyer's security team, and by the CRA's future Single Reporting
// Platform. CycloneDX JSON is the format those three already read; a bespoke
// JSON would have to be explained every time, and explained again to every new
// reader.
//
// WHAT THE DOCUMENT CONTAINS: the binary itself (version, commit, date), and
// every component of the version registry — name, version, image WITH ITS
// DIGEST, role, licence, and the module that deploys it. The digest is what
// makes the document worth something: a tag can be repointed, a digest cannot.
//
// WHAT IT DOES NOT CONTAIN, and says so: the internal dependencies of the
// third-party images. Their SBOM belongs to their publisher; inventing one here
// would be a guess dressed as a proof.
package sbom

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// Document is the CycloneDX 1.6 JSON document, reduced to what this project
// emits. Everything here is required or used; nothing is decorative.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata carries the tool and the component the document is about.
type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []Tool     `json:"tools"`
	Component *Component `json:"component,omitempty"`
}

// Tool identifies the producer: an SBOM without it is a document with no
// author, and the reader cannot know which version judged what.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is either the binary (type "application") or a deployed component
// (type "container"). The CycloneDX "type" field is an enum; these two are the
// only ones this project emits.
type Component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Purl       string     `json:"purl,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// License carries the SPDX identifier. `id` is an enum in the official schema,
// so an invented string fails the test that validates the document.
//
// NOASSERTION IS AN EXPRESSION, NOT AN ID: the official schema accepts only real
// SPDX identifiers in `license.id`, and `NOASSERTION` belongs to the
// `expression` form. Writing it as an id fails validation — which is how the
// difference was found, by the test that reads the schema rather than our idea
// of it.
type License struct {
	License    *LicenceID `json:"license,omitempty"`
	Expression string     `json:"expression,omitempty"`
}

// licence builds the right shape for what we know: an identifier when the source
// states one, an expression otherwise.
func licence(id string) License {
	if id == "" || id == "NOASSERTION" {
		return License{Expression: "NOASSERTION"}
	}
	return License{License: &LicenceID{ID: id}}
}

// LicenceID is the `license` object of CycloneDX.
type LicenceID struct {
	ID string `json:"id"`
}

// Property is a name/value pair from the CycloneDX property namespace.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Construire builds the document from the registry.
//
// THE COMPONENTS ARE SORTED BY NAME: two runs on the same installation must
// produce the same document, byte for byte, or a diff between two releases says
// nothing. A map iteration order would make the document change on every run.
func Construire(composants []version.Composant) Document {
	tri := make([]version.Composant, len(composants))
	copy(tri, composants)
	sort.Slice(tri, func(i, j int) bool { return tri[i].Nom < tri[j].Nom })

	doc := Document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: Metadata{
			Tools: []Tool{{Vendor: "MANDEM", Name: "ceffio", Version: version.Binary}},
		},
		Components: make([]Component, 0, len(tri)),
	}

	for _, c := range tri {
		doc.Components = append(doc.Components, Component{
			Type:    "container",
			Name:    c.Nom,
			Version: c.Version,
			Purl:    purlDe(c.Image),
			// NEVER A GUESS: the registry carries the SPDX identifier verified
			// at the upstream source, or NOASSERTION.
			Licenses: []License{licence(c.Licence)},
			Properties: []Property{
				{Name: "ceffio:role", Value: c.Role},
				{Name: "ceffio:module", Value: c.Module},
				{Name: "ceffio:image", Value: c.Image},
				{Name: "ceffio:optional", Value: fmt.Sprintf("%t", c.Optionnel)},
				{Name: "ceffio:pinned", Value: "true"},
			},
		})
	}
	return doc
}

// AjouteLeBinaire puts the ceffio binary itself in metadata.component: the
// document must say which version produced it.
func AjouteLeBinaire(doc *Document) {
	doc.Metadata.Component = &Component{
		Type:    "application",
		Name:    "ceffio",
		Version: version.Binary,
		Purl:    "pkg:generic/ceffio@" + version.Binary,
		Properties: []Property{
			{Name: "ceffio:commit", Value: version.Commit},
			{Name: "ceffio:built", Value: version.Date},
		},
	}
}

// purlDe builds the package URL of a container image.
//
// THE DIGEST IS IN THE PURL when the registry entry is pinned: that is what
// makes the purl identify bytes rather than a name. `repository_url` keeps the
// registry and the repository path readable without parsing.
func purlDe(image string) string {
	ref, digest, _ := strings.Cut(image, "@")
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return "pkg:oci/" + ref
	}
	// "docker.io/library/nextcloud:34.0.3" → name "library/nextcloud", repo url
	// "docker.io", version "34.0.3".
	nomEtRegistre, tag := ref[:i], ref[i+1:]
	registre := ""
	if j := strings.Index(nomEtRegistre, "/"); j >= 0 {
		registre, nomEtRegistre = nomEtRegistre[:j], nomEtRegistre[j+1:]
	}
	purl := "pkg:oci/" + nomEtRegistre + "@" + tag
	if digest != "" {
		purl = "pkg:oci/" + nomEtRegistre + "@" + digest
	}
	if registre != "" {
		purl += "?repository_url=" + registre
	}
	return purl
}

func licenceOuNoAssertion(l string) string {
	if l == "" {
		return "NOASSERTION"
	}
	return l
}

// Decrit rend le document lisible en une ligne, pour les journaux.
func Decrit(d Document) string {
	return fmt.Sprintf("%d composant(s), binaire %s", len(d.Components), version.Binary)
}

// AjouteLaPlateforme appends the components Ceffio does not pin.
//
// THEY CARRY `ceffio:pinned=false`, and that property is the whole point: an
// image whose version belongs to a chart is reported, not claimed. The document
// says what sits on the machine; it does not pretend Ceffio chose the version.
func AjouteLaPlateforme(doc *Document, composants []version.Composant) {
	for _, c := range composants {
		doc.Components = append(doc.Components, Component{
			Type:     "container",
			Name:     c.Nom,
			Version:  versionDe(c.Image),
			Purl:     purlDe(c.Image),
			Licenses: []License{licence(c.Licence)},
			Properties: []Property{
				{Name: "ceffio:role", Value: c.Role},
				{Name: "ceffio:module", Value: c.Module},
				{Name: "ceffio:image", Value: c.Image},
				{Name: "ceffio:optional", Value: fmt.Sprintf("%t", c.Optionnel)},
				{Name: "ceffio:pinned", Value: "false"},
			},
		})
	}
	sort.SliceStable(doc.Components, func(i, j int) bool {
		return doc.Components[i].Name < doc.Components[j].Name
	})
}

// versionDe returns the tag of an image reference, empty when it has none.
func versionDe(image string) string {
	if strings.Contains(image, "@") {
		return ""
	}
	if i := strings.LastIndex(image, ":"); i >= 0 && !strings.Contains(image[i:], "/") {
		return image[i+1:]
	}
	return ""
}
