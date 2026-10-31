// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sbom

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// Les schémas officiels du CycloneDX 1.6, EMBARQUÉS : un test qui télécharge son
// schéma ne teste plus rien le jour où le réseau tombe, et il dépend de ce qui
// sera publié demain à cette URL.
//
//go:embed testdata/bom-1.6.schema.json testdata/spdx.schema.json testdata/jsf-0.82.schema.json
var schemas embed.FS

// compilateur compares the documents against the official schema.
func compilateur(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	for _, nom := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		brut, err := schemas.ReadFile("testdata/" + nom)
		if err != nil {
			t.Fatalf("reading the embedded schema %s: %v", nom, err)
		}
		var doc any
		if err := json.Unmarshal(brut, &doc); err != nil {
			t.Fatalf("parsing %s: %v", nom, err)
		}
		id := "http://cyclonedx.org/schema/" + nom
		if err := c.AddResource(id, doc); err != nil {
			t.Fatalf("adding %s: %v", nom, err)
		}
	}
	sch, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatalf("compiling the CycloneDX schema: %v", err)
	}
	return sch
}

// TestLeDocumentValideLeSchemaCycloneDX: the document is checked against the
// OFFICIAL schema, not against what we believe CycloneDX says.
func TestLeDocumentValideLeSchemaCycloneDX(t *testing.T) {
	doc := Construire(version.Registry)
	AjouteLeBinaire(&doc)
	// LA PLATEFORME AUSSI : ses entrées portent `ceffio:pinned=false`, et le
	// schéma officiel doit accepter un composant sans version.
	AjouteLaPlateforme(&doc, version.Plateforme)
	doc.Metadata.Timestamp = "2026-10-30T12:00:00Z"

	brut, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var valeur any
	if err := json.Unmarshal(brut, &valeur); err != nil {
		t.Fatalf("re-parsing: %v", err)
	}
	if err := compilateur(t).Validate(valeur); err != nil {
		t.Fatalf("the document does not validate against the CycloneDX 1.6 schema: %v", err)
	}
}

// TestLeDocumentEstStable: two runs on the same registry must produce the same
// document, byte for byte. An SBOM whose component order changes on every run
// cannot be diffed between two releases — which is the only way to see what
// changed.
func TestLeDocumentEstStable(t *testing.T) {
	premier, _ := json.Marshal(Construire(version.Registry))
	second, _ := json.Marshal(Construire(version.Registry))
	if !bytes.Equal(premier, second) {
		t.Error("two builds of the same registry produced different documents")
	}
}

// TestUneLicenceInconnueNVautPasUneSupposition: an empty licence becomes
// NOASSERTION, never "Apache-2.0" because it is the most common one.
func TestUneLicenceInconnueNVautPasUneSupposition(t *testing.T) {
	doc := Construire([]version.Composant{{Nom: "x", Image: "docker.io/x/y:1", Licence: ""}})
	// NOASSERTION is an EXPRESSION in CycloneDX, not an identifier: the official
	// schema rejects it in `license.id`.
	l := doc.Components[0].Licenses[0]
	if l.Expression != "NOASSERTION" {
		t.Errorf("expression = %q, expected NOASSERTION", l.Expression)
	}
	if l.License != nil {
		t.Errorf("an unknown licence must not be written as an SPDX id (%v)", l.License)
	}
}

// TestChaqueComposantDUregistrePorteSaLicence: the registry is complete, so the
// document does not fall back to NOASSERTION for a component we actually know.
func TestChaqueComposantDUregistrePorteSaLicence(t *testing.T) {
	for _, c := range version.Registry {
		if c.Licence == "" {
			t.Errorf("%s: no licence in the registry — the SBOM would say NOASSERTION", c.Nom)
		}
	}
}
