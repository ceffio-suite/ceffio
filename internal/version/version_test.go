// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistryEstCoherent verifies what the registry's documentation promises:
// "Any change to an image in a module MUST be carried over here: the
// VerifierCoherence() function checks it and the test verifies it."
//
// This test was missing. A promise written in a comment and not verified
// drifts at the first hurried change — and that is exactly the kind of hole
// through which a floating version reaches production.
func TestRegistryEstCoherent(t *testing.T) {
	if problemes := VerifierCoherence(); len(problemes) > 0 {
		for _, p := range problemes {
			t.Errorf("inconsistent registry: %s", p)
		}
	}
}

// TestAucuneVersionFlottante forbids `latest` and `stable`.
//
// A component tracking `latest` cannot be upgraded reproducibly: you know
// neither what runs before, nor what will run after. That is the rule this
// package set for itself.
func TestAucuneVersionFlottante(t *testing.T) {
	for _, c := range Registry {
		switch c.Version {
		case "":
			t.Errorf("%s: image without an explicit tag (%s)", c.Nom, c.Image)
		case "latest", "stable":
			t.Errorf("%s: floating tag %q, a pinned tag is required", c.Nom, c.Version)
		}
	}
}

// TestImagesQualifiees requires an explicit registry in the image reference.
//
// WHY: `openbao/openbao:2.7.1` and `docker.io/openbao/openbao:2.7.1` do not
// necessarily designate the same thing depending on the engine configuration.
// On a machine where a mirror is configured, the short form can pull something
// other than what you think — and that is the kind of failure only seen in
// production, on somebody else's machine.
func TestImagesQualifiees(t *testing.T) {
	for _, c := range Registry {
		if !strings.Contains(strings.SplitN(c.Image, "/", 2)[0], ".") {
			t.Errorf("%s: unqualified image reference (%s) — prefix with docker.io/", c.Nom, c.Image)
		}
	}
}

// TestNomsUniques and paths: two components cannot carry the same name,
// otherwise ParNom returns the first and the second becomes unfindable.
func TestNomsUniques(t *testing.T) {
	vus := make(map[string]bool, len(Registry))
	for _, c := range Registry {
		if vus[c.Nom] {
			t.Errorf("duplicate component name: %s", c.Nom)
		}
		vus[c.Nom] = true
	}
}

// TestParNomTrouveTout verifies the registry is usable: every declared
// component must be findable. A registry you cannot query is of little use.
func TestParNomTrouveTout(t *testing.T) {
	for _, c := range Registry {
		got, ok := ParNom(c.Nom)
		if !ok {
			t.Errorf("ParNom(%q) finds nothing although the component is declared", c.Nom)
			continue
		}
		if got.Image != c.Image {
			t.Errorf("%s: ParNom returns image %q instead of %q", c.Nom, got.Image, c.Image)
		}
	}
}

// TestOpenBaoDeclare explicitly verifies the vault appears in the registry.
//
// WHY A TEST NAMED FOR ONE COMPONENT: the vault is deployed by internal/vault
// and MUST appear here, otherwise `upgrade` and `status` ignore it — a
// component that runs without being declared is one you can neither upgrade
// nor diagnose.
func TestOpenBaoDeclare(t *testing.T) {
	c, ok := ParNom("openbao")
	if !ok {
		t.Fatal("the vault (openbao) is deployed by internal/vault but absent from the registry")
	}
	if !strings.Contains(c.Image, "openbao") {
		t.Errorf("unexpected image for openbao: %s", c.Image)
	}
	if c.Module != "internal/vault" {
		t.Errorf("module declared for openbao: %q, expected internal/vault", c.Module)
	}
}

// avecBinary runs fn with Binary replaced, then restores the value: the
// ImageTag tests modify a global state of the package, and a test that leaves
// its value behind skews the following ones in the same package.
func avecBinary(t *testing.T, valeur string, fn func()) {
	t.Helper()
	ancien := Binary
	Binary = valeur
	defer func() { Binary = ancien }()
	fn()
}

// TestImageTagRelease verifies the "release" regime: a git tag v0.6.0 must
// produce the image tag 0.6.0, without the "v" (Docker image tags never carry
// it in this repository).
func TestImageTagRelease(t *testing.T) {
	cas := []struct{ binaire, attendu string }{
		{"v0.6.0", "0.6.0"},
		{"v0.6.0-rc.1", "0.6.0-rc.1"},
		{"v12.34.56", "12.34.56"},
	}
	for _, c := range cas {
		avecBinary(t, c.binaire, func() {
			if got := ImageTag(); got != c.attendu {
				t.Errorf("ImageTag() avec Binary=%q = %q, attendu %q", c.binaire, got, c.attendu)
			}
		})
	}
}

// TestImageTagDev verifies the "development" regime: without a release
// version, the tag is derived from the content of the binary (dev- prefix +
// truncated SHA-256). We inject a fake path via cheminExecutable so as not to
// depend on the real test binary.
func TestImageTagDev(t *testing.T) {
	// Temporary file instead of the real executable: the hash must be
	// computed on a content that is known and stable during the test.
	fichier := filepath.Join(t.TempDir(), "faux-binaire")
	if err := os.WriteFile(fichier, []byte("contenu de test"), 0o755); err != nil {
		t.Fatal(err)
	}
	ancien := cheminExecutable
	cheminExecutable = func() (string, error) { return fichier, nil }
	defer func() { cheminExecutable = ancien }()

	for _, dev := range []string{"0.0.0-dev", "0.1.0-dev", "feat/version-unique"} {
		avecBinary(t, dev, func() {
			got := ImageTag()
			if !strings.HasPrefix(got, "dev-") {
				t.Fatalf("ImageTag() avec Binary=%q = %q, attendu un préfixe dev-", dev, got)
			}
			if got == "dev-" {
				t.Errorf("tag de développement sans hachage : %q", got)
			}
		})
	}
}

// TestImageTagDevStable verifies that two successive calls give the same tag:
// a tag that would change between the image build and its deployment would
// reference a nonexistent image.
func TestImageTagDevStable(t *testing.T) {
	fichier := filepath.Join(t.TempDir(), "faux-binaire")
	if err := os.WriteFile(fichier, []byte("contenu de test"), 0o755); err != nil {
		t.Fatal(err)
	}
	ancien := cheminExecutable
	cheminExecutable = func() (string, error) { return fichier, nil }
	defer func() { cheminExecutable = ancien }()

	avecBinary(t, "0.0.0-dev", func() {
		premier := ImageTag()
		second := ImageTag()
		if premier != second {
			t.Errorf("ImageTag() non stable : %q puis %q", premier, second)
		}
	})
}

// TestImageTagJamaisVide verifies the function's central promise: even when
// the binary cannot be found (nonexistent path OR os.Executable error), the
// tag is never empty. An empty tag would produce an invalid image reference
// and break the deployment.
func TestImageTagJamaisVide(t *testing.T) {
	ancien := cheminExecutable
	defer func() { cheminExecutable = ancien }()

	avecBinary(t, "0.0.0-dev", func() {
		// Case 1: os.Executable fails.
		cheminExecutable = func() (string, error) { return "", fmt.Errorf("executable not found") }
		if got := ImageTag(); got == "" {
			t.Error("ImageTag() vide quand le chemin de l'exécutable est introuvable")
		}

		// Case 2: the returned path points at no real file.
		cheminExecutable = func() (string, error) { return "/chemin/qui/nexiste/pas", nil }
		if got := ImageTag(); got == "" {
			t.Error("ImageTag() vide quand le binaire est illisible")
		}
	})
}

// TestUnDigestNeMasquePasLEtiquette: an image pinned by tag AND digest keeps its
// tag as Version.
//
// WHY IT MATTERS: the operator reads the version in `ceffio status` and in the
// upgrade plan. A digest suffix that swallowed the tag would show a hexadecimal
// string where a version belongs, and the upgrade diff would compare digests
// instead of versions.
func TestUnDigestNeMasquePasLEtiquette(t *testing.T) {
	cas := map[string]string{
		"ghcr.io/ceffio-suite/ceffio-capture:v0.8.3@sha256:08a4fb37d5c0": "v0.8.3",
		"docker.io/library/nextcloud:34.0.3":                             "34.0.3",
		"ghcr.io/ceffio-suite/ceffio-capture@sha256:08a4fb37d5c0":        "", // digest seul : pas d'étiquette
		"registry.local:5000/team/app:1.2.3":                             "1.2.3",
	}
	for image, attendu := range cas {
		if got := TagDe(image); got != attendu {
			t.Errorf("TagDe(%q) = %q, attendu %q", image, got, attendu)
		}
	}
}

// TestChaqueImageEstEpingleeParDigest: a tag is a pointer the registry can move.
//
// WHY THIS IS A TEST AND NOT A CONVENTION: the installer deploys these images to
// machines that keep files, mail and identities. A tag repointed upstream — by
// accident, by a compromise, by a "helpful" rebuild — would ship other bytes to
// the next installation, with no diff in this repository to show it. The digest
// is the only reference that cannot move.
func TestChaqueImageEstEpingleeParDigest(t *testing.T) {
	for _, c := range Registry {
		if !strings.Contains(c.Image, "@sha256:") {
			t.Errorf("%s: image %q carries no digest — run `make pin-digests`", c.Nom, c.Image)
		}
	}
}

// TestComposantBinaireNExisteQuePourUneVersionPubliee: a development build names
// no image anybody can pull, so it must not enter the upgrade target.
func TestComposantBinaireNExisteQuePourUneVersionPubliee(t *testing.T) {
	ancien := Binary
	defer func() { Binary = ancien }()

	Binary = "v0.10.3"
	c, ok := ComposantBinaire()
	if !ok {
		t.Fatal("a release binary must give a component")
	}
	if c.Image != "ghcr.io/ceffio-suite/ceffio:0.10.3" || c.Version != "0.10.3" {
		t.Errorf("component = %+v, expected the 0.10.3 image", c)
	}

	for _, dev := range []string{"0.0.0-dev", "dev-inconnu", ""} {
		Binary = dev
		if _, ok := ComposantBinaire(); ok {
			t.Errorf("%q: a development build must not give a component", dev)
		}
	}
}

// TestChaqueComposantDePlateformePorteSaLicence: the platform list is what an
// operator reads to know what runs; an empty licence would silently become
// NOASSERTION.
func TestChaqueComposantDePlateformePorteSaLicence(t *testing.T) {
	vus := map[string]bool{}
	for _, c := range Plateforme {
		if c.Licence == "" {
			t.Errorf("%s: no licence", c.Nom)
		}
		if c.Image == "" || c.Nom == "" {
			t.Errorf("%s: incomplete entry", c.Nom)
		}
		if vus[c.Image] {
			t.Errorf("%s: listed twice", c.Nom)
		}
		vus[c.Image] = true
	}
}
