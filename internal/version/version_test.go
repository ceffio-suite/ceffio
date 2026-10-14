// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package version

import (
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
		// Official Docker library images are an accepted exception:
		// `redis:7.4.11` is a recognized form, not an imprecision.
		if strings.HasPrefix(c.Image, "redis:") {
			continue
		}
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
