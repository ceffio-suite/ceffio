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

// avecBinary exécute fn avec Binary remplacé, puis restaure la valeur :
// les tests d'ImageTag modifient un état global du package, et un test qui
// laisse sa valeur derrière lui fausse les suivants dans le même paquet.
func avecBinary(t *testing.T, valeur string, fn func()) {
	t.Helper()
	ancien := Binary
	Binary = valeur
	defer func() { Binary = ancien }()
	fn()
}

// TestImageTagRelease vérifie le régime « release » : un tag git v0.6.0 doit
// produire le tag d'image 0.6.0, sans le « v » (les tags d'image Docker ne
// le portent jamais dans ce dépôt).
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

// TestImageTagDev vérifie le régime « développement » : sans version de
// release, le tag est dérivé du contenu du binaire (préfixe dev- + SHA-256
// tronqué). On injecte un faux chemin via cheminExecutable pour ne pas
// dépendre du vrai binaire de test.
func TestImageTagDev(t *testing.T) {
	// Fichier temporaire au lieu du vrai exécutable : le hachage doit être
	// calculé sur un contenu connu et stable pendant le test.
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

// TestImageTagDevStable vérifie que deux appels successifs donnent le même
// tag : un tag qui changerait entre la construction de l'image et son
// déploiement referencerait une image inexistante.
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

// TestImageTagJamaisVide vérifie la promesse centrale de la fonction : même
// quand le binaire est introuvable (chemin inexistant OU erreur
// d'os.Executable), le tag n'est jamais vide. Un tag vide produirait une
// référence d'image invalide et casserait le déploiement.
func TestImageTagJamaisVide(t *testing.T) {
	ancien := cheminExecutable
	defer func() { cheminExecutable = ancien }()

	avecBinary(t, "0.0.0-dev", func() {
		// Cas 1 : os.Executable échoue.
		cheminExecutable = func() (string, error) { return "", fmt.Errorf("executable not found") }
		if got := ImageTag(); got == "" {
			t.Error("ImageTag() vide quand le chemin de l'exécutable est introuvable")
		}

		// Cas 2 : le chemin retourné ne pointe vers aucun fichier réel.
		cheminExecutable = func() (string, error) { return "/chemin/qui/nexiste/pas", nil }
		if got := ImageTag(); got == "" {
			t.Error("ImageTag() vide quand le binaire est illisible")
		}
	})
}
