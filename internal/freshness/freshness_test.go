// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package freshness

import (
	"context"
	"errors"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// fauxDepot answers with a fixed tag list, or an error.
type fauxDepot struct {
	tags   map[string][]string
	erreur error
}

func (f fauxDepot) Tags(_ context.Context, depot string) ([]string, error) {
	if f.erreur != nil {
		return nil, f.erreur
	}
	return f.tags[depot], nil
}

// TestUneVersionPlusRecenteEstVue: the whole point — the pin is behind.
func TestUneVersionPlusRecenteEstVue(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"docker.io/library/nextcloud": {"34.0.2", "34.0.3", "34.0.5", "latest"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3@sha256:aaaa"},
	})
	if len(obs) != 1 {
		t.Fatalf("%d observation(s)", len(obs))
	}
	o := obs[0]
	if !o.PlusRecente || o.Recente != "34.0.5" {
		t.Errorf("observé %+v, attendu 34.0.5 plus récent", o)
	}
	if o.Action() != "bump" {
		t.Errorf("action = %q", o.Action())
	}
}

// TestLaVersionEpingleeEstLaPlusRecente: no finding, and no noise.
func TestLaVersionEpingleeEstLaPlusRecente(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"ghcr.io/ceffio-suite/ceffio-capture": {"v0.8.2", "v0.8.3"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "capture", Image: "ghcr.io/ceffio-suite/ceffio-capture:v0.8.3@sha256:bbbb"},
	})
	if obs[0].Action() != "up to date" {
		t.Errorf("action = %q, attendu à jour (%+v)", obs[0].Action(), obs[0])
	}
}

// TestUnTagNonComparableNeMentPas: "release" is not a version, and saying
// "up to date" about it would be a verdict with no basis.
func TestUnTagNonComparableNeMentPas(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"ghcr.io/nextcloud/nextcloud-appapi-harp": {"release", "canary"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "harp", Image: "ghcr.io/nextcloud/nextcloud-appapi-harp:release"},
	})
	if obs[0].Note == "" || obs[0].PlusRecente {
		t.Errorf("un tag non numérique doit être « à décider », pas « à jour » : %+v", obs[0])
	}
	if obs[0].Action() != "manual" {
		t.Errorf("action = %q", obs[0].Action())
	}
}

// TestUnePanneNArreteque: one failing repository must not hide the others.
func TestUnePanneNArretPasLesAutres(t *testing.T) {
	src := fauxDepot{erreur: errors.New("429 too many requests")}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "a", Image: "docker.io/x/a:1.0"}, {Nom: "b", Image: "docker.io/x/b:1.0"},
	})
	if len(obs) != 2 {
		t.Fatalf("%d observation(s), attendu 2", len(obs))
	}
	for _, o := range obs {
		if o.Note == "" {
			t.Errorf("%s: l'erreur doit être dite (%+v)", o.Nom, o)
		}
	}
}

// TestComparaisonDesTags: the shapes the registry actually contains, including
// the ones a strict semver parser would refuse.
func TestComparaisonDesTags(t *testing.T) {
	cas := []struct {
		candidat, reference string
		plusGrand           bool
	}{
		{"34.0.5", "34.0.3", true},
		{"34.0.2", "34.0.3", false},
		{"9.4.0.2", "9.4.0.1", true},
		{"1.4.3-2", "1.4.3-1", true},
		{"v0.8.10", "v0.8.9", true},
		{"2.7.1", "2.7", true},
		{"2.7", "2.7.0", false}, // un zéro de fin n'est pas une version
		{"4.18.0", "4.18", false},
	}
	for _, c := range cas {
		a, _, okA := decoupe(c.candidat)
		b, _, okB := decoupe(c.reference)
		if !okA || !okB {
			t.Fatalf("%q ou %q non comparable", c.candidat, c.reference)
		}
		if got := plusGrand(a, b); got != c.plusGrand {
			t.Errorf("plusGrand(%q, %q) = %v, attendu %v", c.candidat, c.reference, got, c.plusGrand)
		}
	}
}

// TestDepotSansEtiquette: the port of a registry is not a tag.
func TestDepotSansEtiquette(t *testing.T) {
	cas := map[string]string{
		"docker.io/library/nextcloud:34.0.3@sha256:aa": "docker.io/library/nextcloud",
		"registry.local:5000/x:1.0":                    "registry.local:5000/x",
		"registry.local:5000/x":                        "registry.local:5000/x",
	}
	for entree, attendu := range cas {
		if got := DepotDe(entree); got != attendu {
			t.Errorf("DepotDe(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

// TestLesVariantesNeSontPasDesVersions: the finding a check nobody reads is
// born here — comparing the apache tag with an -fpm-alpine one.
func TestLesVariantesNeSontPasDesVersions(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"docker.io/library/nextcloud": {"34.0.3", "34.0.5-fpm-alpine", "35.0.2-fpm-alpine", "35.0.2"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3@sha256:aa"},
	})
	if obs[0].Recente != "35.0.2" {
		t.Errorf("publié = %q, attendu 35.0.2 (la variante -fpm-alpine n'est pas la même image)", obs[0].Recente)
	}
}

// TestUnHachageDeCommitNEstPasUneVersion: talk-signaling publie des SHA.
func TestUnHachageDeCommitNEstPasUneVersion(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"docker.io/strukturag/nextcloud-spreed-signaling": {"8703323", "8703324"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "talk-signaling", Image: "docker.io/strukturag/nextcloud-spreed-signaling:8703323"},
	})
	if obs[0].Note == "" {
		t.Errorf("un hachage doit être « à décider », pas comparé : %+v", obs[0])
	}
}

// TestUnZeroDeFinNEstPasUneVersion: coturn publie 4.18 et 4.18.0 pour la même
// chose ; le signaler une fois par semaine serait du bruit.
func TestUnZeroDeFinNEstPasUneVersion(t *testing.T) {
	src := fauxDepot{tags: map[string][]string{
		"docker.io/coturn/coturn": {"4.18", "4.18.0"},
	}}
	obs := Comparer(context.Background(), src, []version.Composant{
		{Nom: "coturn", Image: "docker.io/coturn/coturn:4.18@sha256:aa"},
	})
	if obs[0].Action() != "up to date" {
		t.Errorf("4.18 contre 4.18.0 = %q, attendu à jour", obs[0].Action())
	}
}
