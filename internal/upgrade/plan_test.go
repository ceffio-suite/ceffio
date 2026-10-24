// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package upgrade

import (
	"testing"

	"github.com/ceffio-suite/ceffio/internal/version"
)

// THE CASE THAT MOTIVATED THE REWRITE. On a real installation, a substring
// match associated `nextcloud` with the Talk recording server, whose
// repository merely starts with the same word, and reported a version drift
// that did not exist. Two products, two repositories: they must not be
// confused, whatever the iteration order.
func TestAssocierDistingueDeuxProduitsAuNomProche(t *testing.T) {
	images := []string{
		"docker.io/nextcloud/aio-talk-recording:20261014_095932",
		"docker.io/library/nextcloud:34.0.3",
	}
	composants := []version.Composant{
		{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3"},
		{Nom: "talk-recording", Image: "docker.io/nextcloud/aio-talk-recording:20261014_095932"},
	}

	got := associer(images, composants)
	if got["nextcloud"] != "docker.io/library/nextcloud:34.0.3" {
		t.Fatalf("nextcloud = %q, want the Nextcloud image", got["nextcloud"])
	}
	if got["talk-recording"] != "docker.io/nextcloud/aio-talk-recording:20261014_095932" {
		t.Fatalf("talk-recording = %q, want the recording image", got["talk-recording"])
	}
}

// kubelet does not always report the long Docker form: the comparison must
// survive `nextcloud:34.0.3` on one side and the full reference on the other.
func TestAssocierAccepteLaFormeCourte(t *testing.T) {
	got := associer(
		[]string{"nextcloud:34.0.3"},
		[]version.Composant{{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3"}},
	)
	if got["nextcloud"] != "nextcloud:34.0.3" {
		t.Fatalf("short form was not matched: %+v", got)
	}
}

// A digest-pinned pod has no tag to compare, but its repository still
// identifies the component: losing it would report the layer as absent.
func TestAssocierIgnoreLeDigest(t *testing.T) {
	got := associer(
		[]string{"docker.io/library/nextcloud@sha256:0123456789abcdef"},
		[]version.Composant{{Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3"}},
	)
	if got["nextcloud"] == "" {
		t.Fatal("a digest-pinned image was not associated with its repository")
	}
}

// An installation that has not migrated yet still runs redis: it must be
// reported as a drift TO UPGRADE, not as a missing layer.
func TestAssocierReconnaitLAncienDepot(t *testing.T) {
	got := associer(
		[]string{"docker.io/library/redis:7.4"},
		[]version.Composant{{Nom: "valkey", Image: "docker.io/valkey/valkey:8.1.10"}},
	)
	if got["valkey"] != "docker.io/library/redis:7.4" {
		t.Fatalf("the previous repository was not recognised: %+v", got)
	}
}

func TestAssocierAbsentNEstPasInvente(t *testing.T) {
	got := associer(
		[]string{"docker.io/library/nextcloud:34.0.3"},
		[]version.Composant{{Nom: "janus", Image: "ghcr.io/ceffio-suite/janus-gateway:1.4.3-1"}},
	)
	if _, present := got["janus"]; present {
		t.Fatalf("an absent component was reported as running: %+v", got)
	}
}

// During a rollout two tags coexist: the installation runs the one carried by
// most pods, and the answer does not depend on map iteration order.
func TestPlusFrequent(t *testing.T) {
	if got := plusFrequent([]string{"a:1", "a:1", "a:2"}); got != "a:1" {
		t.Fatalf("plusFrequent = %q, want the majority", got)
	}
	if got := plusFrequent(nil); got != "" {
		t.Fatalf("plusFrequent(nil) = %q, want empty", got)
	}
	// Equal counts: deterministic, not whatever the map decided.
	if a, b := plusFrequent([]string{"x:1", "x:2"}), plusFrequent([]string{"x:1", "x:2"}); a != b {
		t.Fatalf("tie is not deterministic: %q then %q", a, b)
	}
}

func TestDepotDe(t *testing.T) {
	cas := map[string]string{
		"docker.io/library/nextcloud:34.0.3":           "docker.io/library/nextcloud",
		"nextcloud:34.0.3":                             "docker.io/library/nextcloud",
		"nextcloud":                                    "docker.io/library/nextcloud",
		"nextcloud/aio-talk-recording:20261014_095932": "docker.io/nextcloud/aio-talk-recording",
		"ghcr.io/ceffio-suite/janus-gateway:1.4.3-1":   "ghcr.io/ceffio-suite/janus-gateway",
		"localhost:5000/ceffio/api:1.0":                "localhost:5000/ceffio/api",
		"registry.lab:5000/team/image@sha256:deadbeef": "registry.lab:5000/team/image",
		"docker.io/valkey/valkey:8.1.10":               "docker.io/valkey/valkey",
		"":                                             "",
	}
	for ref, voulu := range cas {
		if got := depotDe(ref); got != voulu {
			t.Errorf("depotDe(%q) = %q, want %q", ref, got, voulu)
		}
	}
}
