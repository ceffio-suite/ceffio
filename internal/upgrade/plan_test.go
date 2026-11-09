// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package upgrade

import (
	"strings"
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

// LE POD JETABLE NE MASQUE PLUS LA DÉRIVE. Mesuré le 2026-11-09 : un pod de
// test portant app=stalwart en 1.0.3 faisait afficher `= stalwart v1.0.3` au
// plan alors que le Deployment pinn ait encore 0.16.27 — précisément la dérive
// que le plan doit voir. Le workload fait foi ; le pod majoritaire ne sert plus
// que de repli.
func TestAssocierPrefereLeWorkloadAuPod(t *testing.T) {
	got := associerTout(
		[]string{"docker.io/stalwartlabs/stalwart:v0.16.27"},
		[]string{
			"docker.io/stalwartlabs/stalwart:v1.0.3",
			"docker.io/stalwartlabs/stalwart:v1.0.3",
		},
		nil,
		[]version.Composant{{Nom: "stalwart", Image: "docker.io/stalwartlabs/stalwart:v1.0.3"}},
	)
	if got.images["stalwart"] != "docker.io/stalwartlabs/stalwart:v0.16.27" {
		t.Fatalf("stalwart = %q, want the deployment's image, not the stray pod's", got.images["stalwart"])
	}
}

// UN COMPOSANT À ZÉRO RÉPLICA N'EST PAS ABSENT. Sans cette lecture, le plan
// répondait « not deployed » et le blocage de migration majeure ne pouvait pas
// se déclencher : il compare deux versions, et il n'y en avait plus qu'une.
func TestAssocierLitLeWorkloadArrete(t *testing.T) {
	got := associerTout(
		[]string{"docker.io/stalwartlabs/stalwart:v0.16.27"},
		nil,
		map[string]bool{"docker.io/stalwartlabs/stalwart": true},
		[]version.Composant{{Nom: "stalwart", Image: "docker.io/stalwartlabs/stalwart:v1.0.3"}},
	)
	if got.images["stalwart"] != "docker.io/stalwartlabs/stalwart:v0.16.27" {
		t.Fatalf("a stopped component lost its image: %+v", got.images)
	}
	if !got.arretes["stalwart"] {
		t.Fatal("a zero-replica workload was reported as running")
	}
	// Et donc l'écart, et donc le blocage.
	e := Etat{Nom: "stalwart", Installee: "v0.16.27", Cible: "v1.0.3", Ecart: true, Arrete: true}
	if _, bloque := blocageMigrationMajeure(e); !bloque {
		t.Fatal("the major-migration blocker does not fire for a stopped component")
	}
}

// Sans workload lisible (un pod géré par un opérateur, un daemonset), le pod
// reste la source : ne pas retomber sur « absent ».
func TestAssocierRetombeSurLesPods(t *testing.T) {
	got := associerTout(
		nil,
		[]string{"ghcr.io/ceffio-suite/janus-gateway:1.4.3-2"},
		nil,
		[]version.Composant{{Nom: "janus", Image: "ghcr.io/ceffio-suite/janus-gateway:1.4.3-2"}},
	)
	if got.images["janus"] != "ghcr.io/ceffio-suite/janus-gateway:1.4.3-2" {
		t.Fatalf("the pod fallback was lost: %+v", got)
	}
	if got.arretes["janus"] {
		t.Fatal("a pod was reported stopped")
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

// THE BLOCKER THAT PREVENTS A MAIL OUTAGE. Stalwart 1.0 refuses to open a
// pre-1.0 store and the pod loops in CrashLoopBackOff. Measured on 1.0.3 with
// the rehearsal volume: "The data store was created by a Stalwart version
// prior to 1.0 and cannot be opened by this version". An upgrade must stop
// BEFORE the backup and the replay, not discover it through a dead pod.
func TestBlocageMigrationMajeureStalwart(t *testing.T) {
	pb, bloque := blocageMigrationMajeure(Etat{
		Nom: "stalwart", Installee: "v0.16.27", Cible: "v1.0.3", Ecart: true,
	})
	if !bloque {
		t.Fatal("a 0.x → 1.x bump of stalwart was not blocked")
	}
	for _, attendu := range []string{"stalwart", "docs/stalwart-1.0.md", "--allow-major-migration"} {
		if !strings.Contains(pb, attendu) {
			t.Errorf("blocker %q does not mention %q", pb, attendu)
		}
	}
}

func TestBlocageMigrationMajeureNeBloquePasLeReste(t *testing.T) {
	cas := []struct {
		nom  string
		e    Etat
		quoi string
	}{
		{"correctif", Etat{Nom: "stalwart", Installee: "v1.0.2", Cible: "v1.0.3", Ecart: true}, "a patch release"},
		{"mineure", Etat{Nom: "stalwart", Installee: "v0.15.0", Cible: "v0.16.27", Ecart: true}, "a minor release"},
		{"autre composant", Etat{Nom: "valkey", Installee: "v9.1", Cible: "v9.2", Ecart: true}, "a component with no migration"},
		{"sans écart", Etat{Nom: "stalwart", Installee: "v1.0.3", Cible: "v1.0.3"}, "an aligned component"},
		{"version illisible", Etat{Nom: "stalwart", Installee: "", Cible: "v1.0.3"}, "an unknown installed version"},
	}
	for _, c := range cas {
		if _, bloque := blocageMigrationMajeure(c.e); bloque {
			t.Errorf("%s (%s) was blocked, it must not be", c.quoi, c.nom)
		}
	}
}

func TestMajeur(t *testing.T) {
	for tag, attendu := range map[string]int{
		"v1.0.3": 1, "1.0.3": 1, "v0.16.27": 0, "  v2 ": 2, "": -1, "latest": -1, "v": -1,
	} {
		if got := majeur(tag); got != attendu {
			t.Errorf("majeur(%q) = %d, want %d", tag, got, attendu)
		}
	}
}
