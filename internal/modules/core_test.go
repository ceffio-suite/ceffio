// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// idsSocle lists the ten core layers, now Core modules. The order follows
// the one of the install sequence (cmd/ceffio/install.go), so that the
// table below stays readable like the product itself.
var idsSocle = []string{
	"storage", "platform", "data", "vault", "identity", "files",
	"office", "talk", "ingress", "mail", "console",
}

// entreeCatalogue is the REFERENCE COPY of a row of catalogueServices
// (internal/console/status.go). Duplicated deliberately: the test must
// break if either table drifts, not silently follow the second one.
type entreeCatalogue struct {
	sub       string
	nom       string
	role      string
	technique bool
	sso       bool
	pods      []string
	modulaire string // ID of the module that must carry this exposure
}

// catalogueReference reproduces the 6 entries of catalogueServices as they
// existed before the modularization, with the expected module.
var catalogueReference = []entreeCatalogue{
	{"cloud", "Nextcloud", "Files, sharing and collaboration", false, true,
		[]string{"nextcloud"}, "files"},
	{"talk", "Nextcloud Talk", "Messaging and video conferencing (built into Nextcloud)", false, true,
		[]string{"nextcloud"}, "files"},
	{"keycloak", "Keycloak", "Single sign-on (SSO) for all apps", false, false,
		[]string{"keycloak"}, "identity"},
	{"office", "ONLYOFFICE", "Editing engine for Nextcloud documents — loaded by the browser, no useful direct access", true, false,
		[]string{"onlyoffice"}, "office"},
	{"admin", "Ceffio console", "This administration console", true, false,
		[]string{"ceffio-admin"}, "console"},
	{"spreed", "Talk — media server", "Video transport for meetings (Janus + signaling)", true, false,
		[]string{"janus", "talk-signaling", "coturn", "nats"}, "talk"},
}

// TestChaqueEntreeCatalogueVitDansExactementUnModule is the migration guard:
// every public exposure of the former catalogueServices must end up in
// EXACTLY ONE module of the registry — neither zero (lost along the way),
// nor two (duplicated, the status page would display it twice).
//
// WHY check the FIELDS and not only the Sub: a Service copied with a wrong
// SSO or a wrong PodPrefixes would break no existence test, but would
// silently change the answer of /api/status that batch B5 must reproduce
// identically.
func TestChaqueEntreeCatalogueVitDansExactementUnModule(t *testing.T) {
	tout := module.All()

	for _, ref := range catalogueReference {
		var trouveDans []string
		var trouvee module.Service
		for _, m := range tout {
			for _, svc := range m.Info().Services {
				if svc.Sub != ref.sub {
					continue
				}
				trouveDans = append(trouveDans, m.Info().ID)
				trouvee = svc
			}
		}

		switch len(trouveDans) {
		case 0:
			t.Errorf("catalog entry %q was lost: no module declares a Service with this Sub", ref.sub)
			continue
		case 1:
			// expected
		default:
			t.Errorf("catalog entry %q is duplicated across modules %s: it must live in exactly one",
				ref.sub, strings.Join(trouveDans, ", "))
			continue
		}

		if trouveDans[0] != ref.modulaire {
			t.Errorf("catalog entry %q lives in module %q, expected %q",
				ref.sub, trouveDans[0], ref.modulaire)
		}
		if trouvee.Name != ref.nom {
			t.Errorf("entry %q: Name = %q, expected %q (console/status.go wording)",
				ref.sub, trouvee.Name, ref.nom)
		}
		if trouvee.Role != ref.role {
			t.Errorf("entry %q: Role = %q, expected %q", ref.sub, trouvee.Role, ref.role)
		}
		if trouvee.Technical != ref.technique {
			t.Errorf("entry %q: Technical = %v, expected %v", ref.sub, trouvee.Technical, ref.technique)
		}
		if trouvee.SSO != ref.sso {
			t.Errorf("entry %q: SSO = %v, expected %v — /api/status must answer the same value",
				ref.sub, trouvee.SSO, ref.sso)
		}
		if strings.Join(trouvee.PodPrefixes, ",") != strings.Join(ref.pods, ",") {
			t.Errorf("entry %q: PodPrefixes = %v, expected %v", ref.sub, trouvee.PodPrefixes, ref.pods)
		}
	}
}

// TestLesCouchesDuSocleSontDesModulesCore checks the common contract of
// the Core modules: registered, Kind Core, Default=true (semantics:
// `ceffio install` lays them all down), real namespaces declared, and an
// explicit refusal of per-layer uninstall.
//
// THE COUNT IS NOT IN THE NAME ANY MORE. It used to say "dix", and the storage
// layer made it eleven — a rename with a number in it turns every added layer into a
// false claim about the test's scope.
func TestLesCouchesDuSocleSontDesModulesCore(t *testing.T) {
	for _, id := range idsSocle {
		m, ok := module.Get(id)
		if !ok {
			t.Errorf("module %q is not registered", id)
			continue
		}
		info := m.Info()
		if info.Kind != module.Core {
			t.Errorf("module %q: Kind = %v, expected module.Core", id, info.Kind)
		}
		if !info.Default {
			t.Errorf("module %q: Default must be true — the install sequence always deploys the core layers", id)
		}
		if info.Title == "" || info.Description == "" {
			t.Errorf("module %q: Title and Description must not be empty (the console shows them)", id)
		}
		if len(info.Namespaces) == 0 {
			t.Errorf("module %q: Namespaces must not be empty — status and doctor read the layers through them", id)
		}
		for _, ns := range info.Namespaces {
			// THE NAMESPACE SET IS CLOSED ON PURPOSE: a core layer that invents a
			// namespace is a layer nobody planned for, and the console's RBAC derives
			// from this list. `longhorn-system` joins it with its reason: Longhorn
			// installs itself there through Helm and cannot be moved.
			if !strings.HasPrefix(ns, "ceffio-") && ns != "cert-manager" &&
				ns != "cnpg-system" && ns != "longhorn-system" {
				t.Errorf("module %q: namespace %q is not a real one (no layer deploys into it)", id, ns)
			}
		}

		// Uninstall MUST refuse: the layers are the product. A
		// per-layer removal would leave an amnesiac suite that believes
		// itself healthy — the explicit error is the behavior.
		if err := m.Uninstall(context.Background(), module.Env{}); err == nil {
			t.Errorf("module %q: Uninstall must refuse — core layers are removed with the cluster only", id)
		}
	}
}

// TestMailNeFaitPasSemblantDInstaller checks the delicate case of the
// batch: mail.Deploy requires the SMTP relay settings that Env does not
// carry. The module must refuse outright, with an error that names the REAL
// installer — never delegate with an empty relay (a Stalwart without a
// relay runs, receives, and sends nothing: a silently broken
// installation).
func TestMailNeFaitPasSemblantDInstaller(t *testing.T) {
	m, ok := module.Get("mail")
	if !ok {
		t.Fatal("module \"mail\" is not registered")
	}
	err := m.Install(context.Background(), module.Env{Domain: "ceffio.example.com"})
	if err == nil {
		t.Fatal("mail Install must return an error: the SMTP relay settings live in the install sequence, not in Env")
	}
	if !strings.Contains(err.Error(), "install sequence") {
		t.Errorf("mail Install error must name the real installer, got: %v", err)
	}
}

// TestEtatSansClientDitInconnu checks the transversal rule of the state
// reads: without a Kubernetes client in Env, we answer Unknown — never
// Absent, which is an observed fact and not a lack of point of view.
func TestEtatSansClientDitInconnu(t *testing.T) {
	for _, id := range idsSocle {
		m, ok := module.Get(id)
		if !ok {
			continue
		}
		etat := m.State(context.Background(), module.Env{})
		if etat.Status != module.Unknown {
			t.Errorf("module %q: State without a Kubernetes client = %q, expected \"unknown\"", id, etat.Status)
		}
	}
}

// TestPasDeCollisionAvecLesModulesOptionnels checks that the core IDs do
// not overlap with those of the optional modules (Register would panic at
// startup on a collision, but a future rename must be caught here, with a
// readable message, rather than in an init panic).
func TestPasDeCollisionAvecLesModulesOptionnels(t *testing.T) {
	optionnels := []string{"exapps-daemon", "live-transcription", "recording", "longhorn-ui"}
	vus := map[string]bool{}
	for _, id := range append(append([]string{}, idsSocle...), optionnels...) {
		if vus[id] {
			t.Errorf("module ID %q is declared twice (core and optional lists overlap)", id)
		}
		vus[id] = true
	}
	for _, id := range optionnels {
		m, ok := module.Get(id)
		if !ok {
			t.Errorf("optional module %q disappeared from the registry", id)
			continue
		}
		if m.Info().Kind != module.Optional {
			t.Errorf("module %q: Kind = %v, expected module.Optional — the core layers must not absorb it", id, m.Info().Kind)
		}
	}
	// WHY NOT "len(All()) == 13": a count freezes the registry at today's size.
	// The whole point of the registry is that a feature can be ADDED — the
	// demo module does exactly that — and a hard count turns every addition
	// into a test failure. What this assertion actually defends is that the
	// built-in lists below did not silently drift: every module they name
	// exists with the right kind, and no OTHER module outside them is a core
	// layer (a core layer missing from the list would go unchecked).
	//
	// Modules with a build tag (demo) are deliberately not enumerated: they
	// are opt-in and must not change what the default build asserts.
	for _, m := range module.All() {
		i := m.Info()
		if i.Kind != module.Core {
			continue
		}
		if !vus[i.ID] {
			t.Errorf("module %q is a core layer but is missing from the core/optional lists above: "+
				"the list drifted from the registry", i.ID)
		}
	}
}
