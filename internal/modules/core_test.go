// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// idsSocle liste les dix couches du socle, devenues des modules Core.
// L'ordre reprend celui de la séquence d'installation
// (cmd/ceffio/install.go), pour que la table ci-dessous reste lisible comme
// le produit lui-même.
var idsSocle = []string{
	"platform", "data", "vault", "identity", "files",
	"office", "talk", "ingress", "mail", "console",
}

// entreeCatalogue est la COPIE de référence d'une ligne de
// catalogueServices (internal/console/status.go). Dupliquée volontairement :
// le test doit casser si l'une des deux tables dérive, pas suivre
// silencieusement la seconde.
type entreeCatalogue struct {
	sub       string
	nom       string
	role      string
	technique bool
	sso       bool
	pods      []string
	modulaire string // ID du module qui doit porter cette exposition
}

// catalogueReference reprend les 6 entrées de catalogueServices telles
// qu'elles existaient avant la modularisation, avec le module attendu.
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

// TestChaqueEntreeCatalogueVitDansExactementUnModule est le garde-fou de la
// migration : chaque exposition publique de l'ancien catalogueServices doit
// se retrouver dans EXACTEMENT UN module du registre — ni zéro (perdue au
// passage), ni deux (dupliquée, la page de statut l'afficherait deux fois).
//
// POURQUOI vérifier les CHAMPS et pas seulement le Sub : un Service
// recopié avec un SSO ou un PodPrefixes faux ne casserait aucun test
// d'existence, mais changerait silencieusement la réponse de /api/status
// que le lot B5 doit reproduire à l'identique.
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
			// attendu
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

// TestLesDixCouchesDuSocleSontDesModulesCore vérifie le contrat commun des
// dix modules Core : enregistrés, Kind Core, Default=true (sémantique :
// `ceffio install` les pose tous), des namespaces réels déclarés, et un
// refus explicite de désinstallation par couche.
func TestLesDixCouchesDuSocleSontDesModulesCore(t *testing.T) {
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
			if !strings.HasPrefix(ns, "ceffio-") && ns != "cert-manager" && ns != "cnpg-system" {
				t.Errorf("module %q: namespace %q is not a real one (no layer deploys into it)", id, ns)
			}
		}

		// Uninstall DOIT refuser : les dix couches sont le produit. Un
		// retrait par couche laisserait une suite amnésique qui se
		// croirait saine — l'erreur explicite est le comportement.
		if err := m.Uninstall(context.Background(), module.Env{}); err == nil {
			t.Errorf("module %q: Uninstall must refuse — core layers are removed with the cluster only", id)
		}
	}
}

// TestMailNeFaitPasSemblantDInstaller vérifie le cas délicat du lot :
// mail.Deploy exige les réglages du relais SMTP que Env ne porte pas. Le
// module doit refouver net, avec une erreur qui nomme le VRAI installateur
// — jamais déléguer avec un relais vide (un Stalwart sans relais tourne,
// reçoit, et n'envoie rien : une installation silencieusement cassée).
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

// TestEtatSansClientDitInconnu vérifie la règle transversale des lectures
// d'état : sans client Kubernetes dans Env, on répond Unknown — jamais
// Absent, qui est un fait observé et non un défaut de point de vue.
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

// TestPasDeCollisionAvecLesModulesOptionnels vérifie que les IDs du socle ne
// recouvrent pas ceux des modules à la carte (Register paniquerait au
// démarrage sur une collision, mais un renommage futur doit être attrapé
// ici, avec un message lisible, plutôt qu'en panique d'init).
func TestPasDeCollisionAvecLesModulesOptionnels(t *testing.T) {
	optionnels := []string{"exapps-daemon", "live-transcription", "recording"}
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
