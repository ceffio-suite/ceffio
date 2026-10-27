// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package capture

import (
	"context"
	"regexp"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestInfoValide vérifie le contrat d'affichage et, surtout, les dépendances :
// a capture without the recorder has nothing to transcribe — and that is the
// only one: it joins the call through the signaling, not through HaRP.
func TestInfoValide(t *testing.T) {
	m := &captureModule{}
	info := m.Info()

	kebab := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	if !kebab.MatchString(info.ID) || info.ID != "capture" {
		t.Errorf("Info.ID = %q, attendu capture en kebab-case", info.ID)
	}
	if info.Title == "" || info.Description == "" {
		t.Error("Title et Description sont obligatoires")
	}
	if info.Kind != module.Optional {
		t.Errorf("Kind = %v, attendu module.Optional", info.Kind)
	}

	exigences := map[string]bool{}
	for _, d := range info.Requires {
		exigences[d] = true
	}
	if !exigences["recording"] {
		t.Errorf("Info.Requires ne contient pas recording (%v)", info.Requires)
	}
	// THE DEPENDENCY ON HaRP IS GONE, and it must not come back: it would
	// force exapps-daemon — and therefore the right for Nextcloud to start
	// containers — on an installation that only wants to record and transcribe.
	if exigences["exapps-daemon"] {
		t.Errorf("Info.Requires contient encore exapps-daemon (%v)", info.Requires)
	}

	// Les droits doivent couvrir les deux execs, sans quoi le service démarre
	// et échoue à la première écriture.
	vus := map[string]bool{}
	for _, p := range info.Permissions {
		vus[p.Namespace] = true
	}
	for _, attendu := range []string{"ceffio-video", "ceffio-files"} {
		if !vus[attendu] {
			t.Errorf("aucune permission déclarée pour %q", attendu)
		}
	}
	// PLUS AUCUN DROIT SUR LA BASE (lot B5) : l'état de l'enregistrement et la
	// langue du salon viennent du relais, plus d'un exec dans le pod PostgreSQL.
	if vus["ceffio-data"] {
		t.Error("le module demande encore des droits sur ceffio-data : il n'y fait " +
			"plus aucun appel, et une permission accordée est une permission utilisée")
	}
}

// TestReglagesDeclares checks the settings contract the console draws from: a
// group, two fields, their defaults, and the closed set of models.
func TestReglagesDeclares(t *testing.T) {
	groupes := (&captureModule{}).Settings()
	if len(groupes) != 1 {
		t.Fatalf("Settings() returned %d groups, expected 1", len(groupes))
	}
	g := groupes[0]
	if g.ID != groupeTranscription {
		t.Errorf("group id = %q, expected %q", g.ID, groupeTranscription)
	}
	champs := map[string]module.Field{}
	for _, f := range g.Fields {
		champs[f.Key] = f
	}
	modele, ok := champs["model"]
	if !ok || modele.Type != module.Choice || modele.Default != "small" {
		t.Fatalf("model field = %+v, expected a choice defaulting to small", modele)
	}
	if len(modele.Options) != 2 {
		t.Errorf("model offers %d options, expected 2", len(modele.Options))
	}
	threads, ok := champs["threads"]
	if !ok || threads.Type != module.Number || threads.Default != "4" {
		t.Fatalf("threads field = %+v, expected a number defaulting to 4", threads)
	}
}

// TestApplyRefusesHorsBornes: validation happens before anything is stored or
// applied. An unknown model, or 99 threads, must be refused with the field
// named — not written and then discovered by a restart.
func TestApplyRefusesHorsBornes(t *testing.T) {
	m := &captureModule{}
	store := &fauxMagasin{donnees: map[string]string{}}
	env := module.Env{Settings: store}

	if err := m.Apply(context.Background(), env, groupeTranscription,
		module.Values{"model": "huge", "threads": "4"}); err == nil {
		t.Error("Apply accepted an unknown model")
	}
	if err := m.Apply(context.Background(), env, groupeTranscription,
		module.Values{"model": "small", "threads": "99"}); err == nil {
		t.Error("Apply accepted 99 threads")
	}
	if store.ecriture != 0 {
		t.Errorf("the store was written %d times for invalid values", store.ecriture)
	}
}

// fauxMagasin is a settings store held in a map.
type fauxMagasin struct {
	donnees  map[string]string
	ecriture int
}

func (f *fauxMagasin) Lire(_ context.Context, _, _, cle string) (string, error) {
	return f.donnees[cle], nil
}

func (f *fauxMagasin) Ecrire(_ context.Context, _, _ string, d map[string]string) error {
	f.ecriture++
	for k, v := range d {
		f.donnees[k] = v
	}
	return nil
}

func (f *fauxMagasin) Supprimer(_ context.Context, _, _, cle string) error {
	delete(f.donnees, cle)
	return nil
}
