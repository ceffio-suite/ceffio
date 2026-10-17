// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"io"
	"strings"
	"testing"
)

// fauxModule est un module factice minimal pour tester le registre sans
// toucher au cluster. Son état est figé (etat) pour que Blocked soit
// testable de façon déterministe.
type fauxModule struct {
	info Info
	etat State
}

func (f *fauxModule) Info() Info { return f.info }

func (f *fauxModule) Install(context.Context, Env) error { return nil }

func (f *fauxModule) State(context.Context, Env) State { return f.etat }

func (f *fauxModule) Uninstall(context.Context, Env) error { return nil }

// nouveauFaux construit un module factice avec le strict nécessaire.
func nouveauFaux(id string, requires ...string) *fauxModule {
	return &fauxModule{info: Info{ID: id, Requires: requires}}
}

// envFactice fournit un Env inutilisable côté cluster mais suffisant pour
// les tests de Blocked, qui n'appellent jamais Kube.
func envFactice() Env {
	return Env{Domain: "test.local", Kube: nil, Out: io.Discard}
}

// capturePanic exécute fn et renvoie le message de panique éventuel.
func capturePanic(fn func()) (msg string, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			switch v := r.(type) {
			case string:
				msg = v
			case error:
				msg = v.Error()
			default:
				msg = "panic value of unexpected type"
			}
		}
	}()
	fn()
	return "", false
}

func TestRegistry(t *testing.T) {
	t.Run("register rejects duplicate", func(t *testing.T) {
		reinitialiserPourTest()

		Register(nouveauFaux("alpha"))
		msg, panicked := capturePanic(func() { Register(nouveauFaux("alpha")) })
		if !panicked {
			t.Fatal("expected panic when registering a duplicate ID")
		}
		if !strings.Contains(msg, "alpha") || !strings.Contains(msg, "already registered") {
			t.Fatalf("panic message should name the duplicate, got: %s", msg)
		}
	})

	t.Run("register rejects empty ID", func(t *testing.T) {
		reinitialiserPourTest()

		msg, panicked := capturePanic(func() { Register(nouveauFaux("")) })
		if !panicked {
			t.Fatal("expected panic when registering an empty ID")
		}
		if !strings.Contains(msg, "empty") {
			t.Fatalf("panic message should mention the empty ID, got: %s", msg)
		}
	})

	t.Run("register rejects non kebab-case ID", func(t *testing.T) {
		reinitialiserPourTest()

		for _, id := range []string{"Alpha", "alpha_beta", "alpha-", "-alpha", "al pha", "alpha--beta"} {
			msg, panicked := capturePanic(func() { Register(nouveauFaux(id)) })
			if !panicked {
				t.Fatalf("expected panic for invalid ID %q", id)
			}
			if !strings.Contains(msg, "kebab-case") {
				t.Fatalf("panic message should mention kebab-case for %q, got: %s", id, msg)
			}
		}
	})

	t.Run("all rejects unknown dependency", func(t *testing.T) {
		reinitialiserPourTest()

		Register(nouveauFaux("solo", "fantome"))
		msg, panicked := capturePanic(func() { All() })
		if !panicked {
			t.Fatal("expected panic when a module requires an unregistered ID")
		}
		if !strings.Contains(msg, "solo") || !strings.Contains(msg, "fantome") {
			t.Fatalf("panic message should name both modules, got: %s", msg)
		}
		if !strings.Contains(msg, "unknown") {
			t.Fatalf("panic message should explain the unknown dependency, got: %s", msg)
		}
	})

	t.Run("all detects cycle", func(t *testing.T) {
		reinitialiserPourTest()

		Register(nouveauFaux("a", "b"))
		Register(nouveauFaux("b", "a"))

		msg, panicked := capturePanic(func() { All() })
		if !panicked {
			t.Fatal("expected panic on a dependency cycle")
		}
		if !strings.Contains(msg, "a -> b -> a") && !strings.Contains(msg, "b -> a -> b") {
			t.Fatalf("panic message should contain the readable cycle, got: %s", msg)
		}
	})

	t.Run("all returns topological order", func(t *testing.T) {
		reinitialiserPourTest()

		// Enregistrement dans le désordre : c'est All qui doit rétablir l'ordre.
		Register(nouveauFaux("talk", "identity"))
		Register(nouveauFaux("live-transcription", "talk", "identity"))
		Register(nouveauFaux("identity"))
		Register(nouveauFaux("cloud"))

		ordered := All()
		if len(ordered) != 4 {
			t.Fatalf("expected 4 modules, got %d", len(ordered))
		}

		position := map[string]int{}
		for i, m := range ordered {
			position[m.Info().ID] = i
		}
		for _, m := range ordered {
			for _, dep := range m.Info().Requires {
				if position[dep] >= position[m.Info().ID] {
					t.Errorf("%q must come after its dependency %q, got order %v",
						m.Info().ID, dep, ordered)
				}
			}
		}
	})

	t.Run("all is deterministic", func(t *testing.T) {
		reinitialiserPourTest()

		// Trois modules indépendants enregistrés en désordre : les maps Go
		// étant non ordonnées, seul le tri alphabétique garantit un ordre
		// stable d'un appel à l'autre.
		Register(nouveauFaux("zeta"))
		Register(nouveauFaux("alpha"))
		Register(nouveauFaux("mid"))

		want := []string{"alpha", "mid", "zeta"}
		for call := 0; call < 3; call++ {
			got := All()
			for i, id := range want {
				if got[i].Info().ID != id {
					t.Fatalf("call %d: expected order %v, got %q at position %d", call, want, got[i].Info().ID, i)
				}
			}
		}
	})

	t.Run("all on empty registry", func(t *testing.T) {
		reinitialiserPourTest()

		if got := All(); len(got) != 0 {
			t.Fatalf("expected an empty registry to yield no modules, got %d", len(got))
		}
	})

	t.Run("get finds registered and misses unknown", func(t *testing.T) {
		reinitialiserPourTest()

		alpha := nouveauFaux("alpha")
		Register(alpha)

		m, ok := Get("alpha")
		if !ok {
			t.Fatal("expected to find registered module alpha")
		}
		if m != Module(alpha) {
			t.Fatal("Get returned a different module than the one registered")
		}

		if _, ok := Get("absent"); ok {
			t.Fatal("expected Get to report false for an unknown ID")
		}
	})
}

func TestBlocked(t *testing.T) {
	t.Run("reason when dependency absent", func(t *testing.T) {
		reinitialiserPourTest()

		identity := nouveauFaux("identity")
		identity.etat = State{Status: Absent}
		Register(identity)

		talk := nouveauFaux("talk", "identity")
		Register(talk)

		reason := Blocked(context.Background(), envFactice(), talk)
		if reason == "" {
			t.Fatal("expected a non-empty reason while the dependency is absent")
		}
		if !strings.Contains(reason, "identity") || !strings.Contains(reason, string(Absent)) {
			t.Fatalf("reason should name the dependency and its status, got: %s", reason)
		}
	})

	t.Run("reason surfaces dependency own blocked detail", func(t *testing.T) {
		reinitialiserPourTest()

		identity := nouveauFaux("identity")
		identity.etat = State{Status: Degraded, Blocked: "database pod is not ready"}
		Register(identity)

		talk := nouveauFaux("talk", "identity")
		Register(talk)

		reason := Blocked(context.Background(), envFactice(), talk)
		if reason == "" {
			t.Fatal("expected a non-empty reason while the dependency is degraded")
		}
		if !strings.Contains(reason, "database pod is not ready") {
			t.Fatalf("reason should surface the dependency's own blocking detail, got: %s", reason)
		}
	})

	t.Run("empty reason when dependency installed", func(t *testing.T) {
		reinitialiserPourTest()

		identity := nouveauFaux("identity")
		identity.etat = State{Status: Installed}
		Register(identity)

		talk := nouveauFaux("talk", "identity")
		Register(talk)

		if reason := Blocked(context.Background(), envFactice(), talk); reason != "" {
			t.Fatalf("expected an empty reason once the dependency is installed, got: %s", reason)
		}
	})

	t.Run("empty reason without dependencies", func(t *testing.T) {
		reinitialiserPourTest()

		solo := nouveauFaux("solo")
		Register(solo)

		if reason := Blocked(context.Background(), envFactice(), solo); reason != "" {
			t.Fatalf("a module without dependencies is never blocked, got: %s", reason)
		}
	})

	t.Run("reason when dependency not registered", func(t *testing.T) {
		// Cas défensif : Blocked appelé sur un module jamais passé par All.
		m := nouveauFaux("orphelin", "fantome")

		reason := Blocked(context.Background(), envFactice(), m)
		if reason == "" {
			t.Fatal("expected a reason when the dependency is not registered")
		}
		if !strings.Contains(reason, "fantome") {
			t.Fatalf("reason should name the unregistered dependency, got: %s", reason)
		}
	})
}
