// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// POURQUOI un registre global : les modules s'enregistrent depuis leur
// propre package (init ou appel explicite au démarrage), et les deux frontaux
// — CLI et console — ont besoin exactement de la même liste. Un registre
// unique, rempli avant tout usage, évite de transmettre une liste de modules
// à travers toute la pile d'appels.
var (
	mu       sync.RWMutex
	registry = map[string]Module{}
)

// kebabCase définit la forme autorisée des identifiants de module.
//
// POURQUOI aussi strict : l'ID sert de clé dans le registre, apparaît dans
// les noms de ressources Kubernetes et dans l'URL de la console ; un ID
// fantaisiste casserait silencieusement ces trois usages. On le refuse donc
// dès l'enregistrement, au démarrage, plutôt qu'à l'exécution.
var kebabCase = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Register adds a module to the global registry.
//
// Elle PANIQUE en cas d'ID vide, d'ID déjà pris ou d'ID non kebab-case :
// ce sont des erreurs de programmation, détectables au démarrage ; mieux
// vaut un échec bruyant et immédiat qu'un module introuvable ou écrasé des
// heures plus tard.
func Register(m Module) {
	info := m.Info()
	id := info.ID

	if id == "" {
		panic("module.Register: module ID must not be empty")
	}
	if !kebabCase.MatchString(id) {
		panic(fmt.Sprintf("module.Register: module ID %q is not valid kebab-case", id))
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := registry[id]; exists {
		panic(fmt.Sprintf("module.Register: module %q is already registered", id))
	}
	registry[id] = m
}

// Get returns the module registered under id, if any.
func Get(id string) (Module, bool) {
	mu.RLock()
	defer mu.RUnlock()

	m, ok := registry[id]
	return m, ok
}

// All returns every registered module in dependency order: a module always
// appears AFTER the modules it requires.
//
// Le tri est topologique et DÉTERMINISTE (les ex æquo sont départagés par
// ordre alphabétique d'ID), pour que le CLI et la console déroulent la même
// séquence à chaque exécution.
//
// Elle PANIQUE dans deux cas, tous deux des erreurs de programmation qui
// doivent tomber au premier appel plutôt que produire une séquence fausse :
//   - une dépendance déclare un ID inconnu : l'ignorer silencieusement
//     ferait installer un module avant son prérequis absent ;
//   - les dépendances forment un cycle : aucun ordre d'installation ne peut
//     le satisfaire, le message de panique contient le cycle lisible
//     (ex. "a -> b -> a") pour localiser l'erreur immédiatement.
func All() []Module {
	mu.RLock()
	defer mu.RUnlock()

	// Vérification préalable : toute dépendance doit être enregistrée. C'est
	// fait au PREMIER appel de All (et non dans Register) parce qu'un module
	// peut être enregistré avant sa dépendance, selon l'ordre des init.
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		for _, dep := range registry[id].Info().Requires {
			if _, ok := registry[dep]; !ok {
				panic(fmt.Sprintf("module.All: module %q requires unknown module %q", id, dep))
			}
		}
	}

	ordered := topoSort(ids)

	out := make([]Module, 0, len(ordered))
	for _, id := range ordered {
		out = append(out, registry[id])
	}
	return out
}

// topoSort trie les IDs par ordre topologique (dépendances d'abord) via un
// parcours DFS coloré. Les nœuds sont visités en ordre alphabétique pour
// garantir un résultat déterministe, et le chemin DFS en cours est conservé
// pour pouvoir nommer le cycle exact en cas de retour arrière.
func topoSort(ids []string) []string {
	const (
		white = 0 // jamais visité
		grey  = 1 // en cours de visite : sur le chemin DFS actuel
		black = 2 // terminé : tous ses dépendants sont déjà triés
	)

	color := map[string]int{}
	path := []string{}
	var ordered []string

	var visit func(id string)
	visit = func(id string) {
		switch color[id] {
		case black:
			return
		case grey:
			// On retombe sur un nœud du chemin courant : cycle. On extrait le
			// cycle depuis la première occurrence pour le rendre lisible.
			start := 0
			for i, p := range path {
				if p == id {
					start = i
					break
				}
			}
			cycle := append(append([]string{}, path[start:]...), id)
			panic(fmt.Sprintf("module.All: dependency cycle detected: %s", strings.Join(cycle, " -> ")))
		}

		color[id] = grey
		path = append(path, id)

		// Dépendances visitées en ordre alphabétique : déterminisme.
		deps := append([]string{}, registry[id].Info().Requires...)
		sort.Strings(deps)
		for _, dep := range deps {
			visit(dep)
		}

		path = path[:len(path)-1]
		color[id] = black
		ordered = append(ordered, id)
	}

	for _, id := range ids {
		visit(id)
	}
	return ordered
}

// Blocked renvoie la raison (phrase anglaise complète) pour laquelle m ne
// peut pas être installé maintenant, ou une chaîne vide s'il peut l'être.
//
// POURQUOI interroger l'état réel et non le seul registre : une dépendance
// « enregistrée » peut être absente ou dégradée sur le cluster ; seule sa
// State observée dit la vérité. La raison retournée alimente directement le
// champ State.Blocked et le message de la console.
func Blocked(ctx context.Context, env Env, m Module) string {
	for _, dep := range m.Info().Requires {
		mod, ok := Get(dep)
		if !ok {
			// Cas normalement déjà refusé par All ; on reste défensif car
			// Blocked peut être appelé sur un module construit à la main.
			return fmt.Sprintf("required module %q is not registered", dep)
		}

		state := mod.State(ctx, env)
		if state.Status != Installed {
			reason := fmt.Sprintf("required module %q is not installed (status: %s)", dep, state.Status)
			if state.Blocked != "" {
				reason += fmt.Sprintf(": %s", state.Blocked)
			}
			return reason
		}
	}
	return ""
}

// reinitialiserPourTest vide le registre global.
//
// Non exportée : elle n'a de sens que pour les tests de CE package, qui
// doivent pouvoir repartir d'un registre vierge à chaque sous-test sans que
// les enregistrements d'un test ne fuient dans le suivant.
func reinitialiserPourTest() {
	mu.Lock()
	defer mu.Unlock()

	registry = map[string]Module{}
}
