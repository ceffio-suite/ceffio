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

// WHY a global registry: modules register themselves from their own package
// (init or an explicit call at startup), and both frontends — CLI and
// console — need exactly the same list. A single registry, filled before any
// use, avoids passing a module list through the entire call stack.
var (
	mu       sync.RWMutex
	registry = map[string]Module{}
)

// kebabCase defines the allowed shape of module identifiers.
//
// WHY so strict: the ID serves as the registry key, appears in Kubernetes
// resource names and in the console URL; a fanciful ID would silently break
// all three uses. It is therefore rejected at registration time, at startup,
// rather than at runtime.
var kebabCase = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Register adds a module to the global registry.
//
// It PANICS on an empty ID, an already-taken ID or a non kebab-case ID:
// these are programming errors, detectable at startup; a loud, immediate
// failure beats a missing or overwritten module discovered hours later.
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
// The sort is topological and DETERMINISTIC (ties are broken by
// alphabetical ID order), so that the CLI and the console run the same
// sequence on every execution.
//
// It PANICS in two cases, both programming errors that must fail on the
// first call rather than produce a wrong sequence:
//   - a dependency declares an unknown ID: silently ignoring it would
//     install a module before its missing prerequisite;
//   - the dependencies form a cycle: no install order can satisfy it, and
//     the panic message contains the readable cycle (e.g. "a -> b -> a") to
//     locate the error immediately.
func All() []Module {
	mu.RLock()
	defer mu.RUnlock()

	// Up-front check: every dependency must be registered. This is done on
	// the FIRST call of All (and not in Register) because a module may be
	// registered before its dependency, depending on init order.
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

// topoSort sorts the IDs in topological order (dependencies first) via a
// colored DFS walk. Nodes are visited in alphabetical order to guarantee a
// deterministic result, and the current DFS path is kept so the exact cycle
// can be named on a back edge.
func topoSort(ids []string) []string {
	const (
		white = 0 // never visited
		grey  = 1 // being visited: on the current DFS path
		black = 2 // done: all its dependencies are already sorted
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
			// We land back on a node of the current path: cycle. We
			// extract the cycle from its first occurrence to make it
			// readable.
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

		// Dependencies visited in alphabetical order: determinism.
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

// Blocked returns the reason (a full English sentence) why m cannot be
// installed now, or an empty string if it can.
//
// WHY query the actual state and not the registry alone: a "registered"
// dependency may be absent or degraded on the cluster; only its observed
// State tells the truth. The returned reason feeds directly into the
// State.Blocked field and the console message.
func Blocked(ctx context.Context, env Env, m Module) string {
	for _, dep := range m.Info().Requires {
		mod, ok := Get(dep)
		if !ok {
			// Case normally already rejected by All; we stay defensive
			// because Blocked can be called on a hand-built module.
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

// reinitialiserPourTest empties the global registry.
//
// Unexported: it only makes sense for the tests of THIS package, which must
// be able to start from a clean registry on each sub-test without one
// test's registrations leaking into the next.
func reinitialiserPourTest() {
	mu.Lock()
	defer mu.Unlock()

	registry = map[string]Module{}
}
