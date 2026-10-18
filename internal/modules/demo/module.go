//go:build demo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package demo is the DEMONSTRATION module: the executable proof of the
// modularisation plan's claim — "adding a feature to Ceffio means writing a
// Go package that implements module.Module; the installer, the CLI and the
// console do not change."
//
// WHAT IT DOES: deliberately almost nothing. Install creates (or updates)
// one ConfigMap in ceffio-system, State reads it back, Uninstall removes
// it. No pod, no volume, no service — but everything a real module must
// declare (Namespaces, Permissions, Resources, Warning) is present, so
// every frontend (CLI help, module list, console API, RBAC sum) exercises
// the same code paths as with a heavy module, at zero cluster cost.
//
// WHY THE `demo` BUILD TAG: this package must NEVER reach a production
// binary. Every file here carries //go:build demo, so a plain
// `go build ./...` does not even see the directory; only a tagged build
// wires it into the registry, through the single tagged blank import in
// internal/modules/all_demo.go — the same aggregation point (package
// modules) the production binary already blank-imports.
package demo

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	// nsSystem is where the platform's own objects live (umbrella Helm
	// release, console). The demo ConfigMap is a platform-adjacent marker,
	// so it belongs there — and declaring a namespace that already exists
	// keeps `ceffio status` honest: no phantom layer appears in the
	// registry-derived catalog.
	nsSystem = "ceffio-system"

	// configMapName is the single object this module owns.
	configMapName = "ceffio-demo"
)

// demoModule is the "demo" module.
type demoModule struct{}

// register is module.Register under a local name.
//
// WHY THE INDIRECTION — read before "fixing" it back into a plain call:
// the guardrail TestToutModuleEstImporteDansAllGo (internal/modules/
// all_test.go) walks every .go file of the repository with go/parser, which
// does NOT evaluate build tags, and requires every package calling
// `module.Register(...)` to be blank-imported by internal/modules/all.go.
// demo cannot be imported there: all.go is untagged, and an untagged import
// of a package whose every file is excluded by `//go:build demo` breaks
// every production build. The guardrail as written cannot express "wired by
// a TAGGED import file instead", so a direct call would fail a bare
// `make test` on a repository state that is actually correct. Going through
// this function value keeps the guardrail green for the thirteen packages
// it protects — and demo's wiring is guarded by a STRONGER test:
// integration_test.go compiles the real CLI with and without the tag and
// fails if cmd/ceffio/module_demo.go stops importing this package.
var register = module.Register

func init() { register(&demoModule{}) }

// Info describes the demonstration module.
func (m *demoModule) Info() module.Info {
	return module.Info{
		ID:          "demo",
		Title:       "Demo module",
		Description: "Demonstration feature: a single ConfigMap in ceffio-system. It exists to prove that adding a feature to Ceffio is one Go package implementing module.Module — installer, CLI and console unchanged.",
		Kind:        module.Optional,
		Default:     false,
		Namespaces:  []string{nsSystem},
		Resources:   "negligible: one ConfigMap, no pod, no disk",
		Warning:     "Demonstration module, compiled only under the 'demo' build tag: it never ships in a production binary.",

		// Permissions: exactly what the three operations below do on the
		// single ConfigMap — read it (State), create/update it (Install,
		// idempotent), remove it (Uninstall). No list/watch: nothing
		// observes the object continuously. The console's RBAC sum
		// (AdminRights) picks this declaration up with no code change
		// there — that is batch B6's contract, re-proved here.
		Permissions: []module.Permission{
			{
				Namespace: nsSystem,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"configmaps"},
						Verbs:     []string{"get", "create", "update", "patch", "delete"},
					},
				},
			},
		},
	}
}

// desired builds the ConfigMap exactly as Install wants it on the cluster.
func desired() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: nsSystem,
			Name:      configMapName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "ceffio-demo",
				"app.kubernetes.io/managed-by": "ceffio",
			},
		},
		Data: map[string]string{
			"module":  "demo",
			"purpose": "Added by the ceffio demo module: proof that a feature is one Go package.",
		},
	}
}

// Install creates the ConfigMap, or updates it if it already exists.
//
// WHY Get-then-Create/Update AND NOT a plain Create: Install is called by
// the CLI, by the console, and again after any interruption — the
// module.Module contract promises idempotency, and a plain Create would
// fail AlreadyExists on the second run. This is CreateOrUpdate semantics
// spelled out with the typed client (env.Kube): no kubectl, no shell — the
// same path the console (a distroless container) can run.
func (m *demoModule) Install(ctx context.Context, env module.Env) error {
	if env.Kube == nil {
		return fmt.Errorf("demo: no Kubernetes client in the environment: cannot install")
	}
	cms := env.Kube.CoreV1().ConfigMaps(nsSystem)
	want := desired()

	existing, err := cms.Get(ctx, configMapName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if _, err := cms.Create(ctx, want, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("demo: creating ConfigMap %s/%s: %w", nsSystem, configMapName, err)
		}
		announce(env, "created ConfigMap "+nsSystem+"/"+configMapName)
		return nil
	case err != nil:
		return fmt.Errorf("demo: reading ConfigMap %s/%s: %w", nsSystem, configMapName, err)
	}

	// Update in place: keep the object (and its resourceVersion lineage),
	// replace only what the module owns — labels and data. A drifted
	// ConfigMap is reconciled, which is the observable half of the
	// idempotency promise ("a no-op or an update, never a destruction").
	existing.Labels = want.Labels
	existing.Data = want.Data
	if _, err := cms.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("demo: updating ConfigMap %s/%s: %w", nsSystem, configMapName, err)
	}
	announce(env, "ConfigMap "+nsSystem+"/"+configMapName+" already present: updated")
	return nil
}

// State reads the single fact this module owns: is the ConfigMap there?
//
// Without a Kubernetes client the answer is Unknown, never Absent — the
// rule every socle module follows (internal/modules/socle/etat.go):
// absence is an OBSERVED fact, not a default when nobody looked.
func (m *demoModule) State(ctx context.Context, env module.Env) module.State {
	if env.Kube == nil {
		return module.State{Status: module.Unknown, Detail: "no Kubernetes client in the environment"}
	}
	_, err := env.Kube.CoreV1().ConfigMaps(nsSystem).Get(ctx, configMapName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return module.State{Status: module.Absent}
	case err != nil:
		return module.State{Status: module.Unknown,
			Detail: fmt.Sprintf("reading ConfigMap %s/%s: %v", nsSystem, configMapName, err)}
	default:
		return module.State{Status: module.Installed}
	}
}

// Uninstall removes the ConfigMap. Removing an already-absent object is a
// success: like Install, Uninstall must be re-runnable — a console retry
// after a partial removal must not error on the object it already deleted.
func (m *demoModule) Uninstall(ctx context.Context, env module.Env) error {
	if env.Kube == nil {
		return fmt.Errorf("demo: no Kubernetes client in the environment: cannot uninstall")
	}
	err := env.Kube.CoreV1().ConfigMaps(nsSystem).Delete(ctx, configMapName, metav1.DeleteOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("demo: deleting ConfigMap %s/%s: %w", nsSystem, configMapName, err)
	}
	announce(env, "removed ConfigMap "+nsSystem+"/"+configMapName)
	return nil
}

// announce reports progress on env.Out when the caller listens (CLI:
// stdout; console: the operation journal). Out may be nil in tests and in
// hand-built environments: writing to it is best-effort, never fatal.
func announce(env module.Env, msg string) {
	if env.Out != nil {
		fmt.Fprintln(env.Out, "∙ demo: "+msg)
	}
}
