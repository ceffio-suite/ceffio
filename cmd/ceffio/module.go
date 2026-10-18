// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// WHY THIS FILE: the optional features (exapps-daemon, live-transcription,
// recording) used to be reachable only through hardcoded flags and calls in
// install.go. Everything here is driven by the module registry instead: the
// flags, the install order, the dependency expansion and the state reads all
// come from module.All(), so adding a module to the registry is enough to
// make it installable, removable and observable from the CLI.

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ceffio-suite/ceffio/internal/acme"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/stack"
	// Blank import: each module registers itself from the init() of its own
	// package, and Go only runs the init() of packages the binary actually
	// imports. Without this line the registry would be EMPTY and every
	// command below would silently see zero modules. internal/modules/all.go
	// is the single aggregation point (and its test is the guardrail).
	_ "github.com/ceffio-suite/ceffio/internal/modules"
)

// kubeClient builds the Kubernetes client shared by the module commands and
// by the optional-module phase of `ceffio install`.
//
// WHY this resolution order: it is EXACTLY the one of the administration
// console (internal/console/console.go, New): in-cluster configuration
// first, then the default kubeconfig loading rules. The same binary runs in
// both contexts, and two different resolutions would mean two different
// truths about "which cluster am I talking to".
func kubeClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			rules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("Kubernetes configuration: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes client: %w", err)
	}
	return cs, nil
}

// moduleEnv assembles the environment the registry modules act on.
//
// The Kubernetes client is BEST-EFFORT: `module list` must still print the
// catalog when no cluster is reachable — the modules then report Unknown
// (socle.sansClient), which is the honest answer, and a hard failure here
// would hide the catalog exactly when the operator needs it to understand
// what is installed where.
//
// The ACME settings are the SAME rule for the same reason: a broken value must
// not make `module list` fail, because listing the catalog is how an operator
// discovers what is installed before fixing anything. An invalid setting is
// reported on stderr and the historical HTTP-01 is used, so that a read-only
// command keeps answering.
func moduleEnv(domain string) module.Env {
	env := module.Env{Domain: domain, Out: os.Stdout, Acme: acme.HTTP01()}
	if kube, err := kubeClient(); err == nil {
		env.Kube = kube
	} else {
		fmt.Fprintf(os.Stderr, "⚠ no Kubernetes client (%v) — states will read \"unknown\"\n", err)
	}
	if reglages, err := acme.DepuisEnvironnement(); err == nil {
		env.Acme = reglages
	} else {
		fmt.Fprintf(os.Stderr, "⚠ %v — assuming the %s challenge\n", err, acme.ChallengeHTTP)
	}
	return env
}

// optionalIDs returns the IDs of the Optional modules, in registry order.
func optionalIDs() []string {
	var ids []string
	for _, m := range module.All() {
		if i := m.Info(); i.Kind == module.Optional {
			ids = append(ids, i.ID)
		}
	}
	return ids
}

func newModuleCmd() *cobra.Command {
	var domain string

	c := &cobra.Command{
		Use:   "module",
		Short: "Manage the optional modules (driven by the registry)",
		Long: `Lists, installs, removes and inspects the modules of the suite.

The catalog is the module registry: every optional feature declares itself
there (ID, dependencies, resources, warnings), and these commands only walk
it — no feature list is hardcoded in the CLI.

Core modules (platform, data, identity, files, talk, mail, …) are NOT
managed here: they are the product, deployed by "ceffio install" in its own
sequence, and removed with the cluster by "ceffio uninstall".`,
	}

	// Same production default as `ceffio install` (see the note there):
	// every deployment goes through the reference domain until further
	// notice. Module installs that write public URLs need it.
	c.PersistentFlags().StringVar(&domain, "domain", "ceffio.example.com",
		"Base domain of the installation (e.g. company.fr)")

	c.AddCommand(
		newModuleListCmd(&domain),
		newModuleInstallCmd(&domain),
		newModuleRemoveCmd(&domain),
		newModuleStatusCmd(&domain),
	)
	return c
}

func newModuleListCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every module of the registry with its state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			env := moduleEnv(*domain)

			fmt.Printf("%-20s %-9s %-12s %s\n", "ID", "TYPE", "STATE", "RESOURCES")
			for _, m := range module.All() {
				i := m.Info()
				kind := "core"
				if i.Kind == module.Optional {
					kind = "optional"
				}
				// State is read from the cluster, never guessed: a module
				// can be half-installed or degraded, and hiding that would
				// make the list lie (see module.Status).
				st := m.State(ctx, env)
				resources := i.Resources
				if resources == "" {
					resources = "-"
				}
				fmt.Printf("%-20s %-9s %-12s %s\n", i.ID, kind, st.Status, resources)
			}
			return nil
		},
	}
}

// planInstallation returns the modules to install for a target ID: the
// transitive closure of its dependencies plus the target itself, in
// REGISTRY ORDER (module.All is topological: a dependency always comes
// before the module that requires it, so walking All() and keeping the
// closure members yields a valid install sequence for free).
func planInstallation(id string) []module.Module {
	cible, _ := module.Get(id)
	closure := map[string]bool{id: true}

	// Expand the dependencies recursively. The walk goes through All(),
	// which panics on an unknown dependency — the same guarantee the
	// install sequence relies on.
	var expand func(m module.Module)
	expand = func(m module.Module) {
		for _, dep := range m.Info().Requires {
			if closure[dep] {
				continue
			}
			closure[dep] = true
			if dm, ok := module.Get(dep); ok {
				expand(dm)
			}
		}
	}
	expand(cible)

	var plan []module.Module
	for _, m := range module.All() {
		if closure[m.Info().ID] {
			plan = append(plan, m)
		}
	}
	return plan
}

func newModuleInstallCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "install <id>",
		Short: "Install an optional module and its missing dependencies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			m, ok := module.Get(id)
			if !ok {
				return fmt.Errorf("unknown module %q (optional modules: %s)",
					id, strings.Join(optionalIDs(), ", "))
			}
			if m.Info().Kind == module.Core {
				return fmt.Errorf("%q is a core module: core modules are installed by `ceffio install`", id)
			}

			ctx := cmd.Context()
			env := moduleEnv(*domain)
			plan := planInstallation(id)

			for _, pm := range plan {
				pid := pm.Info().ID
				pinfo := pm.Info()

				if pinfo.Kind == module.Core {
					// A core dependency belongs to the install sequence:
					// its registry Install either delegates to a phase
					// that needs settings the registry does not carry
					// (mail and its SMTP relay) or refuses outright. If
					// the platform is there, so is the core module.
					st := pm.State(ctx, env)
					if st.Status != module.Installed {
						return fmt.Errorf("module %q requires the core module %q, which is not installed (status: %s): run `ceffio install`",
							id, pid, st.Status)
					}
					fmt.Printf("∙ %s: core dependency present\n", pid)
					continue
				}

				st := pm.State(ctx, env)
				if st.Status == module.Installed {
					fmt.Printf("∙ %s: already installed\n", pid)
					continue
				}
				if pid != id {
					fmt.Printf("∙ %s requires %s: installing it\n", id, pid)
				}
				// Blocked is the registry's own verdict on the
				// dependencies: asking it here (and not recomputing the
				// requires graph) keeps a single source of truth.
				if raison := module.Blocked(ctx, env, pm); raison != "" {
					return fmt.Errorf("module %q cannot be installed: %s", pid, raison)
				}
				fmt.Printf("→ installing %s\n", pid)
				if err := pm.Install(ctx, env); err != nil {
					return fmt.Errorf("installing module %q: %w", pid, err)
				}
				fmt.Printf("✓ %s installed\n", pid)
			}
			return nil
		},
	}
}

func newModuleRemoveCmd(domain *string) *cobra.Command {
	var oui bool

	c := &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove an optional module",
		Long: `Removes an optional module: workloads, services and volumes it created.

Refuses a core module (they go away with the cluster, via "ceffio uninstall")
and refuses when another INSTALLED module declares a dependency on it —
removing a dependency from under a running module would leave it broken with
nothing in the logs pointing at the cause.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			m, ok := module.Get(id)
			if !ok {
				return fmt.Errorf("unknown module %q (optional modules: %s)",
					id, strings.Join(optionalIDs(), ", "))
			}
			info := m.Info()
			if info.Kind == module.Core {
				return fmt.Errorf("%q is a core module: core modules are installed by `ceffio install` and removed by `ceffio uninstall`", id)
			}

			ctx := cmd.Context()
			env := moduleEnv(*domain)

			// Reverse dependency check, on OBSERVED states: a registered
			// dependent that is not installed does not block the removal.
			for _, other := range module.All() {
				oi := other.Info()
				for _, dep := range oi.Requires {
					if dep != id {
						continue
					}
					if st := other.State(ctx, env); st.Status == module.Installed {
						return fmt.Errorf("module %q is installed and requires %s: remove %q first",
							oi.ID, id, oi.ID)
					}
				}
			}

			if info.Warning != "" {
				fmt.Printf("⚠ %s\n", info.Warning)
			}
			fmt.Printf("This will remove the module %q (%s), including the volumes it created.\n", id, info.Title)
			if !oui {
				fmt.Print("Confirm (type \"yes\"): ")
				rep, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(rep)) != "yes" {
					fmt.Println("Canceled.")
					return nil
				}
			}

			fmt.Printf("→ removing %s\n", id)
			if err := m.Uninstall(ctx, env); err != nil {
				return fmt.Errorf("removing module %q: %w", id, err)
			}
			fmt.Printf("✓ %s removed\n", id)
			return nil
		},
	}

	c.Flags().BoolVar(&oui, "yes", false, "Do not ask for confirmation")
	return c
}

func newModuleStatusCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status <id>",
		Short: "Show the detailed state of a module",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			m, ok := module.Get(id)
			if !ok {
				return fmt.Errorf("unknown module %q (known modules: %s)", id,
					strings.Join(knownIDs(), ", "))
			}
			info := m.Info()
			ctx := cmd.Context()
			env := moduleEnv(*domain)
			st := m.State(ctx, env)

			kind := "core"
			if info.Kind == module.Optional {
				kind = "optional"
			}
			fmt.Printf("Module      %s (%s)\n", info.ID, info.Title)
			fmt.Printf("Type        %s\n", kind)
			if len(info.Namespaces) > 0 {
				fmt.Printf("Namespaces  %s\n", strings.Join(info.Namespaces, ", "))
			}
			if info.Resources != "" {
				fmt.Printf("Resources   %s\n", info.Resources)
			}
			fmt.Printf("Status      %s\n", st.Status)
			if st.Detail != "" {
				fmt.Printf("Detail      %s\n", st.Detail)
			}
			if st.Blocked != "" {
				fmt.Printf("Blocked     %s\n", st.Blocked)
			}
			return nil
		},
	}
}

// knownIDs lists every registered module ID, in registry order.
func knownIDs() []string {
	var ids []string
	for _, m := range module.All() {
		ids = append(ids, m.Info().ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Registry-derived layer list, shared by `ceffio status` and `ceffio doctor`.
// ---------------------------------------------------------------------------

// registryLayers derives the namespace list from the module registry,
// replacing the hardcoded stack.Layers table.
//
// WHY DERIVE IT: the old table knew seven namespaces and missed the ones the
// registry declares (ceffio-mail, ceffio-vault, ceffio-exapps,
// cert-manager, cnpg-system): `ceffio status` could not see a broken mail
// server. The registry is the single source of truth about where the suite
// lives, and walking it keeps status/doctor honest as modules are added.
//
// A namespace appears only ONCE (the invariant stack.Collect relies on to
// avoid counting the same pods twice — see the warning on stack.Layers).
// Naming, in three passes so the label stays stable and meaningful:
//  1. the PRIMARY namespace (Namespaces[0]) of each Core module names the
//     layer after that module — Core first because it defines the product
//     (ceffio-video is "talk", not "recording", even though recording also
//     lives there);
//  2. same for Optional modules (ceffio-exapps → "exapps-daemon");
//  3. secondary namespaces (cnpg-system, cert-manager) are named after the
//     namespace itself: no module owns them primarily.
func registryLayers() []struct{ Name, Namespace string } {
	type layer = struct{ Name, Namespace string }
	seen := map[string]bool{}
	var out []layer

	claim := func(kind module.Kind) {
		for _, m := range module.All() {
			i := m.Info()
			if i.Kind != kind || len(i.Namespaces) == 0 {
				continue
			}
			ns := i.Namespaces[0]
			if seen[ns] {
				continue
			}
			seen[ns] = true
			out = append(out, layer{i.ID, ns})
		}
	}
	claim(module.Core)
	claim(module.Optional)

	for _, m := range module.All() {
		for _, ns := range m.Info().Namespaces {
			if seen[ns] {
				continue
			}
			seen[ns] = true
			out = append(out, layer{ns, ns})
		}
	}
	return out
}

// useRegistryLayers points stack.Collect at the registry-derived layer list.
//
// WHY ASSIGN A VARIABLE OF ANOTHER PACKAGE: stack.Layers lives in
// internal/stack, which this batch must not modify (the shared collector is
// also used elsewhere and its rework belongs to a later batch). The variable
// is exported precisely as the list Collect walks, so the command layer can
// replace the source of the list without touching the collector.
func useRegistryLayers() {
	stack.Layers = registryLayers()
}

// namespaceOnlyOptional reports whether a namespace is declared exclusively
// by Optional modules.
//
// WHY: doctor must not cry "critical" for a namespace the operator never
// asked for. The old rule keyed on the layer NAME ("video"), a leftover of a
// --video flag that no longer exists; the registry answers the question
// directly — ceffio-exapps is optional-only, ceffio-video is not (talk is
// Core and lives there).
func namespaceOnlyOptional(ns string) bool {
	claimed := false
	for _, m := range module.All() {
		i := m.Info()
		for _, n := range i.Namespaces {
			if n != ns {
				continue
			}
			if i.Kind == module.Core {
				return false
			}
			claimed = true
		}
	}
	return claimed
}
