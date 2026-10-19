// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/settings"
	"github.com/spf13/cobra"
)

// newModuleConfigCmd reads and writes a module's settings from the command line.
//
// WHY THE CLI AND NOT ONLY THE CONSOLE: the settings must be reachable when the
// console is not — an installation whose console pod is down, a script that
// provisions an installation end to end, an operator working over SSH. The
// console and the CLI share the SAME contract, the SAME validation and the SAME
// storage: a value accepted here is accepted there, and the two cannot disagree
// about what is stored.
//
// SECRETS ARE READ FROM STANDARD INPUT, never from an argument: an argument is
// visible in `ps` for every account on the machine and lands in the shell
// history. `key=-` reads the value from the input, so a credential never
// appears in a command line.
func newModuleConfigCmd(domain *string) *cobra.Command {
	var tester bool

	c := &cobra.Command{
		Use:   "config <id> [<group> [key=value …]]",
		Short: "Read or write a module's settings",
		Long: `Reads or writes the settings a module declares.

  ceffio module config <id>                       list the groups and current values
  ceffio module config <id> <group>               the same, for one group
  ceffio module config <id> <group> key=value …   validate, store and apply
  ceffio module config <id> <group> --test …      check without storing

A SECRET IS READ FROM THE INPUT, never from an argument: pass key=- and the
value is read from standard input. An argument would be visible in ps for every
account on the machine, and would land in the shell history.

A secret left out KEEPS the stored value, so a group can be re-saved without
retyping a password.

The values are validated before anything is stored: an unknown key, a missing
required field or a value outside its options is refused with the field named,
exactly as the console refuses it.`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			m, ok := module.Get(id)
			if !ok {
				return fmt.Errorf("unknown module: %s (see `ceffio module list`)", id)
			}
			cfg, ok := m.(module.Configurable)
			if !ok {
				return fmt.Errorf("module %s declares no settings", id)
			}

			// No group named: the whole catalogue is printed, which is how an
			// operator discovers what can be set before setting anything.
			if len(args) == 1 {
				if tester {
					return fmt.Errorf("--test needs a group: nothing to check")
				}
				return afficherReglages(cmd, m, cfg, "")
			}

			groupe := args[1]
			g, ok := groupeDe(cfg, groupe)
			if !ok {
				return fmt.Errorf("module %s has no group %q (groups: %s)", id, groupe, idsDesGroupes(cfg))
			}

			// A group named, no values: it is a read of that group.
			if len(args) == 2 {
				return afficherReglages(cmd, m, cfg, groupe)
			}

			valeurs, err := valeursDepuisArguments(cmd, g, args[2:])
			if err != nil {
				return err
			}

			env := moduleEnvCLI(*domain, id)

			if tester {
				testable, ok := m.(module.Testable)
				if !ok {
					return fmt.Errorf("module %s has no check for its settings", id)
				}
				// Validated first, so a typo is reported as a field error
				// rather than as a connection failure the operator would chase.
				if err := module.Validate(g, valeurs); err != nil {
					return err
				}
				r := testable.Test(cmd.Context(), env, groupe, valeurs)
				for _, e := range r.Steps {
					fmt.Printf("  · %s\n", e)
				}
				if !r.OK {
					return fmt.Errorf("%s", r.Detail)
				}
				fmt.Printf("✓ %s\n", r.Detail)
				return nil
			}

			if err := cfg.Apply(cmd.Context(), env, groupe, valeurs); err != nil {
				return err
			}
			fmt.Printf("✓ %s/%s saved and applied\n", id, groupe)
			return nil
		},
	}

	c.Flags().BoolVar(&tester, "test", false,
		"check the values without storing them")
	return c
}

// afficherReglages prints one group, or every group when group is empty.
//
// The values are read through the MODULE, not through the store: a module that
// keeps its settings elsewhere (a path another component reads) answers here
// too, and the CLI never has to know where they live.
func afficherReglages(cmd *cobra.Command, m module.Module, cfg module.Configurable, groupe string) error {
	env := moduleEnvCLI("", m.Info().ID)
	for _, g := range cfg.Settings() {
		if groupe != "" && g.ID != groupe {
			continue
		}
		vals, err := cfg.Current(cmd.Context(), env, g.ID)
		if err != nil {
			// One group failing to read does not hide the others.
			fmt.Printf("%s: unreadable (%v)\n", g.ID, err)
			continue
		}
		fmt.Printf("%s — %s\n", g.ID, g.Title)
		if g.Description != "" {
			fmt.Printf("  %s\n", g.Description)
		}
		for _, f := range g.Fields {
			marque := " "
			if f.Required {
				marque = "*"
			}
			// A secret arrives as the placeholder or as empty, NEVER as its
			// value: the store does not send it back, and the CLI has no way
			// of showing what it does not receive.
			fmt.Printf("  %s %-18s = %s\n", marque, f.Key, valeurAffichee(vals, f))
		}
	}
	return nil
}

// valeurAffichee renders one field for the terminal.
func valeurAffichee(vals module.Values, f module.Field) string {
	v, present := vals[f.Key]
	switch {
	case f.Type == module.Secret && v == module.SecretSet:
		return "(stored — pass " + f.Key + "=- to replace)"
	case f.Type == module.Secret:
		return "(not set)"
	case !present && f.Default != "":
		return f.Default + "  (default)"
	case v == "":
		return "(empty)"
	default:
		return v
	}
}

// valeursDepuisArguments turns `key=value` pairs into values, reading the ones
// whose value is "-" from standard input.
func valeursDepuisArguments(cmd *cobra.Command, g module.Group, args []string) (module.Values, error) {
	champs := map[string]module.Field{}
	for _, f := range g.Fields {
		champs[f.Key] = f
	}

	valeurs := module.Values{}
	lecteur := bufio.NewReader(cmd.InOrStdin())
	for _, a := range args {
		cle, val, trouve := strings.Cut(a, "=")
		cle = strings.TrimSpace(cle)
		if !trouve {
			return nil, fmt.Errorf("%q is not a key=value pair", a)
		}
		f, ok := champs[cle]
		if !ok {
			return nil, fmt.Errorf("unknown field %q in %s/%s", cle, g.ID, cle)
		}

		if val == "-" {
			// The value is read from the input, so it never appears in `ps`
			// nor in the shell history.
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", f.Label)
			ligne, err := lecteur.ReadString('\n')
			if err != nil && ligne == "" {
				return nil, fmt.Errorf("reading %s from the input: %w", cle, err)
			}
			val = strings.TrimRight(ligne, "\r\n")
		}
		valeurs[cle] = val
	}
	return valeurs, nil
}

func groupeDe(cfg module.Configurable, id string) (module.Group, bool) {
	for _, g := range cfg.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

func idsDesGroupes(cfg module.Configurable) string {
	var ids []string
	for _, g := range cfg.Settings() {
		ids = append(ids, g.ID)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// moduleEnvCLI builds the Env for a settings command.
//
// THE MODULE ID IS SET, and the stores are the concrete kubectl-backed ones:
// internal/settings refuses an Env without an ID because two modules would then
// share one entry. A missing Kubernetes client is reported on stderr and the
// command continues — reading a settings catalogue must work on a machine that
// is not the cluster, which is how an operator inspects an installation they
// cannot reach.
func moduleEnvCLI(domain, moduleID string) module.Env {
	env := moduleEnv(domain)
	env.ModuleID = moduleID
	env.Settings = settings.ConfigMaps{}
	env.Secrets = settings.Secrets{}
	return env
}
