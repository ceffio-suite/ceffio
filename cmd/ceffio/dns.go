// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/dnscheck"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/spf13/cobra"
)

func newDNSCmd() *cobra.Command {
	var domaine string

	c := &cobra.Command{
		Use:   "dns",
		Short: "Resolve the hosts the modules declare",
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Check that every host the modules declare resolves",
		Long: `Resolves each host the modules declare and reports what came back.

THE HOST LIST COMES FROM THE REGISTRY, not from a table in this file: a module
declares its subdomain through Info().Services, so a module added tomorrow is
checked without editing this command. A module OBSERVED as absent or being
removed is skipped — its subdomain is free on purpose — so the output does not
send the operator to create a record for a host nothing serves. When the cluster
cannot be read, every state is "unknown" and every declared host is kept: an
empty list would look like a success.

THE LOOKUPS GO TO PUBLIC RESOLVERS (1.1.1.1 and 9.9.9.9 by default, overridable
through CEFFIO_DNS_SERVERS): a public record is what the outside world sees, and
the resolver of a freshly built host often knows a name the Internet does not.

WHAT IS CHECKED HERE IS ONLY THAT THE NAME RESOLVES. The mail-specific records
(MX, SPF, DKIM, DMARC, reverse DNS) and the mail ports are checks declared by
the modules themselves: they are printed below, for each installed module that
declares any. Fixing a missing A record is this command's business; choosing an
MX target is not.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if domaine == "" {
				return fmt.Errorf("--domain is required: the hosts are built from it")
			}
			useRegistryLayers()
			return verifierDNS(cmd.Context(), domaine)
		},
	}
	status.Flags().StringVar(&domaine, "domain", "", "Base domain (e.g. company.fr)")
	c.AddCommand(status)
	return c
}

// hoteDNS is a host the platform should answer on, and what declared it.
type hoteDNS struct {
	Hote      string
	Declare   string
	Technique bool
}

// hotesDeclares builds the host list from the modules.
//
// EVERY DECLARED SUBDOMAIN, without looking at any state: this is the registry's
// answer to "which names does the suite claim". Deciding which of them are
// supposed to exist is the caller's job (see filtrerAbsents), because that
// question needs the cluster and this one does not.
func hotesDeclares(domaine string) []hoteDNS {
	var out []hoteDNS
	for _, m := range module.All() {
		info := m.Info()
		for _, s := range info.Services {
			if s.Sub == "" {
				continue
			}
			out = append(out, hoteDNS{
				Hote:      s.Sub + "." + domaine,
				Declare:   info.ID,
				Technique: s.Technical,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hote < out[j].Hote })
	return out
}

// filtrerAbsents drops the hosts whose module is observed as absent.
//
// THE STATE IS THE ONLY HONEST SOURCE: a stored flag can be stale after a
// `module remove`, and a module that is not installed keeps its subdomain free —
// reporting a missing record for a host nothing serves would send the operator
// to create a name that should not exist.
func filtrerAbsents(hotess []hoteDNS, etats map[string]module.State) []hoteDNS {
	out := make([]hoteDNS, 0, len(hotess))
	for _, h := range hotess {
		if st, ok := etats[h.Declare]; ok && !estPresenteObserve(st) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// verifierDNS resolves each declared host and reports the answer, then prints
// the checks the installed modules declare.
//
// THE EXIT CODE IS THE VERDICT for the resolution part: 1 when a host does not
// resolve, 0 when every host does. The module checks below are INFORMATIONAL
// here — `module check <id>` is the command that owns their exit code, and
// printing them after a failing resolution would otherwise mix two verdicts in
// one exit code.
func verifierDNS(ctx context.Context, domaine string) error {
	env := moduleEnv(domaine)
	etats := etatsDesModules(ctx, env)
	hotess := filtrerAbsents(hotesDeclares(domaine), etats)
	if len(hotess) == 0 {
		return fmt.Errorf("no module declares a host on %s: nothing to check. A module "+
			"declares its subdomain through Info().Services", domaine)
	}

	client := dnscheck.Nouveau()

	fmt.Printf("Hosts declared by the modules on %s:\n\n", domaine)
	manquants := 0
	var techniques []hoteDNS

	for _, h := range hotess {
		if h.Technique {
			techniques = append(techniques, h)
			continue
		}
		if err := verifierUnHote(ctx, client, h); err != nil {
			manquants++
			fmt.Printf("  ✗ %-32s %v\n     declared by %s\n", h.Hote, err, h.Declare)
			continue
		}
	}

	// THE TECHNICAL HOSTS ARE CHECKED TOO, but listed apart: they are not meant to be
	// opened in a browser, so a missing record there is a fault without being a
	// user-facing one.
	if len(techniques) > 0 {
		fmt.Println("\nTechnical hosts (machines, not browsers):")
		for _, h := range techniques {
			if err := verifierUnHote(ctx, client, h); err != nil {
				manquants++
				fmt.Printf("  ✗ %-32s %v\n     declared by %s\n", h.Hote, err, h.Declare)
				continue
			}
		}
	}

	afficherChecksDesModules(ctx, env, etats)

	if manquants > 0 {
		fmt.Printf("\n%d host(s) do not resolve. Create the missing records, or remove the "+
			"module that declares them.\n", manquants)
		os.Exit(1)
	}
	fmt.Printf("\n✓ %d host(s) resolve.\n", len(hotess))
	return nil
}

// afficherChecksDesModules prints the checks of every module observed as
// present that declares any.
//
// WHY HERE: the records that matter for mail are known by the mail module, not
// by this command, and asking the operator to remember which module to query is
// how a mail server ends up with no reverse DNS. A module that is not installed
// declares nothing to print — its checks would measure a service that does not
// exist.
func afficherChecksDesModules(ctx context.Context, env module.Env, etats map[string]module.State) {
	for _, m := range module.All() {
		chk, ok := m.(module.Checker)
		if !ok {
			continue
		}
		if st, ok := etats[m.Info().ID]; ok && !estPresenteObserve(st) {
			continue
		}
		checks := chk.Checks(ctx, env)
		if len(checks) == 0 {
			continue
		}
		fmt.Printf("\nChecks declared by %s (%s):\n\n", m.Info().ID, m.Info().Title)
		afficherChecks(os.Stdout, checks)
	}
}

// verifierUnHote resolves one host through the public resolver.
func verifierUnHote(ctx context.Context, client *dnscheck.Client, h hoteDNS) error {
	addrs, err := client.Adresses(ctx, h.Hote)
	if err != nil {
		return fmt.Errorf("does not resolve: %s", court(err.Error()))
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolves to nothing")
	}
	fmt.Printf("  ✓ %-32s %s\n", h.Hote, strings.Join(addrs, ", "))
	return nil
}

// court keeps a resolver error readable on one line: the resolvers' messages
// carry trailing detail that is useful once and noise in a table.
func court(s string) string {
	if i := strings.IndexAny(s, "\n"); i >= 0 {
		s = s[:i]
	}
	const max = 90
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
