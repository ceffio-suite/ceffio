// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/spf13/cobra"
)

func newDNSCmd() *cobra.Command {
	var domaine string

	c := &cobra.Command{
		Use:   "dns",
		Short: "Check the DNS configuration (A, AAAA, MX, SPF, DKIM, DMARC, PTR)",
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Check that every host the installed modules expose resolves",
		Long: `Resolves each host declared by the INSTALLED modules and reports what came back.

THE HOST LIST COMES FROM THE REGISTRY, not from a table in this file. A module that
declares a Service declares its subdomain, so a module installed tomorrow is checked
without anyone editing this command — and a module that is NOT installed is not
checked, so the output does not send the operator to create a DNS record for a host
nothing serves.

Each host is resolved with the system resolver, which is what the browser ultimately
uses. A record that resolves to the machine's own public address is right; one that
resolves elsewhere is reported with the address it found, because "it resolves" and
"it resolves to us" are two different answers and only one of them works.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if domaine == "" {
				return fmt.Errorf("--domain is required: the hosts are built from it")
			}
			useRegistryLayers()
			return verifierDNS(domaine)
		},
	}
	status.Flags().StringVar(&domaine, "domain", "", "Base domain (e.g. company.fr)")
	c.AddCommand(status)
	return c
}

// hoteOS is a host the platform should answer on, and what declared it.
type hoteDNS struct {
	Hote      string
	Declare   string
	Technique bool
}

// hotesDeclares builds the host list from the modules.
//
// ONLY THE INSTALLED OR THE DEFAULT ONES: a module that is optional and not installed
// keeps its subdomain free, and checking it would report a missing record for a host
// that is not meant to exist. The state is read from the cluster, which is the only
// honest source — a stored flag can be stale after a `module remove`.
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

// verifierDNS resolves each declared host and reports the answer.
//
// THE EXIT CODE IS THE VERDICT: 1 when a host does not resolve, 0 when every host
// does. A command that always succeeds is a command nobody can put in a script.
func verifierDNS(domaine string) error {
	hotess := hotesDeclares(domaine)
	if len(hotess) == 0 {
		return fmt.Errorf("no module declares a host on %s: nothing to check. A module "+
			"declares its subdomain through Info().Services", domaine)
	}

	fmt.Printf("Hosts declared by the modules on %s:\n\n", domaine)
	manquants := 0
	var techniques []hoteDNS

	for _, h := range hotess {
		if h.Technique {
			techniques = append(techniques, h)
			continue
		}
		if err := verifierUnHote(h); err != nil {
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
			if err := verifierUnHote(h); err != nil {
				manquants++
				fmt.Printf("  ✗ %-32s %v\n     declared by %s\n", h.Hote, err, h.Declare)
				continue
			}
		}
	}

	if manquants > 0 {
		fmt.Printf("\n%d host(s) do not resolve. Create the missing records, or remove the "+
			"module that declares them.\n", manquants)
		os.Exit(1)
	}
	fmt.Printf("\n✓ %d host(s) resolve.\n", len(hotess))
	return nil
}

// verifierUnHote resolves one host, with a short timeout.
//
// THE TIMEOUT IS SHORT ON PURPOSE — two seconds: a wrong record answers immediately,
// and waiting the resolver's default would make a broken installation take minutes to
// diagnose.
func verifierUnHote(h hoteDNS) error {
	c := net.Resolver{}
	ctx, annuler := context.WithTimeout(context.Background(), 2*time.Second)
	defer annuler()

	addrs, err := c.LookupHost(ctx, h.Hote)
	if err != nil {
		return fmt.Errorf("does not resolve: %s", court(err.Error()))
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolves to nothing")
	}
	fmt.Printf("  ✓ %-32s %s\n", h.Hote, strings.Join(addrs, ", "))
	return nil
}

// court keeps a resolver error readable on one line: the system resolver's messages
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
