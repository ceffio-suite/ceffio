// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// WHY THIS FILE: two commands read check lists — `module check <id>` and
// `dns status` — and a list printed two different ways would make the operator
// learn two layouts for one concept. The formatting lives here, the commands
// supply the list.

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// symboleCheck maps a check level to the mark printed beside it.
//
// `not_applicable` gets a mark of its own rather than being hidden: "this check
// does not apply here" is an answer the operator asked for, and hiding it makes
// the list look like it silently skipped something.
func symboleCheck(niveau module.CheckLevel) string {
	switch niveau {
	case module.CheckOK:
		return "✓"
	case module.CheckWarning:
		return "⚠"
	case module.CheckBlocking:
		return "✗"
	case module.CheckNotApplicable:
		return "·"
	default:
		return "?"
	}
}

// afficherChecks prints the checks and returns how many are blocking.
//
// DETAIL AND FIX ARE PRINTED DIFFERENTLY: Detail is what was measured (one
// line), Fix is what the operator does about it (possibly several lines, a DNS
// zone entry or a command) and is indented under the check so a copy of the
// block stays valid.
func afficherChecks(out io.Writer, checks []module.Check) (bloquants int) {
	for _, c := range checks {
		titre := c.Label
		if titre == "" {
			titre = c.ID
		}
		detail := ""
		if c.Detail != "" {
			detail = " — " + c.Detail
		}
		fmt.Fprintf(out, "  %s %-11s %s%s\n", symboleCheck(c.Level), c.Level, titre, detail)
		if c.Fix != "" {
			for _, ligne := range strings.Split(strings.TrimRight(c.Fix, "\n"), "\n") {
				fmt.Fprintf(out, "              %s\n", ligne)
			}
		}
		if c.Level == module.CheckBlocking {
			bloquants++
		}
	}
	return bloquants
}

// verifierModuleCheck runs the checks a module declares and prints them.
//
// IT REFUSES A MODULE THAT DECLARES NONE instead of printing nothing and
// succeeding: an empty success is indistinguishable from "everything was
// verified", which is precisely the false reassurance a check command must not
// produce. The error names the module, so a script can tell the two refusals
// apart.
func verifierModuleCheck(ctx context.Context, m module.Module, env module.Env, out io.Writer) (int, error) {
	chk, ok := m.(module.Checker)
	if !ok {
		return 0, fmt.Errorf("module %q declares no check (it does not implement module.Checker)", m.Info().ID)
	}
	checks := chk.Checks(ctx, env)
	if len(checks) == 0 {
		fmt.Fprintf(out, "✓ %s declares no check to report right now.\n", m.Info().ID)
		return 0, nil
	}
	fmt.Fprintf(out, "%s (%s):\n\n", m.Info().Title, m.Info().ID)
	bloquants := afficherChecks(out, checks)
	if bloquants > 0 {
		fmt.Fprintf(out, "\n%d blocking check(s).\n", bloquants)
	} else {
		fmt.Fprintln(out, "\n✓ no blocking check.")
	}
	return bloquants, nil
}

// etatsDesModules reads each module's observed state ONCE.
//
// WHY ONCE: `dns status` and the module checks both need "which modules are
// installed", and each State read can touch the cluster (a Deployment read, an
// exec in some modules). Reading it per host would multiply those calls by the
// number of subdomains, for an answer that cannot change within one command.
func etatsDesModules(ctx context.Context, env module.Env) map[string]module.State {
	etats := make(map[string]module.State, len(module.All()))
	for _, m := range module.All() {
		etats[m.Info().ID] = m.State(ctx, env)
	}
	return etats
}

// estPresenteObserve tells whether a module's state means "it is supposed to
// exist here": anything but an explicit absence or a removal in progress.
//
// UNKNOWN IS KEPT, deliberately: without a cluster client every state reads
// Unknown, and dropping those hosts would make `dns status` print an empty,
// reassuring list exactly when it could not look. Listing them may be noisy;
// hiding them would be wrong.
func estPresenteObserve(st module.State) bool {
	return st.Status != module.Absent && st.Status != module.Removing
}
