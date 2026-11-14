// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import "context"

// This file adds the second half of the module contract: a module can SAY what
// it observed outside the cluster, instead of only reporting whether its own
// objects exist.
//
// WHY IT IS SEPARATE FROM State: State answers "is the workload there?", which
// a Kubernetes read can answer. A mail server can have its Deployment ready and
// still receive nothing, because the MX record points elsewhere, port 25 is
// filtered, or the certificate does not cover the host — none of which is
// visible in the cluster. Those prerequisites live outside, so they need a
// declaration of their own, and the operator needs to see WHICH one is wrong
// and WHAT to change. The console and `ceffio module check` read this contract;
// neither names a module.

// CheckLevel says what a failed check means.
//
// THE FOUR LEVELS EXIST BECAUSE "FAILED" IS NOT ONE THING: an unverified
// SPF record degrades delivery, a wrong MX means the domain is handled
// elsewhere, and a reverse DNS that the hosting provider must set is not
// something the operator can fix in the console. Collapsing them into
// pass/fail would tell the operator to stop working on a feature that is
// merely imperfect, or to ignore a check that makes it unusable.
type CheckLevel string

const (
	CheckOK            CheckLevel = "ok"
	CheckWarning       CheckLevel = "warning"        // works, but degraded (spam, missing record…)
	CheckBlocking      CheckLevel = "blocking"       // the feature cannot work correctly
	CheckNotApplicable CheckLevel = "not_applicable" // e.g. private domain, relay mode
)

// Check is one verified prerequisite. Fix is shown verbatim (a DNS record to
// publish, a command, a sentence); the console offers to copy it.
//
// Detail and Fix are separate fields on purpose: Detail is what was MEASURED
// ("MX points to another host"), Fix is what the operator DOES about it. A
// single message inevitably mixes the two, and the fix is the part that gets
// copied into a terminal or a DNS zone — it must not carry the observation.
type Check struct {
	ID     string     `json:"id"`
	Label  string     `json:"label"`
	Level  CheckLevel `json:"level"`
	Detail string     `json:"detail"`        // what was measured
	Fix    string     `json:"fix,omitempty"` // what the operator does
}

// Checker is implemented by a module whose operation depends on things
// outside the cluster. The console shows the list on the module card
// (GET /api/modules/{id}/checks); `ceffio module check <id>` prints it and
// exits 1 when a check is Blocking.
//
// Checks MUST be read-only and idempotent: the console calls them when the
// Modules page is opened, and `ceffio dns status` calls them on every run.
// A check that fixed something would make a diagnostic change the system it
// was asked to observe.
type Checker interface {
	Checks(ctx context.Context, env Env) []Check
}

// Bloquants returns the Blocking checks (helper used by State and by Accounts).
//
// WHY A HELPER AND NOT A len(checks) COMPARISON: a module's State must be
// Degraded exactly when a blocking check fails, and computing that with a
// range loop in every module is where the off-by-one ("warning counted as
// blocking" or "not_applicable counted as a failure") would appear. One
// function, one definition.
func Bloquants(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if c.Level == CheckBlocking {
			out = append(out, c)
		}
	}
	return out
}
