// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The JMAP client used by the mail package.
//
// WHY A CLIENT AND NOT CALLS SCATTERED IN EACH FILE: the two behaviours that
// matter — adding the management account, and turning Stalwart's in-body
// refusals into errors — were duplicated in `internal/mail` and in the CLI, and
// the CLI copy judged refusals differently. A single client means a single
// judgement, exercised once by tests, and the raw form is explicit at the one
// call site that needs it (route deletion, see envoi.go).
package mail

import (
	"context"

	"github.com/ceffio-suite/ceffio/internal/mail/jmap"
)

// clientJMAP returns a client bound to Stalwart's management account.
//
// THE TRANSPORT IS READ AT EACH CALL, not captured: tests substitute
// `transportJMAP`, and a captured transport would make the substitution depend
// on initialization order — a test that passes or fails depending on which test
// built the client first.
func clientJMAP() *jmap.Client {
	return jmap.Nouveau(jmap.Func(func(ctx context.Context, corps []byte) ([]byte, error) {
		return transportJMAP(ctx, corps)
	}), compteGestion)
}

// appelJMAP sends a JMAP request and returns the first response body.
//
// THE REFUSALS ARE JUDGED HERE, once: a `notCreated`/`notUpdated`/
// `notDestroyed` is a write that did not happen, and taking it for a success is
// how a configuration silently stays the old one.
func appelJMAP(ctx context.Context, methode string, args map[string]any) (map[string]any, error) {
	return clientJMAP().Appel(ctx, methode, args)
}

// appelJMAPBrut is the same WITHOUT judging the refusals.
//
// RESERVED FOR ONE CALL SITE, and it is a measured exception: 1.0.3 answers
// `notDestroyed` for a route that is already gone, so failing on the refusal
// would make `direct` mode undeployable on an installation whose relay route
// was deleted. That caller decides on the read-back instead.
func appelJMAPBrut(ctx context.Context, methode string, args map[string]any) (string, map[string]any, error) {
	return clientJMAP().AppelBrut(ctx, methode, args)
}
