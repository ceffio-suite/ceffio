// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

import "github.com/ceffio-suite/ceffio/internal/acme"

// This file re-exports the DNS provider table through the ingress package.
//
// WHY: the module `ingress` describes the TLS settings and needs to know which
// credential fields each provider declares. The table itself belongs to
// internal/acme, where the solver's expectations are written — re-declaring it
// here would give two tables to keep in step, and a provider added to one would
// silently miss the other.
//
// The re-export keeps the module's import list short without copying anything.

// ProvidersConnus lists the providers Ceffio describes.
func ProvidersConnus() []acme.Provider { return acme.ProvidersConnus() }

// IdentifiantsDuProvider returns one provider's credential fields.
func IdentifiantsDuProvider(p acme.Provider) ([]acme.ChampIdentifiant, bool) {
	return acme.IdentifiantsDuProvider(p)
}

// ChampsIdentifiant returns one provider's fields, or the free-form fallback.
func ChampsIdentifiant(p acme.Provider) []acme.ChampIdentifiant {
	return acme.ChampsIdentifiant(p)
}
