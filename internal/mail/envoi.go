// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Outbound routing of Stalwart: which route sends what leaves the platform.
//
// WHY THIS FILE EXISTS, AND WHAT IT REPLACES: `Deploy` used to authenticate
// against Stalwart, print "the relay is declared in JMAP (/jmap); to be
// finalized through the admin interface" and return. Nothing was written. On a
// residential connection outbound port 25 is blocked, so a platform in that
// state RECEIVES mail and sends none — the failure is silent, and it is only
// discovered by a user whose message never arrived. The relay was stored in
// OpenBao (internal/modules/mail) but no code ever pushed it into Stalwart.
//
// THE SHAPES BELOW ARE MEASURED, not read from a specification (the JMAP
// extension has no published schema for 1.0.3). They come from the POC round
// recorded in docs/plan-mail.md §9.I:
//
//   - `x:MtaRoute/get` with `ids: null` lists the routes; the demo has a
//     `Local` route (`local`) and an `Mx` route (`mx`) and NO relay route.
//   - `x:MtaRoute/set` `create` needs the `name`, although it is read-only
//     afterwards (`{"type":"Required","property":"name"}` without it).
//   - The credential is `authSecret: {"@type":"Value","secret":"…"}`. The
//     read-back never returns the secret — only `{"@type":"Value"}` — so a
//     written password cannot be verified by reading it back; the rest of the
//     route can, and is.
//   - The outbound strategy is a singleton carrying an Expression:
//     `{"match":{"0":{"if":"is_local_domain(rcpt_domain)","then":"'local'"}},
//     "else":"'mx'"}`. Only the `else` branch designates the outside world;
//     local delivery keeps going to the `local` route whatever the relay does.
//   - `destroy` sometimes answers `notDestroyed` for an object that IS gone
//     (1.0.3 quirk, seen on accounts and routes): the read-back is the
//     authority, never the destroy response.
//
// WHAT THE TWO MODES DO, EXACTLY:
//
//	direct  no relay route; the outbound strategy's `else` branch is `'mx'`
//	        (Stalwart looks up the recipient's MX and delivers itself — the
//	        right configuration when port 25 is open).
//	relais  one Relay route named `relay` carrying host/port/credential, and
//	        the `else` branch becomes `'relay'`.
//
// ORDER OF OPERATIONS IS DELIBERATE. Going to `direct` first removes the
// `else` branch's reference to `relay`, THEN deletes the route: the other way
// round, Stalwart would hold a strategy pointing at a route that no longer
// exists for as long as the two calls take. Going to `relais` creates the
// route BEFORE pointing the strategy at it, for the same reason.
package mail

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ceffio-suite/ceffio/internal/mail/jmap"
)

// Send modes, as stored in the module settings (`mail.server`, field `envoi`).
const (
	// ModeDirect lets Stalwart deliver to the recipient's MX itself. It needs
	// outbound port 25, which most consumer connections block.
	ModeDirect = "direct"
	// ModeRelais hands outgoing mail to an authenticated relay.
	ModeRelais = "relais"
)

// Route names. `relay` is the name of the route this package owns: an operator
// who wants their own routing can add other routes, and this code neither reads
// nor deletes them.
const (
	routeRelais = "relay"
	routeMx     = "mx"
)

// descriptionRouteRelais marks the route as Ceffio-managed, so an operator who
// lists the routes sees where it comes from rather than a mystery object.
const descriptionRouteRelais = "Outbound relay, managed by Ceffio (module settings)"

// Envoi describes how outgoing mail leaves the platform.
type Envoi struct {
	Mode        string // ModeDirect or ModeRelais
	Hote        string // relay host, mode relais only
	Port        int    // relay port, mode relais only
	Utilisateur string // relay username, mode relais only
	MotDePasse  string // relay password, mode relais only
}

// Valider refuses an incomplete relay before anything is written.
//
// THE PASSWORD IS REQUIRED IN RELAIS MODE. A relay without a credential is
// refused by every provider that offers an authenticated submission port, and
// Stalwart would accept the route and bounce every message at delivery time —
// the failure would surface on a user, not here.
func (e Envoi) Valider() error {
	switch e.Mode {
	case ModeDirect:
		return nil
	case ModeRelais:
		if e.Hote == "" {
			return fmt.Errorf("relay host is empty: an outbound relay needs a host (mode %q)", ModeRelais)
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("relay port %d is not a valid TCP port", e.Port)
		}
		if e.Utilisateur == "" {
			return fmt.Errorf("relay username is empty: an authenticated relay needs an account")
		}
		if e.MotDePasse == "" {
			return fmt.Errorf("relay password is empty: store it in the vault (module settings, group relay)")
		}
		return nil
	default:
		return fmt.Errorf("unknown send mode %q (expected %q or %q)", e.Mode, ModeDirect, ModeRelais)
	}
}

// champsRoute builds the route object for a relay.
//
// `implicitTls` follows the port, as the POC measured: 465 is implicit TLS
// (SMTPS), 587 starts in clear text and upgrades with STARTTLS. Getting this
// wrong produces a connection that hangs instead of an error message.
func (e Envoi) champsRoute() map[string]any {
	return map[string]any{
		"@type":             "Relay",
		"name":              routeRelais,
		"description":       descriptionRouteRelais,
		"host":              e.Hote,
		"port":              e.Port,
		"protocol":          "smtp",
		"implicitTls":       e.Port == 465,
		"allowInvalidCerts": false,
		"authUsername":      e.Utilisateur,
		"authSecret": map[string]any{
			"@type":  "Value",
			"secret": e.MotDePasse,
		},
	}
}

// champsRouteMiseAJour is the same object without the two fields Stalwart
// treats as read-only after creation (`@type`, `name`). Sending them in an
// update is what an `invalidPatch` would come from: the POC only ever created
// routes, so the update path is written to the narrowest shape that can work.
func (e Envoi) champsRouteMiseAJour() map[string]any {
	champs := e.champsRoute()
	delete(champs, "@type")
	delete(champs, "name")
	return champs
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Outbound routing
// ---------------------------------------------------------------------------

// AppliquerEnvoi puts the mail server's outbound routing in the requested
// state, then reads it back.
//
// IDEMPOTENT: with the setting unchanged, nothing is written (`direct` mode on
// an already-direct installation makes no call at all beyond the read). In
// relais mode the route is rewritten on every call even when the visible
// fields are unchanged, because the password is never returned by a read: a
// rotated credential could not be detected any other way.
func AppliquerEnvoi(ctx context.Context, e Envoi) error {
	if err := e.Valider(); err != nil {
		return err
	}
	switch e.Mode {
	case ModeRelais:
		if err := assurerRouteRelais(ctx, e); err != nil {
			return err
		}
		if err := forcerSortie(ctx, routeRelais); err != nil {
			return err
		}
		fmt.Printf("  ∙ outgoing mail: relay %s:%d (%s)\n", e.Hote, e.Port, e.Utilisateur)
		return nil
	case ModeDirect:
		// The strategy first, the route second: see the order note in the file
		// header.
		if err := forcerSortie(ctx, routeMx); err != nil {
			return err
		}
		if err := supprimerRouteRelais(ctx); err != nil {
			return err
		}
		fmt.Println("  ∙ outgoing mail: direct (MX of the recipient)")
		return nil
	}
	return fmt.Errorf("unknown send mode %q", e.Mode)
}

// routeParNom returns the route with that name, or nil when it does not exist.
func routeParNom(ctx context.Context, nom string) (map[string]any, error) {
	routes, err := clientJMAP().Get(ctx, "x:MtaRoute/get", nil, nil)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route["name"] == nom {
			return route, nil
		}
	}
	return nil, nil
}

// assurerRouteRelais creates or updates the `relay` route and proves the result
// by reading it back.
func assurerRouteRelais(ctx context.Context, e Envoi) error {
	existante, err := routeParNom(ctx, routeRelais)
	if err != nil {
		return err
	}

	if existante == nil {
		if _, err := clientJMAP().Set(ctx, "x:MtaRoute/set", jmap.Modification{
			Creer: map[string]map[string]any{routeRelais: e.champsRoute()},
		}); err != nil {
			return fmt.Errorf("creating the relay route: %w", err)
		}
	} else {
		id, _ := existante["id"].(string)
		if id == "" {
			return fmt.Errorf("relay route read back without an identifier: %v", tronquer(fmt.Sprint(existante), 200))
		}
		if _, err := clientJMAP().Set(ctx, "x:MtaRoute/set", jmap.Modification{
			MettreAJour: map[string]map[string]any{id: e.champsRouteMiseAJour()},
		}); err != nil {
			return fmt.Errorf("updating the relay route: %w", err)
		}
	}

	relue, err := routeParNom(ctx, routeRelais)
	if err != nil {
		return err
	}
	if relue == nil {
		return fmt.Errorf("the relay route is absent after it was written")
	}
	return verifierRoute(relue, e)
}

// verifierRoute compares the fields a read-back can show with what was asked.
//
// The password is NOT part of the comparison: Stalwart never returns it. Its
// presence is checked by its type, which is all the server gives away.
func verifierRoute(route map[string]any, e Envoi) error {
	attendu := map[string]any{
		"host":         e.Hote,
		"protocol":     "smtp",
		"implicitTls":  e.Port == 465,
		"authUsername": e.Utilisateur,
	}
	for champ, vouloir := range attendu {
		if route[champ] != vouloir {
			return fmt.Errorf("the relay route reads back %s=%v, expected %v", champ, route[champ], vouloir)
		}
	}
	if port, ok := route["port"].(float64); !ok || int(port) != e.Port {
		return fmt.Errorf("the relay route reads back port=%v, expected %d", route["port"], e.Port)
	}
	if secret, ok := route["authSecret"].(map[string]any); ok {
		if secret["@type"] != "Value" {
			return fmt.Errorf("the relay route reads back an unexpected authSecret: %v", tronquer(fmt.Sprint(secret), 120))
		}
	}
	return nil
}

// supprimerRouteRelais deletes the `relay` route when it exists, and proves its
// absence by reading back.
//
// THE `notDestroyed` ANSWER IS NOT AN ERROR HERE, and that is not tolerance for
// its own sake: 1.0.3 returns it for objects that are gone, so failing on it
// would leave `direct` mode crashing on an installation where the deletion
// succeeded. The absence is verified below instead.
func supprimerRouteRelais(ctx context.Context) error {
	existante, err := routeParNom(ctx, routeRelais)
	if err != nil {
		return err
	}
	if existante == nil {
		return nil
	}
	id, _ := existante["id"].(string)
	if id == "" {
		return fmt.Errorf("relay route read back without an identifier: %v", tronquer(fmt.Sprint(existante), 200))
	}
	if _, _, err := appelJMAPBrut(ctx, "x:MtaRoute/set", map[string]any{
		"destroy": []any{id},
	}); err != nil {
		return fmt.Errorf("deleting the relay route: %w", err)
	}
	relue, err := routeParNom(ctx, routeRelais)
	if err != nil {
		return err
	}
	if relue != nil {
		return fmt.Errorf("the relay route is still present after its deletion")
	}
	return nil
}

// routeSortanteAttendue builds the outbound strategy's `route` expression.
//
// THE EXISTING `match` IS KEPT: local delivery must keep going to the `local`
// route whether the outside world is reached directly or through a relay.
// Overwriting the whole expression would break local mail — the one thing that
// works without any relay at all.
func routeSortanteAttendue(courante map[string]any, nomRoute string) map[string]any {
	route := map[string]any{}
	for cle, v := range courante {
		route[cle] = v
	}
	route["else"] = "'" + nomRoute + "'"
	if _, ok := route["match"]; !ok {
		route["match"] = map[string]any{
			"0": map[string]any{
				"if":   "is_local_domain(rcpt_domain)",
				"then": "'local'",
			},
		}
	}
	return route
}

// lireRouteSortante returns the outbound strategy's `route` expression.
func lireRouteSortante(ctx context.Context) (map[string]any, error) {
	strategies, err := clientJMAP().Get(ctx, "x:MtaOutboundStrategy/get", []string{"singleton"}, nil)
	if err != nil {
		return nil, err
	}
	if len(strategies) == 0 {
		return nil, fmt.Errorf("the outbound strategy is absent from the server")
	}
	route, ok := strategies[0]["route"].(map[string]any)
	if !ok {
		return map[string]any{}, nil
	}
	return route, nil
}

// forcerSortie points the outbound strategy's `else` branch at a route, and
// reads it back.
func forcerSortie(ctx context.Context, nomRoute string) error {
	courante, err := lireRouteSortante(ctx)
	if err != nil {
		return err
	}
	voulue := routeSortanteAttendue(courante, nomRoute)

	// Nothing to write when it is already in place: this is what makes a
	// redeploy with unchanged settings leave the configuration alone.
	if reflect.DeepEqual(courante, voulue) {
		return nil
	}

	if _, err := clientJMAP().Set(ctx, "x:MtaOutboundStrategy/set", jmap.Modification{
		MettreAJour: map[string]map[string]any{
			"singleton": {"route": voulue},
		},
	}); err != nil {
		return fmt.Errorf("pointing outgoing mail at route %q: %w", nomRoute, err)
	}

	relue, err := lireRouteSortante(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(relue, voulue) {
		return fmt.Errorf("the outbound strategy reads back %v, expected %v",
			tronquer(fmt.Sprint(relue), 200), tronquer(fmt.Sprint(voulue), 200))
	}
	return nil
}
