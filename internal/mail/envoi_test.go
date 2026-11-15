// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Guards on the outbound routing: what `AppliquerEnvoi` writes, in both modes.
//
// WHY THEY EXIST: `Deploy` printed "the relay is declared in JMAP; to be
// finalized through the admin interface" and wrote nothing — on a residential
// connection outbound port 25 is blocked, so the platform received mail and sent
// none, silently. The routing is now written, and these tests fix what "written"
// means: the exact route payload, the strategy branch, the disappearance of the
// relay route in direct mode, and the read-back that decides success — because a
// `set` response is not a proof, and 1.0.3 even answers `notDestroyed` for
// objects that are gone.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// fauxStalwart is an in-memory JMAP endpoint holding the routes and the outbound
// strategy, shaped exactly like the objects read back on 1.0.3 (docs/plan-mail.md
// §9.I). It answers through the same envelope the real server does, so the code
// under test parses a response rather than a hand-built map.
type fauxStalwart struct {
	routes     map[string]map[string]any // id → route
	strategie  map[string]any            // the `route` expression
	appels     []string                  // method names, in order
	prochainID int
	// apresEcriture runs after a create or an update, so a test can simulate a
	// server that normalizes a field on write.
	apresEcriture func()
}

func nouveauFauxStalwart() *fauxStalwart {
	return &fauxStalwart{
		routes: map[string]map[string]any{
			"r-local": {"@type": "Local", "id": "r-local", "name": "local"},
			"r-mx":    {"@type": "Mx", "id": "r-mx", "name": "mx"},
		},
		strategie: map[string]any{
			"match": map[string]any{
				"0": map[string]any{"if": "is_local_domain(rcpt_domain)", "then": "'local'"},
			},
			"else": "'mx'",
		},
		prochainID: 100,
	}
}

// avecRelais places the fake in the state an installation with a relay is in.
func (f *fauxStalwart) avecRelais() {
	f.routes["r-relay"] = map[string]any{
		"@type": "Relay", "id": "r-relay", "name": routeRelais,
		"host": "old.example.com", "port": float64(587), "protocol": "smtp",
		"implicitTls": false, "authUsername": "ancien",
		"authSecret": map[string]any{"@type": "Value"},
	}
	f.strategie["else"] = "'" + routeRelais + "'"
}

func (f *fauxStalwart) transport(_ context.Context, corps []byte) ([]byte, error) {
	var enveloppe struct {
		MethodCalls []json.RawMessage `json:"methodCalls"`
	}
	if err := json.Unmarshal(corps, &enveloppe); err != nil {
		return nil, err
	}
	var appel []json.RawMessage
	if err := json.Unmarshal(enveloppe.MethodCalls[0], &appel); err != nil {
		return nil, err
	}
	var methode string
	_ = json.Unmarshal(appel[0], &methode)
	args := map[string]any{}
	_ = json.Unmarshal(appel[1], &args)
	f.appels = append(f.appels, methode)

	reponse, err := f.repondre(methode, args)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"methodResponses": []any{[]any{methode, reponse, "c1"}},
	})
}

func (f *fauxStalwart) repondre(methode string, args map[string]any) (map[string]any, error) {
	switch methode {
	case "x:MtaRoute/get":
		liste := make([]any, 0, len(f.routes))
		for _, route := range f.routes {
			liste = append(liste, route)
		}
		return map[string]any{"list": liste}, nil

	case "x:MtaRoute/set":
		if cree, ok := args["create"].(map[string]any); ok {
			for nom, brut := range cree {
				route, ok := brut.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("create payload is not an object: %T", brut)
				}
				f.prochainID++
				id := fmt.Sprintf("r-%d", f.prochainID)
				route["id"] = id
				route["name"] = nom
				f.routes[id] = route
			}
		}
		if maj, ok := args["update"].(map[string]any); ok {
			for id, brut := range maj {
				route, present := f.routes[id]
				if !present {
					return map[string]any{
						"notUpdated": map[string]any{id: map[string]any{"type": "notFound"}},
					}, nil
				}
				champs, ok := brut.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("update payload is not an object: %T", brut)
				}
				for champ, valeur := range champs {
					route[champ] = valeur
				}
			}
		}
		if detruits, ok := args["destroy"].([]any); ok {
			for _, id := range detruits {
				delete(f.routes, fmt.Sprint(id))
			}
			// THE 1.0.3 QUIRK, reproduced: destroy answers notDestroyed for an
			// object that is gone. Direct mode must not fail on it.
			return map[string]any{"notDestroyed": map[string]any{}}, nil
		}
		if f.apresEcriture != nil {
			f.apresEcriture()
		}
		return map[string]any{}, nil

	case "x:MtaOutboundStrategy/get":
		return map[string]any{"list": []any{
			map[string]any{"id": "singleton", "route": f.strategie},
		}}, nil

	case "x:MtaOutboundStrategy/set":
		if maj, ok := args["update"].(map[string]any); ok {
			if singleton, ok := maj["singleton"].(map[string]any); ok {
				if route, ok := singleton["route"].(map[string]any); ok {
					f.strategie = route
				}
			}
		}
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("unexpected JMAP method: %s", methode)
}

// route returns the route with that name, nil when absent.
func (f *fauxStalwart) route(nom string) map[string]any {
	for _, route := range f.routes {
		if route["name"] == nom {
			return route
		}
	}
	return nil
}

// installerFaux makes the fake the transport for the duration of one test.
func installerFaux(t *testing.T, f *fauxStalwart) {
	t.Helper()
	ancien := transportJMAP
	transportJMAP = f.transport
	t.Cleanup(func() { transportJMAP = ancien })
}

// TestAppliquerEnvoiRelaisEcritLaRoute: relais mode creates a route carrying the
// credential, and points the strategy's `else` branch at it — the two writes
// that used to be missing.
func TestAppliquerEnvoiRelaisEcritLaRoute(t *testing.T) {
	f := nouveauFauxStalwart()
	installerFaux(t, f)

	e := Envoi{Mode: ModeRelais, Hote: "smtp.example.com", Port: 587,
		Utilisateur: "ceffio", MotDePasse: "secret"}
	if err := AppliquerEnvoi(context.Background(), e); err != nil {
		t.Fatalf("AppliquerEnvoi (relais) = %v", err)
	}

	route := f.route(routeRelais)
	if route == nil {
		t.Fatal("the relay route was not created")
	}
	attendu := map[string]any{
		"host":              "smtp.example.com",
		"port":              float64(587),
		"protocol":          "smtp",
		"implicitTls":       false,
		"allowInvalidCerts": false,
		"authUsername":      "ceffio",
	}
	for champ, vouloir := range attendu {
		if route[champ] != vouloir {
			t.Errorf("route[%s] = %v, want %v", champ, route[champ], vouloir)
		}
	}
	secret, ok := route["authSecret"].(map[string]any)
	if !ok || secret["@type"] != "Value" || secret["secret"] != "secret" {
		t.Errorf("route authSecret = %v, want a Value carrying the password", route["authSecret"])
	}
	if f.strategie["else"] != "'"+routeRelais+"'" {
		t.Errorf("strategy else = %v, want 'relay'", f.strategie["else"])
	}
	// Local delivery must keep going to the local route: overwriting `match`
	// would break the one thing that works without a relay.
	if fmt.Sprint(f.strategie["match"]) == "" {
		t.Error("the strategy lost its match expression")
	}
}

// TestAppliquerEnvoiRelaisReecritLaRoute: a second call with the same visible
// values updates the existing route instead of creating a second one, and it
// does write — the password is never returned by a read, so a rotated credential
// could not be detected any other way.
func TestAppliquerEnvoiRelaisReecritLaRoute(t *testing.T) {
	f := nouveauFauxStalwart()
	f.avecRelais()
	installerFaux(t, f)
	avant := len(f.routes)

	e := Envoi{Mode: ModeRelais, Hote: "smtp.example.com", Port: 465,
		Utilisateur: "ceffio", MotDePasse: "nouveau"}
	if err := AppliquerEnvoi(context.Background(), e); err != nil {
		t.Fatalf("AppliquerEnvoi (relais) = %v", err)
	}

	if len(f.routes) != avant {
		t.Errorf("the route count went from %d to %d: the existing route must be updated, not duplicated",
			avant, len(f.routes))
	}
	route := f.route(routeRelais)
	if route == nil {
		t.Fatal("the relay route disappeared")
	}
	if route["id"] != "r-relay" {
		t.Errorf("route id = %v, want the existing r-relay", route["id"])
	}
	if route["host"] != "smtp.example.com" {
		t.Errorf("route host = %v, want the new host", route["host"])
	}
	// 465 is implicit TLS (SMTPS): the port decides it, and getting it wrong
	// produces a connection that hangs instead of an error.
	if route["implicitTls"] != true {
		t.Errorf("route implicitTls = %v, want true for port 465", route["implicitTls"])
	}
	// The fields Stalwart treats as read-only after creation are not resent.
	if _, present := route["@type"]; present && route["@type"] != "Relay" {
		t.Errorf("route @type = %v", route["@type"])
	}
}

// TestAppliquerEnvoiDirectSupprimeLaRoute: direct mode points the strategy back
// at `mx` and deletes the relay route, in that order, and the deletion's
// `notDestroyed` answer is not an error.
func TestAppliquerEnvoiDirectSupprimeLaRoute(t *testing.T) {
	f := nouveauFauxStalwart()
	f.avecRelais()
	installerFaux(t, f)

	if err := AppliquerEnvoi(context.Background(), Envoi{Mode: ModeDirect}); err != nil {
		t.Fatalf("AppliquerEnvoi (direct) = %v", err)
	}

	if route := f.route(routeRelais); route != nil {
		t.Errorf("the relay route is still present after switching to direct: %v", route)
	}
	if f.strategie["else"] != "'"+routeMx+"'" {
		t.Errorf("strategy else = %v, want 'mx'", f.strategie["else"])
	}
}

// TestAppliquerEnvoiDirectNECRIT RIEN: on an installation that is already
// direct, a redeploy leaves the configuration untouched — no write, two reads.
func TestAppliquerEnvoiDirectIdempotent(t *testing.T) {
	f := nouveauFauxStalwart()
	installerFaux(t, f)

	if err := AppliquerEnvoi(context.Background(), Envoi{Mode: ModeDirect}); err != nil {
		t.Fatalf("AppliquerEnvoi (direct) = %v", err)
	}

	for _, methode := range f.appels {
		if strings.HasSuffix(methode, "/set") {
			t.Errorf("an unchanged direct installation was written to: %s (calls %v)", methode, f.appels)
		}
	}
}

// TestAppliquerEnvoiVerifieLaRelecture: a write that does not read back as
// asked is a failure, not a success — the JMAP `set` response says nothing about
// the result.
func TestAppliquerEnvoiVerifieLaRelecture(t *testing.T) {
	f := nouveauFauxStalwart()
	f.apresEcriture = func() {
		if route := f.route(routeRelais); route != nil {
			route["host"] = "normalise.example.com"
		}
	}
	installerFaux(t, f)

	err := AppliquerEnvoi(context.Background(), Envoi{Mode: ModeRelais,
		Hote: "smtp.example.com", Port: 587, Utilisateur: "ceffio", MotDePasse: "secret"})
	if err == nil {
		t.Fatal("AppliquerEnvoi accepted a route that does not read back as written")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("the error does not name the field that disagrees: %v", err)
	}
}

// TestValiderEnvoiRefuseUnRelaisIncomplet: an incomplete relay is refused before
// anything is written. Stalwart would accept the route and bounce every message
// at delivery time, so the failure would surface on a user.
func TestValiderEnvoiRefuseUnRelaisIncomplet(t *testing.T) {
	cas := map[string]Envoi{
		"sans hôte":         {Mode: ModeRelais, Port: 587, Utilisateur: "u", MotDePasse: "p"},
		"port nul":          {Mode: ModeRelais, Hote: "h", Port: 0, Utilisateur: "u", MotDePasse: "p"},
		"port trop grand":   {Mode: ModeRelais, Hote: "h", Port: 70000, Utilisateur: "u", MotDePasse: "p"},
		"sans compte":       {Mode: ModeRelais, Hote: "h", Port: 587, MotDePasse: "p"},
		"sans mot de passe": {Mode: ModeRelais, Hote: "h", Port: 587, Utilisateur: "u"},
		"mode inconnu":      {Mode: "smtp"},
	}
	for nom, e := range cas {
		if err := e.Valider(); err == nil {
			t.Errorf("%s: Valider() accepted %+v", nom, e)
		}
	}
	if err := (Envoi{Mode: ModeDirect}).Valider(); err != nil {
		t.Errorf("Valider() refused direct mode: %v", err)
	}
}

// TestChampsRouteMiseAJourSansLesChampsFiges: the update payload is the same
// object without `@type` and `name`, which Stalwart treats as read-only after
// creation.
func TestChampsRouteMiseAJourSansLesChampsFiges(t *testing.T) {
	e := Envoi{Mode: ModeRelais, Hote: "h", Port: 465, Utilisateur: "u", MotDePasse: "p"}
	maj := e.champsRouteMiseAJour()
	for _, interdit := range []string{"@type", "name"} {
		if _, present := maj[interdit]; present {
			t.Errorf("%s is present in the update payload", interdit)
		}
	}
	if maj["implicitTls"] != true {
		t.Errorf("implicitTls = %v, want true for port 465", maj["implicitTls"])
	}
	if maj["host"] != "h" || maj["authUsername"] != "u" {
		t.Errorf("the update payload lost its coordinates: %v", maj)
	}
}
