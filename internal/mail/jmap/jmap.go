// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package jmap is a minimal JMAP client for Stalwart's management API.
//
// WHY IT EXISTS: the mail package used to speak JMAP through a `kubectl exec`
// and parse the answer by hand, five times over — once per helper. That worked
// from the CLI, where a `kubectl` binary exists, and it could not work from the
// console, whose image is built `FROM scratch`: no shell, no kubectl. The
// transport is now a seam, so the same calls run inside the cluster.
//
// WHAT IS NOT NEGOTIABLE: Stalwart reports its refusals IN THE RESPONSE BODY,
// not through an HTTP status. A caller that only looks at the transport would
// take a refused write for a success — that is how the routing stayed absent
// while `Deploy` printed no error. Every refusal therefore becomes a *Refus,
// and the one caller that must judge on a read-back (route deletion, where
// 1.0.3 answers `notDestroyed` for an object that is gone) asks for the raw
// form explicitly.
//
// THE ENVELOPE IS `{"using":[…],"methodCalls":[[method,args,"c1"]]}`, AND THE
// LIST DEPENDS ON THE METHOD:
//
//   - management calls (`x:…`) get an EMPTY list. Stalwart 1.0.3 answers them,
//     and requesting `urn:ietf:params:jmap:core` is not needed (verified on the
//     live server: a bare `using` list returns the full `x:Account/get` list
//     instead of an `unknownCapability` error).
//   - RFC 8621 methods (`Mailbox/get`, `Email/query`, `Email/get`) get their
//     capabilities. Without them Stalwart refuses with `unknownMethod` and the
//     body says why ("requires capability urn:ietf:params:jmap:mail which is not
//     present in the \"using\" property") — measured on the live demo,
//     2026-11-14, after the method names had been fixed and the check still
//     failed for a different reason.
package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Transport performs ONE JMAP exchange: it receives the complete request body
// and returns the complete response body.
//
// THE TRUNCATED SIGNATURE IS DELIBERATE: a JMAP request is one POST to /jmap,
// and nothing above this layer may need to know whether that POST goes through
// an exec into a pod, an in-cluster HTTP client, or an `httptest` server. That
// is the whole point of the seam.
type Transport interface {
	Do(ctx context.Context, corps []byte) ([]byte, error)
}

// Func adapts a plain function to Transport. It exists so production code and
// tests can both write a transport without declaring a type: the mail package
// keeps its `transportJMAP` variable, and the tests keep using it.
type Func func(ctx context.Context, corps []byte) ([]byte, error)

// Do implements Transport.
func (f Func) Do(ctx context.Context, corps []byte) ([]byte, error) { return f(ctx, corps) }

// Genre classifies a refusal reported by the server.
type Genre string

// The four refusals the management API reports. `Erreur` is the top-level
// `"error"` response (a malformed call, an unknown method); the three others
// are the per-object maps a `set` call returns when it refused part of a write.
//
// WHY THREE AND NOT ONE: an operator reading "the write failed" cannot tell a
// permission problem (`error`) from a wrong payload (`notCreated`) from an
// object that vanished between the read and the write (`notUpdated`). Each has
// a different fix, so each keeps its own name.
const (
	Erreur     Genre = "error"
	NonCree    Genre = "notCreated"
	NonModifie Genre = "notUpdated"
	NonDetruit Genre = "notDestroyed"
)

// Refus is a refusal reported in a JMAP response body.
type Refus struct {
	Methode string // the JMAP method that was refused
	Genre   Genre  // which refusal it is
	Detail  string // the server's own detail, truncated for a log line
}

// Error implements error. The wording keeps the one the mail package used
// before the client existed, so a log line stays recognisable.
func (r *Refus) Error() string {
	if r.Genre == Erreur {
		return fmt.Sprintf("Stalwart refusal: %s", r.Detail)
	}
	return fmt.Sprintf("Stalwart refused (%s): %s", r.Genre, r.Detail)
}

// EstRefus reports whether err is a JMAP refusal of that genre.
//
// WHY NOT COMPARE ERRORS DIRECTLY: the caller needs `errors.As` to reach the
// Refus (the transport may wrap it), and repeating that type assertion at every
// call site is how one of them ends up checking the wrong genre.
func EstRefus(err error, genre Genre) bool {
	var r *Refus
	return errors.As(err, &r) && r.Genre == genre
}

// Client speaks to one Stalwart account.
//
// The account is part of the client because every call of the management API
// carries it, and forgetting it at one call site produces a valid-looking
// request that answers `accountNotFound` — which reads like a version problem.
type Client struct {
	transport Transport
	compte    string
}

// Nouveau builds a client for an account (for Stalwart's management account,
// see the caller).
func Nouveau(t Transport, compte string) *Client {
	return &Client{transport: t, compte: compte}
}

// AppelBrut sends one method call and returns its name and body WITHOUT
// interpreting the refusals.
//
// RESERVED FOR THE READ-BACK CALLERS: `appelJMAP` below is the default, and it
// turns every refusal into an error. Route deletion is the documented exception
// (§9.I of docs/plan-mail.md): 1.0.3 answers `notDestroyed` for an object that
// is gone, so treating that body as a failure would make direct mode
// undeployable on an installation whose relay route was already deleted. The
// caller of the brut form decides — and it decides on the read-back.
func (c *Client) AppelBrut(ctx context.Context, methode string, args map[string]any) (string, map[string]any, error) {
	enveloppe := map[string]any{
		"using":       capacites(methode),
		"methodCalls": []any{[]any{methode, c.avecCompte(args), "c1"}},
	}
	brut, err := json.Marshal(enveloppe)
	if err != nil {
		return "", nil, err
	}
	sortie, err := c.transport.Do(ctx, brut)
	if err != nil {
		return "", nil, fmt.Errorf("JMAP call %s: %w", methode, err)
	}

	var reponse struct {
		MethodResponses []json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(sortie, &reponse); err != nil {
		return "", nil, fmt.Errorf("unreadable JMAP response (%s): %w", tronquer(string(sortie), 200), err)
	}
	if len(reponse.MethodResponses) == 0 {
		return "", nil, fmt.Errorf("empty JMAP response: %s", tronquer(string(sortie), 200))
	}
	var couple []json.RawMessage
	if err := json.Unmarshal(reponse.MethodResponses[0], &couple); err != nil || len(couple) < 2 {
		return "", nil, fmt.Errorf("unexpected JMAP response: %s", tronquer(string(sortie), 200))
	}
	var nom string
	_ = json.Unmarshal(couple[0], &nom)
	var corps map[string]any
	if err := json.Unmarshal(couple[1], &corps); err != nil {
		return "", nil, fmt.Errorf("unreadable JMAP body: %w", err)
	}
	return nom, corps, nil
}

// capacites returns the JMAP capabilities one method needs.
//
// THE NAMESPACE DECIDES, and the split is not cosmetic: the `x:` methods are
// Stalwart's own management API, the others are RFC 8621 mail data. Capabilities
// are declared per request in JMAP, so a single envelope cannot serve both.
func capacites(methode string) []string {
	if strings.HasPrefix(methode, "x:") {
		return []string{}
	}
	return []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"}
}

// Appel sends one method call and turns every refusal into a *Refus.
func (c *Client) Appel(ctx context.Context, methode string, args map[string]any) (map[string]any, error) {
	nom, corps, err := c.AppelBrut(ctx, methode, args)
	if err != nil {
		return nil, err
	}
	if nom == "error" {
		return nil, &Refus{Methode: methode, Genre: Erreur, Detail: detailler(corps)}
	}
	for _, genre := range []Genre{NonCree, NonModifie, NonDetruit} {
		if v, ok := corps[string(genre)]; ok {
			return nil, &Refus{Methode: methode, Genre: genre, Detail: detailler(v)}
		}
	}
	return corps, nil
}

// Get returns the objects of a type, optionally restricted to some ids.
//
// A NIL `ids` MEANS ALL OBJECTS: JMAP distinguishes `"ids": null` (everything)
// from an omitted list, and the caller asking for a by-name lookup relies on
// the first.
func (c *Client) Get(ctx context.Context, methode string, ids []string, proprietes []string) ([]map[string]any, error) {
	args := map[string]any{"ids": ids}
	if len(proprietes) > 0 {
		args["properties"] = proprietes
	}
	corps, err := c.Appel(ctx, methode, args)
	if err != nil {
		return nil, err
	}
	liste, _ := corps["list"].([]any)
	objets := make([]map[string]any, 0, len(liste))
	for _, e := range liste {
		if m, ok := e.(map[string]any); ok {
			objets = append(objets, m)
		}
	}
	return objets, nil
}

// Query returns the ids of the objects matching a filter.
func (c *Client) Query(ctx context.Context, methode string, filtre map[string]any) ([]string, error) {
	args := map[string]any{}
	if filtre != nil {
		args["filter"] = filtre
	}
	corps, err := c.Appel(ctx, methode, args)
	if err != nil {
		return nil, err
	}
	liste, _ := corps["ids"].([]any)
	ids := make([]string, 0, len(liste))
	for _, e := range liste {
		if id, ok := e.(string); ok {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Modification is the payload of a `set` call: what to create, to update and
// to destroy, in one request.
//
// ONE STRUCTURE RATHER THAN THREE METHODS, because that is JMAP's shape: a
// single `set` can do all three, and splitting it would have made a caller
// send three round trips for an operation the server defines as atomic.
type Modification struct {
	Creer       map[string]map[string]any // client key → object
	MettreAJour map[string]map[string]any // id → changed fields
	Detruire    []string                  // ids
}

// Set applies a modification and returns the identifiers the server created,
// keyed by the client key of the creation.
//
// THE CREATED ID IS RETURNED, NOT GUESSED: an object created without its id is
// unusable for the next step (attach this domain to that directory), and
// re-reading the whole type to find it would race with another writer.
func (c *Client) Set(ctx context.Context, methode string, m Modification) (map[string]string, error) {
	args := map[string]any{}
	if len(m.Creer) > 0 {
		args["create"] = m.Creer
	}
	if len(m.MettreAJour) > 0 {
		args["update"] = m.MettreAJour
	}
	if len(m.Detruire) > 0 {
		args["destroy"] = m.Detruire
	}
	corps, err := c.Appel(ctx, methode, args)
	if err != nil {
		return nil, err
	}
	crees := map[string]string{}
	bruts, _ := corps["created"].(map[string]any)
	for cle, v := range bruts {
		if o, ok := v.(map[string]any); ok {
			if id, ok := o["id"].(string); ok {
				crees[cle] = id
			}
		}
	}
	return crees, nil
}

// avecCompte adds the account identifier when the caller did not set it.
//
// SET BY DEFAULT, NOT REQUIRED: every call of the management API carries it,
// and an omitted accountId is answered with `accountNotFound` — an error that
// reads like a wrong account rather than a forgotten field.
func (c *Client) avecCompte(args map[string]any) map[string]any {
	if args == nil {
		args = map[string]any{}
	}
	if _, present := args["accountId"]; !present && c.compte != "" {
		args["accountId"] = c.compte
	}
	return args
}

// detailler renders a refusal payload for an error message.
func detailler(v any) string {
	brut, err := json.Marshal(v)
	if err != nil {
		return tronquer(fmt.Sprint(v), 300)
	}
	return tronquer(string(brut), 300)
}

// tronquer shortens a value for an error message.
func tronquer(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
