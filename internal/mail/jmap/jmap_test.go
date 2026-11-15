// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Tests of the JMAP client against a real HTTP server.
//
// WHY THEY EXIST: the client exists to move the mail package OFF `kubectl`, and
// the part that changes shape is the transport — not the payloads, which are
// measured against the live server (§9.I of docs/plan-mail.md). These tests fix
// both halves: an `httptest` server receives the exact envelope the pod would
// receive, and the refusals Stalwart reports in the BODY become typed errors
// instead of passing for a success.
package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveurJPMA starts an HTTP server that answers every /jmap POST with the
// given method response, and returns a client wired to it through
// TransportFunc-like code: the test never builds a body by hand for the
// response, the handler does.
type serveurJMAP struct {
	t          *testing.T
	derniere   map[string]any // the last request body decoded
	capacites  []string       // the last `using` list, verbatim
	appels     int
	nomReponse string // response name, when it differs from the method (an "error")
	repondre   func(methode string, args map[string]any) any
	status     int
	transport  Transport
}

func nouveauServeur(t *testing.T, repondre func(methode string, args map[string]any) any) *serveurJMAP {
	t.Helper()
	s := &serveurJMAP{t: t, repondre: repondre, status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jmap" {
			s.t.Errorf("request path = %q, want /jmap", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			s.t.Errorf("request method = %s, want POST", r.Method)
		}
		var enveloppe struct {
			Using       []string          `json:"using"`
			MethodCalls []json.RawMessage `json:"methodCalls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&enveloppe); err != nil {
			s.t.Errorf("the request body is not the JMAP envelope: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.appels++
		s.capacites = enveloppe.Using
		var couple []json.RawMessage
		if err := json.Unmarshal(enveloppe.MethodCalls[0], &couple); err != nil || len(couple) != 3 {
			s.t.Errorf("methodCall = %s, want [method, args, callId]", enveloppe.MethodCalls[0])
			http.Error(w, "bad methodCall", http.StatusBadRequest)
			return
		}
		var methode, idAppel string
		args := map[string]any{}
		_ = json.Unmarshal(couple[0], &methode)
		_ = json.Unmarshal(couple[1], &args)
		_ = json.Unmarshal(couple[2], &idAppel)
		s.derniere = args

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"methodResponses": []any{[]any{s.nomReponseOu(methode), s.repondre(methode, args), idAppel}},
		})
	}))
	t.Cleanup(srv.Close)

	s.transport = Func(func(ctx context.Context, corps []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/jmap", strings.NewReader(string(corps)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var reponse json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&reponse); err != nil {
			return nil, err
		}
		return reponse, nil
	})
	return s
}

// nomReponseOu returns the response name: the method's own, except for a
// top-level refusal, which JMAP answers as "error".
func (s *serveurJMAP) nomReponseOu(methode string) string {
	if s.nomReponse != "" {
		return s.nomReponse
	}
	return methode
}

// client builds the client under test.
func (s *serveurJMAP) client() *Client { return Nouveau(s.transport, "d333333") }

// TestGetReturnsTheListAndSendsTheAccount: one `get` through a real HTTP
// server returns the parsed list, and the envelope carries the account the
// client was built for — the field whose absence answers `accountNotFound`.
func TestGetReturnsTheListAndSendsTheAccount(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any {
		return map[string]any{"list": []any{
			map[string]any{"id": "r-local", "name": "local"},
			map[string]any{"id": "r-mx", "name": "mx"},
		}}
	})
	objets, err := s.client().Get(context.Background(), "x:MtaRoute/get", nil, []string{"id", "name"})
	if err != nil {
		t.Fatalf("Get() = %v", err)
	}
	if len(objets) != 2 || objets[0]["id"] != "r-local" || objets[1]["name"] != "mx" {
		t.Fatalf("Get() = %v, want the two routes in order", objets)
	}
	if s.derniere["accountId"] != "d333333" {
		t.Errorf("accountId = %v, want the client's account", s.derniere["accountId"])
	}
	if ids, present := s.derniere["ids"]; !present || ids != nil {
		t.Errorf("ids = %v (present %v), want a nil list meaning \"all objects\"", ids, present)
	}
	proprietes, _ := s.derniere["properties"].([]any)
	if len(proprietes) != 2 || proprietes[0] != "id" || proprietes[1] != "name" {
		t.Errorf("properties = %v, want [id name]", s.derniere["properties"])
	}
}

// TestSetReturnsTheCreatedIdentifiers: a creation is usable afterwards only if
// the server's id comes back — the next step attaches the object by id, and
// re-reading the type to find it would race with another writer.
func TestSetReturnsTheCreatedIdentifiers(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any {
		return map[string]any{"created": map[string]any{
			"n1": map[string]any{"id": "a-42"},
		}}
	})
	crees, err := s.client().Set(context.Background(), "x:Account/set", Modification{
		Creer: map[string]map[string]any{"n1": {"@type": "User", "name": "adminceffio"}},
	})
	if err != nil {
		t.Fatalf("Set() = %v", err)
	}
	if crees["n1"] != "a-42" {
		t.Fatalf("created = %v, want n1 → a-42", crees)
	}
	corps, _ := s.derniere["create"].(map[string]any)
	obj, _ := corps["n1"].(map[string]any)
	if obj["name"] != "adminceffio" {
		t.Errorf("create payload = %v, the object was altered on the way", s.derniere["create"])
	}
	if _, present := s.derniere["update"]; present {
		t.Errorf("update present in a creation-only set: %v", s.derniere)
	}
}

// TestSetUpdatesAndDestroysByID: the two other halves of a `set` keep JMAP's
// shape — update keyed by id, destroy a list of ids.
func TestSetUpdatesAndDestroysByID(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any { return map[string]any{} })
	_, err := s.client().Set(context.Background(), "x:Authentication/set", Modification{
		MettreAJour: map[string]map[string]any{
			"singleton": {"defaultAdminRoleIds": map[string]any{"b": true}},
		},
		Detruire: []string{"old-1"},
	})
	if err != nil {
		t.Fatalf("Set() = %v", err)
	}
	maj, _ := s.derniere["update"].(map[string]any)
	singleton, _ := maj["singleton"].(map[string]any)
	if _, ok := singleton["defaultAdminRoleIds"]; !ok {
		t.Errorf("update = %v, the fields were lost", s.derniere["update"])
	}
	detruits, _ := s.derniere["destroy"].([]any)
	if len(detruits) != 1 || detruits[0] != "old-1" {
		t.Errorf("destroy = %v, want [old-1]", s.derniere["destroy"])
	}
}

// TestQueryReturnsTheIDs: the filter travels in `filter`, and the answer's
// `ids` are the identifiers — not the full objects.
func TestQueryReturnsTheIDs(t *testing.T) {
	s := nouveauServeur(t, func(_ string, args map[string]any) any {
		filtre, _ := args["filter"].(map[string]any)
		if filtre["name"] != "relay" {
			t.Errorf("filter = %v, want {name: relay}", args["filter"])
		}
		return map[string]any{"ids": []any{"jkewme12adqb"}}
	})
	ids, err := s.client().Query(context.Background(), "x:MtaRoute/query", map[string]any{"name": "relay"})
	if err != nil {
		t.Fatalf("Query() = %v", err)
	}
	if len(ids) != 1 || ids[0] != "jkewme12adqb" {
		t.Fatalf("Query() = %v, want [jkewme12adqb]", ids)
	}
}

// TestRefusalBecomesATypedError covers the three per-object refusals and the
// top-level error: each is reported in the BODY, and each must reach the caller
// as a Refus of its own genre — never as a silent success.
func TestRefusalBecomesATypedError(t *testing.T) {
	cas := []struct {
		nom    string
		corps  map[string]any
		genre  Genre
		detail string
	}{
		{"error", map[string]any{"type": "unknownMethod"}, Erreur, "unknownMethod"},
		{"notCreated", map[string]any{"notCreated": map[string]any{"n1": map[string]any{"type": "invalidProperties"}}}, NonCree, "invalidProperties"},
		{"notUpdated", map[string]any{"notUpdated": map[string]any{"a-1": map[string]any{"type": "notFound"}}}, NonModifie, "notFound"},
		{"notDestroyed", map[string]any{"notDestroyed": map[string]any{"a-1": map[string]any{"type": "notFound"}}}, NonDetruit, "notFound"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			s := nouveauServeur(t, func(string, map[string]any) any { return c.corps })
			if c.genre == Erreur {
				s.nomReponse = "error"
			}
			_, err := s.client().Appel(context.Background(), "x:MtaRoute/set", map[string]any{})
			if err == nil {
				t.Fatalf("Appel() accepted %v as a success", c.corps)
			}
			if !EstRefus(err, c.genre) {
				t.Fatalf("Appel() = %v, want a %q refusal", err, c.genre)
			}
			var refus *Refus
			if !errors.As(err, &refus) {
				t.Fatalf("the error is not a *Refus: %T", err)
			}
			if refus.Methode != "x:MtaRoute/set" {
				t.Errorf("Refus.Methode = %q, want the refused method", refus.Methode)
			}
			if !strings.Contains(refus.Detail, c.detail) {
				t.Errorf("Refus.Detail = %q, want it to carry %q", refus.Detail, c.detail)
			}
		})
	}
}

// TestAppelBrutDoesNotJudgeTheQuirk: 1.0.3 answers `notDestroyed` for a route
// that is gone (measured, §9.I). The raw form therefore returns the body
// without an error, which is what lets deletion decide on the read-back
// instead of on a response that lies.
// TestLesMethodesDeMessagerieDemandentLeurCapacite : JMAP declares capabilities
// PER REQUEST, so the `using` list cannot be a constant. The management calls
// (`x:`) answer an empty list on Stalwart 1.0.3; the RFC 8621 ones refuse without
// `urn:ietf:params:jmap:mail` (`unknownMethod`, "requires capability … which is
// not present in the \"using\" property"), measured on the live demo,
// 2026-11-14, after the method names had already been fixed.
func TestLesMethodesDeMessagerieDemandentLeurCapacite(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any {
		return map[string]any{"list": []any{}}
	})

	if _, err := s.client().Appel(context.Background(), "Mailbox/get", map[string]any{}); err != nil {
		t.Fatalf("Mailbox/get: %v", err)
	}
	for _, capacite := range []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"} {
		if !contient(s.capacites, capacite) {
			t.Fatalf("Mailbox/get declares %v, want %s in it", s.capacites, capacite)
		}
	}

	if _, err := s.client().Appel(context.Background(), "x:Account/get", map[string]any{}); err != nil {
		t.Fatalf("x:Account/get: %v", err)
	}
	if len(s.capacites) != 0 {
		t.Fatalf("a management call declares %v, want no capability", s.capacites)
	}
}

func contient(liste []string, valeur string) bool {
	for _, v := range liste {
		if v == valeur {
			return true
		}
	}
	return false
}

func TestAppelBrutDoesNotJudgeTheQuirk(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any {
		return map[string]any{"notDestroyed": map[string]any{}}
	})
	nom, corps, err := s.client().AppelBrut(context.Background(), "x:MtaRoute/set",
		map[string]any{"destroy": []string{"gone"}})
	if err != nil {
		t.Fatalf("AppelBrut() = %v, the raw form must not judge the refusal", err)
	}
	if nom != "x:MtaRoute/set" {
		t.Errorf("method = %q, want the called method", nom)
	}
	if _, present := corps["notDestroyed"]; !present {
		t.Errorf("body = %v, the refusal detail must reach the caller", corps)
	}
}

// TestAccountIDIsNotOverwritten: a caller that names another account keeps it.
// The management account is the default, not an imposition.
func TestAccountIDIsNotOverwritten(t *testing.T) {
	s := nouveauServeur(t, func(string, map[string]any) any { return map[string]any{"list": []any{}} })
	if _, err := s.client().Get(context.Background(), "x:Domain/get", nil, nil); err != nil {
		t.Fatalf("Get() = %v", err)
	}
	_, err := s.client().Appel(context.Background(), "x:Domain/get", map[string]any{"accountId": "other"})
	if err != nil {
		t.Fatalf("Appel() = %v", err)
	}
	if s.derniere["accountId"] != "other" {
		t.Errorf("accountId = %v, want the caller's account", s.derniere["accountId"])
	}
}

// TestTransportFailureIsReportedWithTheMethod: an unreachable pod is a
// transport failure, and the message must name the call — otherwise an operator
// sees a bare exec error and cannot tell which step failed.
func TestTransportFailureIsReportedWithTheMethod(t *testing.T) {
	client := Nouveau(Func(func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("no running pod")
	}), "d333333")
	_, err := client.Appel(context.Background(), "x:Role/get", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "x:Role/get") || !strings.Contains(err.Error(), "no running pod") {
		t.Fatalf("Appel() = %v, want the method and the transport failure", err)
	}
}

// TestEmptyMethodResponsesIsAnError: an empty envelope is not "no object" — it
// is a server that did not answer the call, and treating it as an empty list
// would make a missing directory look like a fresh installation.
func TestEmptyMethodResponsesIsAnError(t *testing.T) {
	client := Nouveau(Func(func(context.Context, []byte) ([]byte, error) {
		return []byte(`{"methodResponses":[]}`), nil
	}), "d333333")
	if _, err := client.Appel(context.Background(), "x:Directory/get", map[string]any{}); err == nil {
		t.Fatal("Appel() accepted an empty methodResponses list")
	}
}
