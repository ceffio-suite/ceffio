// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package expos

// WHY THIS IS WORTH A TEST. The port-forward path has one job that no other
// code in this repository can check: NEVER claim a port is open when the
// firewall did not say so. A wrong domain declaration is visible in a browser;
// a wrong port forward is invisible until a sender's queue fills up, days
// later, and the operator looks for the fault in Stalwart. The tests below
// therefore pin three things:
//
//   - the manual rule strings, because they are the contract an operator types
//     into the firewall UI (a wrong one opens the port on the wrong interface);
//   - the fallback: an HTTP error, an HTML page served with 200, a body without
//     uuid must produce the rules and no error, never a success;
//   - idempotence: a second run must not create a duplicate forward, and a
//     search we cannot read must not create blindly.
//
// The fake firewall is an httptest TLS server: the client builds its URL from
// the configured host and skips certificate verification, exactly as it does
// against the real self-signed appliance, so the test exercises the real
// client and the real appel(), not a mock of it.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fauxPareFeu imitates the NAT plugin of the firewall: a search endpoint, an
// add endpoint and an apply endpoint, each with the answer a test needs.
type fauxPareFeu struct {
	mu  sync.Mutex
	srv *httptest.Server

	// regles are the rows returned by the search, written "port:target".
	regles []string
	// corpsRecherche, when set, is returned verbatim by the search: the test
	// uses it to serve an HTML page or a truncated body.
	corpsRecherche string
	// corpsAjout is returned for every add; the zero value answers a uuid.
	corpsAjout string
	// corpsApplique is returned for the apply; the zero value answers ok.
	corpsApplique string
	// statut, when non-zero, forces that HTTP status (with an HTML body) on
	// every endpoint: a 500 from a firewall that is up but broken.
	statut int

	appels []string         // "METHOD /api/path", in arrival order
	ajouts []map[string]any // decoded add bodies, in arrival order
}

func (f *fauxPareFeu) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appels = append(f.appels, r.Method+" "+r.URL.Path)

	if f.statut != 0 {
		w.WriteHeader(f.statut)
		io.WriteString(w, "<html><body>error</body></html>")
		return
	}

	switch r.URL.Path {
	case "/api/" + cheminNATRecherche:
		if f.corpsRecherche != "" {
			io.WriteString(w, f.corpsRecherche)
			return
		}
		rows := []map[string]any{}
		for _, regle := range f.regles {
			port, cible, _ := strings.Cut(regle, ":")
			rows = append(rows, map[string]any{
				"disabled":  "0",
				"interface": "wan",
				"protocol":  "tcp",
				"dstport":   port,
				"target":    cible,
			})
		}
		b, _ := json.Marshal(map[string]any{"rows": rows})
		w.Write(b)

	case "/api/" + cheminNATAjout:
		var corps map[string]any
		if err := json.NewDecoder(r.Body).Decode(&corps); err != nil {
			corps = nil
		}
		f.ajouts = append(f.ajouts, corps)
		if f.corpsAjout == "" {
			io.WriteString(w, `{"uuid":"u-25"}`)
			return
		}
		io.WriteString(w, f.corpsAjout)

	case "/api/" + cheminNATApplique:
		if f.corpsApplique == "" {
			io.WriteString(w, `{"result":"ok"}`)
			return
		}
		io.WriteString(w, f.corpsApplique)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fauxPareFeu) journal() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.appels...)
}

func (f *fauxPareFeu) corpsAjoutes() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.ajouts...)
}

// nbAppels counts the calls to one endpoint path relative to /api/.
func (f *fauxPareFeu) nbAppels(chemin string) int {
	n := 0
	for _, appel := range f.journal() {
		if strings.HasSuffix(appel, " /api/"+chemin) {
			n++
		}
	}
	return n
}

// configTest starts the fake firewall and returns a valid configuration: the
// credentials file exists (the client reads it and refuses short keys), the
// host is the test server, and the target is a documentation address.
func configTest(t *testing.T) (*fauxPareFeu, Config) {
	t.Helper()
	f := &fauxPareFeu{}
	f.srv = httptest.NewTLSServer(f)
	t.Cleanup(f.srv.Close)

	chemin := filepath.Join(t.TempDir(), "apikey.txt")
	contenu := "key=0123456789abcdefghij\nsecret=0123456789abcdefghij\n"
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatalf("writing the credentials file: %v", err)
	}
	return f, Config{
		HoteAPI:     strings.TrimPrefix(f.srv.URL, "https://"),
		FichierCle:  chemin,
		IPInterne:   "10.0.0.5",
		PortInterne: "80",
	}
}

// TestReglesManuelles pins the exact strings an operator types in the firewall
// UI: one NAT rule then one pass rule per port, sorted, deduplicated, and with
// the impossible ports dropped instead of producing a rule that matches nothing.
func TestReglesManuelles(t *testing.T) {
	regles := ReglesManuelles("10.0.0.5", []int{993, 25, 993, 0, -1, 70000, 465})

	attendues := []string{
		"WAN TCP * -> 10.0.0.5:25",
		"pass in on WAN inet proto tcp from any to 10.0.0.5 port 25 keep state",
		"WAN TCP * -> 10.0.0.5:465",
		"pass in on WAN inet proto tcp from any to 10.0.0.5 port 465 keep state",
		"WAN TCP * -> 10.0.0.5:993",
		"pass in on WAN inet proto tcp from any to 10.0.0.5 port 993 keep state",
	}
	if len(regles) != len(attendues) {
		t.Fatalf("%d rules printed, want %d: %v", len(regles), len(attendues), regles)
	}
	for i, attendue := range attendues {
		if regles[i] != attendue {
			t.Errorf("rule %d = %q, want %q", i, regles[i], attendue)
		}
	}

	if regles := ReglesManuelles("10.0.0.5", []int{0, -465, 70000}); len(regles) != 0 {
		t.Errorf("no port is valid, want no rule, got %v", regles)
	}
}

// TestPublierPortsSansPort proves the backward-compatible path: a configuration
// without ports reads no credential file and sends no request, so an
// installation that does not forward any L4 port behaves exactly as before.
func TestPublierPortsSansPort(t *testing.T) {
	f, cfg := configTest(t)
	cfg.FichierCle = filepath.Join(t.TempDir(), "absent.txt")

	var progres []string
	res, err := PublierPorts(context.Background(), cfg, nil, func(e string) {
		progres = append(progres, e)
	})
	if err != nil {
		t.Fatalf("PublierPorts: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if len(res.PortsOuverts) != 0 || len(res.ReglesManuelles) != 0 || len(res.Avertissemts) != 0 {
		t.Errorf("empty port list must produce an empty report, got %+v", res)
	}
	if len(res.Created) != 0 || res.Certificat != "" {
		t.Errorf("port publication must not touch the domain fields, got %+v", res)
	}
	if appels := f.journal(); len(appels) != 0 {
		t.Errorf("no HTTP call expected, got %v", appels)
	}
	if len(progres) != 0 {
		t.Errorf("no progress expected, got %v", progres)
	}
}

// TestPublierPortsCreeLesRedirections is the happy path: the search is empty,
// every add answers a uuid, the apply answers ok — and the result says exactly
// which ports are confirmed, with the payload the firewall must receive.
func TestPublierPortsCreeLesRedirections(t *testing.T) {
	f, cfg := configTest(t)

	res, err := PublierPorts(context.Background(), cfg, []int{993, 25, 465}, nil)
	if err != nil {
		t.Fatalf("PublierPorts: %v", err)
	}
	if res.ReglesManuelles != nil && len(res.ReglesManuelles) != 0 {
		t.Errorf("everything is confirmed, no manual rule expected, got %v", res.ReglesManuelles)
	}
	if len(res.Avertissemts) != 0 {
		t.Errorf("no warning expected, got %v", res.Avertissemts)
	}
	attendus := []int{25, 465, 993}
	if fmt.Sprint(res.PortsOuverts) != fmt.Sprint(attendus) {
		t.Errorf("PortsOuverts = %v, want %v (ascending)", res.PortsOuverts, attendus)
	}
	if len(res.PortsExistants) != 0 {
		t.Errorf("nothing existed, got %v", res.PortsExistants)
	}

	if n := f.nbAppels(cheminNATAjout); n != 3 {
		t.Fatalf("%d add calls, want 3", n)
	}
	if n := f.nbAppels(cheminNATApplique); n != 1 {
		t.Errorf("%d apply calls, want 1 (the running ruleset must be reloaded)", n)
	}
	if n := f.nbAppels(cheminNATRecherche); n != 1 {
		t.Errorf("%d search calls, want 1 (idempotence is read once)", n)
	}

	// The payload is what the firewall plugin will actually receive: the test
	// pins the fields, not a Go struct, because a renamed field would silently
	// create a rule that forwards the wrong port or the wrong target.
	corps := f.corpsAjoutes()
	for i, port := range []int{25, 465, 993} {
		if corps[i] == nil {
			t.Fatalf("add %d: empty body", i)
		}
		regle, ok := corps[i][champNAT].(map[string]any)
		if !ok {
			t.Fatalf("add %d: body has no %q record: %v", i, champNAT, corps[i])
		}
		attendu := map[string]string{
			"enabled":    "1",
			"interface":  "wan",
			"protocol":   "tcp",
			"dstport":    fmt.Sprintf("%d", port),
			"local-port": fmt.Sprintf("%d", port),
			"target":     cfg.IPInterne,
			"descr":      fmt.Sprintf("Ceffio - %d", port),
			"ipprotocol": "inet",
		}
		for champ, valeur := range attendu {
			if regle[champ] != valeur {
				t.Errorf("add %d: %s = %v, want %q", i, champ, regle[champ], valeur)
			}
		}
		if regle["associated-rule-id"] != "add" {
			t.Errorf("add %d: no request for the pass rule, got %v", i, regle["associated-rule-id"])
		}
	}
}

// TestPublierPortsUnResultSuffit: some versions answer {"result":"saved"} where
// others answer a uuid. Both are a confirmation; a bare {} is not.
func TestPublierPortsUnResultSuffit(t *testing.T) {
	f, cfg := configTest(t)
	f.corpsAjout = `{"result":"saved"}`

	res, err := PublierPorts(context.Background(), cfg, []int{25}, nil)
	if err != nil {
		t.Fatalf("PublierPorts: %v", err)
	}
	if len(res.PortsOuverts) != 1 || res.PortsOuverts[0] != 25 {
		t.Errorf("PortsOuverts = %v, want [25]", res.PortsOuverts)
	}
	if len(res.ReglesManuelles) != 0 {
		t.Errorf("no manual rule expected, got %v", res.ReglesManuelles)
	}
}

// TestPublierPortsRetombeSurLesReglesManuelles is the test of the contract: in
// every one of these situations the firewall did NOT confirm the forward, so
// the caller must get the manual rules and no error — a failure here would let
// an operator believe inbound mail is reachable.
func TestPublierPortsRetombeSurLesReglesManuelles(t *testing.T) {
	ports := []int{25, 465}

	cas := []struct {
		nom    string
		regler func(*fauxPareFeu)
		// ajoutAttendu says whether the add endpoint may be called: when the
		// search cannot be read, creating blindly is forbidden.
		ajoutAutorise bool
	}{
		{
			nom: "firewall en erreur 500",
			regler: func(f *fauxPareFeu) {
				f.statut = http.StatusInternalServerError
			},
		},
		{
			nom: "recherche non-JSON",
			regler: func(f *fauxPareFeu) {
				f.corpsRecherche = "<html><body>proxy error</body></html>"
			},
		},
		{
			nom: "ajout non-JSON (HTML avec 200)",
			regler: func(f *fauxPareFeu) {
				f.corpsAjout = "<html><body>error</body></html>"
			},
			ajoutAutorise: true,
		},
		{
			nom: "ajout sans uuid",
			regler: func(f *fauxPareFeu) {
				f.corpsAjout = "{}"
			},
			ajoutAutorise: true,
		},
		{
			nom: "application en erreur",
			regler: func(f *fauxPareFeu) {
				f.corpsApplique = "<html><body>reconfigure failed</body></html>"
			},
			ajoutAutorise: true,
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			f, cfg := configTest(t)
			c.regler(f)

			res, err := PublierPorts(context.Background(), cfg, ports, nil)
			if err != nil {
				t.Fatalf("PublierPorts must never fail on an API problem: %v", err)
			}
			if len(res.PortsOuverts) != 0 {
				t.Errorf("nothing is confirmed, PortsOuverts must stay empty, got %v", res.PortsOuverts)
			}
			if len(res.Avertissemts) == 0 {
				t.Error("the reason must be reported in Avertissemts")
			}
			attendues := ReglesManuelles(cfg.IPInterne, ports)
			if len(res.ReglesManuelles) != len(attendues) {
				t.Fatalf("%d manual rules, want %d: %v", len(res.ReglesManuelles), len(attendues), res.ReglesManuelles)
			}
			for i, attendue := range attendues {
				if res.ReglesManuelles[i] != attendue {
					t.Errorf("manual rule %d = %q, want %q", i, res.ReglesManuelles[i], attendue)
				}
			}
			recherche := f.nbAppels(cheminNATRecherche)
			ajouts := f.nbAppels(cheminNATAjout)
			if !c.ajoutAutorise && ajouts != 0 {
				t.Errorf("%d add call(s) although the search failed: never create blindly", ajouts)
			}
			if c.ajoutAutorise && recherche != 1 {
				t.Errorf("%d search call(s), want 1", recherche)
			}
		})
	}
}

// TestPublierPortsIdempotent: a port already forwarded to the node is reported
// as existing and not created again; the other one is created. A duplicate WAN
// port forward is not harmless, it makes the ruleset ambiguous.
func TestPublierPortsIdempotent(t *testing.T) {
	f, cfg := configTest(t)
	f.regles = []string{
		"25:10.0.0.5",    // ours: must not be created again
		"465:192.0.2.99", // another host: not ours, so the add is attempted
		"993:10.0.0.5",   // ours too
	}

	res, err := PublierPorts(context.Background(), cfg, []int{25, 465, 993}, nil)
	if err != nil {
		t.Fatalf("PublierPorts: %v", err)
	}
	if fmt.Sprint(res.PortsExistants) != fmt.Sprint([]int{25, 993}) {
		t.Errorf("PortsExistants = %v, want [25 993]", res.PortsExistants)
	}
	if fmt.Sprint(res.PortsOuverts) != fmt.Sprint([]int{25, 465, 993}) {
		t.Errorf("PortsOuverts = %v, want [25 465 993]", res.PortsOuverts)
	}
	if n := f.nbAppels(cheminNATAjout); n != 1 {
		t.Errorf("%d add call(s), want 1 (only port 465)", n)
	}
	corps := f.corpsAjoutes()
	if len(corps) == 1 {
		regle := corps[0][champNAT].(map[string]any)
		if regle["dstport"] != "465" {
			t.Errorf("created port %v, want 465", regle["dstport"])
		}
	}
	if len(res.ReglesManuelles) != 0 {
		t.Errorf("all three ports are confirmed, no manual rule expected, got %v", res.ReglesManuelles)
	}

	// A second run must create nothing: idempotence is the reason the search
	// happens first.
	f.regles = []string{"25:10.0.0.5", "465:10.0.0.5", "993:10.0.0.5"}
	avant := f.nbAppels(cheminNATAjout)
	if _, err := PublierPorts(context.Background(), cfg, []int{25, 465, 993}, nil); err != nil {
		t.Fatalf("second PublierPorts: %v", err)
	}
	if apres := f.nbAppels(cheminNATAjout); apres != avant {
		t.Errorf("second run created %d rule(s): %d add calls before, %d after", apres-avant, avant, apres)
	}
}
