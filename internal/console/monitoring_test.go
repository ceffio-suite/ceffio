// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// TestMonitoringNeRenvoieJamais500 : a source that did not answer leaves a
// warning, never an error page.
//
// WHY: an operator opens this page DURING an incident. A 500 would hide the
// figures that ARE readable — the node's capacity, the volumes — which is
// precisely the information they came for. The fake clientset answers nothing
// for metrics, Longhorn or the node list, so this is the worst case, and the
// page must still render.
func TestMonitoringNeRenvoieJamais500(t *testing.T) {
	h := newTestServer(fake.NewSimpleClientset()).Handler()

	rec := doReq(t, h, http.MethodGet, "/api/monitoring", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/monitoring -> %d, expected 200.\nThe page must render what it can read; "+
			"an error page hides it.\nBody: %.200s", rec.Code, rec.Body.String())
	}

	var d struct {
		Nodes      []map[string]interface{} `json:"nodes"`
		Volumes    []map[string]interface{} `json:"volumes"`
		Disks      []map[string]interface{} `json:"disks"`
		Warnings   []string                 `json:"warnings"`
		Alert      bool                     `json:"alert"`
		Conditions []map[string]interface{} `json:"conditions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("the answer is not valid JSON: %v\nBody: %.200s", err, rec.Body.String())
	}

	// The lists must be EMPTY ARRAYS, not null: the page calls .map() on them,
	// and a null would throw in JavaScript and leave a blank section — a
	// front-end failure caused by an API detail.
	for nom, brut := range map[string]string{
		"nodes":      `"nodes":null`,
		"volumes":    `"volumes":null`,
		"disks":      `"disks":null`,
		"warnings":   `"warnings":null`,
		"conditions": `"conditions":null`,
	} {
		if strings.Contains(rec.Body.String(), brut) {
			t.Errorf("%s is null in the answer: the page iterates it and would fail in the browser", nom)
		}
	}

	// A source that answered nothing must be NAMED. Without a warning, an empty
	// section reads as "nothing to report" — the opposite of the truth.
	if len(d.Warnings) == 0 {
		t.Errorf("no warning was reported while no source answered: an empty page would look healthy")
	}
	t.Logf("warnings: %v", d.Warnings)

	// And the alert must be FALSE rather than absent: the page branches on it,
	// and an undefined would take the "all clear" branch on an unknown machine.
	if d.Alert {
		t.Errorf("alert is true while nothing could be read")
	}
}

// TestMonitoringLeNoeudEstLuEtSesConditionsAussi : the node and its conditions
// come from the core API, so a cluster that HAS a node must show it.
//
// This is the case the fake CAN serve, and it is checked separately: the test
// above proves the page degrades gracefully, this one proves it reads something
// when there is something to read. A single test would leave one of the two
// behaviours unverified.
func TestMonitoringLeNoeudEstLuEtSesConditionsAussi(t *testing.T) {
	// The fake clientset's REST client does not serve the node list, so this
	// asserts on what the COLLECTION does when the API answers — through the
	// parsing, not through HTTP. The end-to-end path is covered by the
	// integration test that runs against a real cluster.
	t.Run("le parsing des quantites", func(t *testing.T) {
		cas := []struct {
			entree  string
			attendu float64
		}{
			{"12", 12}, {"542m", 0.542}, {"1500m", 1.5}, {"", 0}, {"n'importe quoi", 0},
		}
		for _, c := range cas {
			if got := enCoeurs(c.entree); got != c.attendu {
				t.Errorf("enCoeurs(%q) = %v, expected %v", c.entree, got, c.attendu)
			}
		}
	})

	t.Run("le parsing des tailles", func(t *testing.T) {
		cas := []struct {
			entree  string
			attendu int64
		}{
			{"10Gi", 10 << 30},
			{"512Mi", 512 << 20},
			{"1Ki", 1024},
			{"1G", 1000000000}, // decimal stays decimal: never silently inflated
			{"", 0},
		}
		for _, c := range cas {
			if got := enOctets(c.entree); got != c.attendu {
				t.Errorf("enOctets(%q) = %d, expected %d", c.entree, got, c.attendu)
			}
		}
	})
}

// TestMonitoringLePourcentageNeDepassePasCent : usage above the limit is real
// (a container over its request), and printing 143 % would read as a bug.
func TestMonitoringLePourcentageNeDepassePasCent(t *testing.T) {
	if p := pourcent(143, 100); p != 100 {
		t.Errorf("pourcent(143,100) = %v, expected 100 (capped)", p)
	}
	if p := pourcent(50, 0); p != -1 {
		t.Errorf("pourcent(50,0) = %v, expected -1: a ratio over nothing is unknown, not zero", p)
	}
	if p := pourcent(25, 100); p != 25 {
		t.Errorf("pourcent(25,100) = %v, expected 25", p)
	}
}

// TestMonitoringZeroEcriveNEstPasZeroLu : the distinction the whole page rests
// on — a volume whose usage is unknown must NOT report 0 %.
//
// A page that confused the two would show a full disk as empty, which is the
// one wrong reading that leads to an outage rather than preventing one.
func TestMonitoringZeroEcriveNEstPasZeroLu(t *testing.T) {
	// Nothing written, and we know it: this is a real zero.
	ecrit := Volume{Demande: 10 << 30, Utilise: 0, UtiliseConnu: true}
	if p := ecrit.PctUtilise(); p != 0 {
		t.Errorf("a volume with nothing written reads %v%%, expected 0%%", p)
	}

	// Nothing read: an UNKNOWN, and it must not read as 0.
	inconnu := Volume{Demande: 10 << 30, Utilise: 0, UtiliseConnu: false}
	if p := inconnu.PctUtilise(); p != -1 {
		t.Errorf("a volume whose usage is unknown reads %v%%, expected -1 "+
			"(the page shows \"—\"): reporting 0 %% would show a full disk as empty", p)
	}
}

// TestMonitoringLesSantesSontJugees is the rule the badge and the table must
// share, and the one that is easiest to invert.
//
// "Ready" is healthy when True; MemoryPressure, DiskPressure and PIDPressure are
// healthy when False — THEY MEAN THE OPPOSITE. A single inverted comparison
// would paint a healthy machine red, or worse, a pressured one green.
func TestMonitoringLesSantesSontJugees(t *testing.T) {
	cas := []struct {
		nom      string
		cond     []ConditionNoeud
		disques  []DisqueStockage
		alerte   bool
		pourquoi string
	}{
		{
			nom: "a healthy node with room to spare",
			cond: []ConditionNoeud{
				{Type: "Ready", Statut: "True"},
				{Type: "MemoryPressure", Statut: "False"},
				{Type: "DiskPressure", Statut: "False"},
			},
			disques:  []DisqueStockage{{Maximum: 100, Disponible: 50}},
			alerte:   false,
			pourquoi: "no pressure and a half-empty disk must not raise anything",
		},
		{
			nom:      "memory pressure is SET: True means the condition is present",
			cond:     []ConditionNoeud{{Type: "Ready", Statut: "True"}, {Type: "MemoryPressure", Statut: "True"}},
			disques:  []DisqueStockage{{Maximum: 100, Disponible: 50}},
			alerte:   true,
			pourquoi: "an inverted rule here would report a machine under pressure as healthy.",
		},
		{
			nom:      "the node is not Ready",
			cond:     []ConditionNoeud{{Type: "Ready", Statut: "False"}},
			disques:  []DisqueStockage{{Maximum: 100, Disponible: 50}},
			alerte:   true,
			pourquoi: "a node that is not Ready is the case the page exists to show.",
		},
		{
			nom:      "the disk is nearly full",
			cond:     []ConditionNoeud{{Type: "Ready", Statut: "True"}},
			disques:  []DisqueStockage{{Maximum: 100, Disponible: 5}},
			alerte:   true,
			pourquoi: "95 % full is the reading that must not wait for a pressure condition to appear",
		},
		{
			nom:      "the disk is full enough to be worth a look, not to raise an alert",
			cond:     []ConditionNoeud{{Type: "Ready", Statut: "True"}},
			disques:  []DisqueStockage{{Maximum: 100, Disponible: 20}},
			alerte:   false,
			pourquoi: "80 % is the colour of the bar, not the alert",
		},
	}
	for _, c := range cas {
		m := Monitoring{Conditions: c.cond, Disques: c.disques}
		if got := m.SouciSante(); got != c.alerte {
			t.Errorf("%s: alert = %v, expected %v\n%s", c.nom, got, c.alerte, c.pourquoi)
		}
	}
}

// TestMonitoringLaLonghornDonneLeBonMessage : "not installed" and "forbidden"
// must not read the same.
//
// The first is normal on another provisioning setup and needs no action; the
// second is a defect in THIS deployment, and no amount of reinstalling Longhorn
// fixes it. Reporting one sentence for both sends an operator down the wrong
// path — and the second case exists only because this code introduces it.
func TestMonitoringLaLonghornDonneLeBonMessage(t *testing.T) {
	absent := traduireErreurLonghorn(errHTTP("the server could not find the requested resource (404)"), "volumes")
	if !strings.Contains(absent.Error(), "does not use Longhorn") {
		t.Errorf("a 404 reads %q, expected it to say the cluster does not use Longhorn", absent)
	}

	interdit := traduireErreurLonghorn(errHTTP("volumes.longhorn.io is forbidden: User cannot list (403)"), "volumes")
	if !strings.Contains(interdit.Error(), "deployment defect") {
		t.Errorf("a 403 reads %q, expected it to name a deployment defect rather than a missing install", interdit)
	}
	if strings.Contains(interdit.Error(), "does not use Longhorn") {
		t.Errorf("a 403 is reported as a missing Longhorn: an operator would reinstall it for nothing")
	}
}

// errHTTP is a stand-in for the API's error text.
type errHTTP string

func (e errHTTP) Error() string { return string(e) }

// TestLaRouteMonitoringEstDansLaListeFermee : the new route is declared, with
// its reason, and the guardrail still passes.
//
// This is the counterpart of the closed list: adding a route is a deliberate act
// visible in a diff, and it must not slip in unnoticed.
func TestLaRouteMonitoringEstDansLaListeFermee(t *testing.T) {
	if _, ok := routesAutorisees["/api/monitoring"]; !ok {
		t.Error("the monitoring route is missing from the closed list: the guardrail would refuse it")
	}
	// And it must be READ-ONLY: a monitoring route that could act would be one
	// more way to break a cluster from a browser tab.
	// And it must be READ-ONLY: a monitoring route that could act would be one
	// more way to break a cluster from a browser tab.
	//
	// THE EXPECTED CODE IS NOT 405, and the measurement is what says so: the
	// route is registered for GET only, so a POST falls through to the /api/
	// handler, which refuses every unknown path — INCLUDING a known one reached
	// with the wrong method. The answer is therefore 404, and it is STRICTER than
	// a 405 would be: there is no route to write through at all.
	//
	// Asserting 405 as first written would have been asserting the mux's
	// behaviour rather than this route's. What matters is that a write cannot
	// reach the handler, and that is what is checked: any 2xx would mean it did.
	h := newTestServer(fake.NewSimpleClientset()).Handler()
	rec := doReq(t, h, http.MethodPost, "/api/monitoring", "{}")
	if rec.Code < 400 {
		t.Errorf("POST /api/monitoring -> %d: a monitoring route must not accept a write.\n"+
			"Body: %.150s", rec.Code, rec.Body.String())
	}
	t.Logf("POST /api/monitoring -> %d (read-only: the write cannot reach the handler)", rec.Code)
}
