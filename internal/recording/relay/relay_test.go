// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// THE ALGORITHM IS WRITTEN AGAIN HERE, AND THAT IS THE POINT: a test that calls
// the function under test proves only that the function agrees with itself. The
// vectors below were produced by the RECORDER's own implementation — Server.py,
// _calculateChecksum: hmac.new(secret, random.encode() + body,
// hashlib.sha256).hexdigest() — so they prove interoperability, not
// self-consistency.
const (
	vecteurSecret   = "s3cret"
	vecteurRandom   = "abc123"
	vecteurStartCor = `{"type":"start"}`
	vecteurStartSom = "cd85a0f4b6e64a200b1bf44f47d69f808bd90cae3d192f9004754a08a2285740"
	vecteurStopCor  = `{"type":"stop"}`
	vecteurStopSom  = "53672f31b208762d0fcf3a1e54aa9e04ba3e09ed286c985678f653d484b963b4"
)

// TestSignatureCommeLEnregistreur compares to the reference implementation.
func TestSignatureCommeLEnregistreur(t *testing.T) {
	if got := signature(vecteurSecret, vecteurRandom, []byte(vecteurStartCor)); got != vecteurStartSom {
		t.Errorf("start: signature = %s, the recorder computes %s", got, vecteurStartSom)
	}
	if got := signature(vecteurSecret, vecteurRandom, []byte(vecteurStopCor)); got != vecteurStopSom {
		t.Errorf("stop: signature = %s, the recorder computes %s", got, vecteurStopSom)
	}
}

// signe is the recorder's checksum, in the test's own words.
func signe(secret, aleatoire string, corps []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(aleatoire))
	mac.Write(corps)
	return hex.EncodeToString(mac.Sum(nil))
}

// appel enregistre une requête reçue par le faux enregistreur.
type appel struct {
	methode string
	chemin  string
	entetes http.Header
	corps   []byte
}

// fauxEnregistreur is the recording server, with the answer we choose.
type fauxEnregistreur struct {
	srv     *httptest.Server
	mu      sync.Mutex
	appels  []appel
	reponse int
	corps   string
}

func nouvelEnregistreur(t *testing.T, reponse int, corps string) *fauxEnregistreur {
	t.Helper()
	f := &fauxEnregistreur{reponse: reponse, corps: corps}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.appels = append(f.appels, appel{r.Method, r.URL.Path, r.Header.Clone(), b})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.reponse)
		_, _ = io.WriteString(w, f.corps)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fauxEnregistreur) recus() []appel {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]appel(nil), f.appels...)
}

// fausseCapture is the capture service, with an optional delay.
type fausseCapture struct {
	srv     *httptest.Server
	delai   time.Duration
	mu      sync.Mutex
	corps   [][]byte
	entetes []http.Header
}

func nouvelleCapture(t *testing.T, delai time.Duration) *fausseCapture {
	t.Helper()
	c := &fausseCapture{delai: delai}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(c.delai)
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.corps = append(c.corps, b)
		c.entetes = append(c.entetes, r.Header.Clone())
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fausseCapture) alertes() ([][]byte, []http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.corps...), append([]http.Header(nil), c.entetes...)
}

// portFerme returns an address nothing listens on: the normal state of a
// cluster without the capture module.
func portFerme(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	adresse := l.Addr().String()
	_ = l.Close()
	return "http://" + adresse + "/v1/recording"
}

// requeteDeTest builds the request Talk sends, correctly signed.
func requeteDeTest(t *testing.T, secret, token string, corps []byte) *http.Request {
	t.Helper()
	aleatoire := "abc123"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/room/"+token, bytes.NewReader(corps))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Talk-Recording-Backend", "https://cloud.exemple.org/")
	req.Header.Set("Talk-Recording-Random", aleatoire)
	req.Header.Set("Talk-Recording-Checksum", signe(secret, aleatoire, corps))
	return req
}

func relais(t *testing.T, o Options) *Relay {
	t.Helper()
	r, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestTransmissionOctetPourOctet: same method, path, headers and body, and the
// recorder's answer returned untouched.
func TestTransmissionOctetPourOctet(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	corps := []byte(`{"type":"start","start":{"owner":"alice","actor":{"type":"users","id":"alice"}}}`)
	req := requeteDeTest(t, secret, "abc123token", corps)
	req.Header.Set("X-Une-Autre", "garde-moi")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, attendu 200 (corps %q)", w.Code, w.Body.String())
	}
	if w.Body.String() != `{"ok":true}` {
		t.Errorf("réponse = %q, attendu le corps de l'enregistreur", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type de la réponse = %q", got)
	}

	recus := rec.recus()
	if len(recus) != 1 {
		t.Fatalf("%d requête(s) transmise(s), attendu une", len(recus))
	}
	a := recus[0]
	if a.methode != http.MethodPost || a.chemin != "/api/v1/room/abc123token" {
		t.Errorf("transmis %s %s", a.methode, a.chemin)
	}
	if !bytes.Equal(a.corps, corps) {
		t.Errorf("corps transmis = %q, attendu %q (octet pour octet)", a.corps, corps)
	}
	for _, h := range []string{"Talk-Recording-Backend", "Talk-Recording-Random", "Talk-Recording-Checksum", "Content-Type"} {
		if a.entetes.Get(h) != req.Header.Get(h) {
			t.Errorf("%s transmis = %q, attendu %q", h, a.entetes.Get(h), req.Header.Get(h))
		}
	}
	// NOTHING ADDED: the recorder's own address logic must see what Talk sent,
	// not what a proxy invented.
	if xff := a.entetes.Get("X-Forwarded-For"); xff != "" {
		t.Errorf("X-Forwarded-For = %q : le relais ne doit rien ajouter", xff)
	}
	// NOTHING CARRIED OVER BY ACCIDENT EITHER: the four headers above are the
	// contract. Copying the whole header set would forward hop-by-hop headers
	// and whatever a caller happened to send.
	if a.entetes.Get("X-Une-Autre") != "" {
		t.Error("un en-tête hors contrat a été transmis : le relais recopie tout au lieu de ce qu'il doit")
	}
}

// TestSignatureInvalide: 403, nothing forwarded, nothing notified.
func TestSignatureInvalide(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	req := requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`))
	req.Header.Set("Talk-Recording-Checksum", strings.Repeat("0", 64))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	r.WaitNotifications()

	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, attendu 403", w.Code)
	}
	if len(rec.recus()) != 0 {
		t.Error("une requête mal signée a été transmise : la signature est la seule porte")
	}
	corps, _ := cap.alertes()
	if len(corps) != 0 {
		t.Errorf("la capture a été prévenue d'une requête refusée : %q", corps)
	}
}

// TestEnTeteManquant: the recorder refuses without the three headers, and so
// does the relay.
func TestEnTeteManquant(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	for _, entete := range []string{"Talk-Recording-Backend", "Talk-Recording-Random", "Talk-Recording-Checksum"} {
		req := requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`))
		req.Header.Del(entete)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("sans %s : code = %d, attendu 403", entete, w.Code)
		}
	}
	if len(rec.recus()) != 0 {
		t.Error("une requête sans signature a été transmise")
	}
}

// TestCorpsTropGros: the recorder's own limit, refused before reading.
func TestCorpsTropGros(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	gros := bytes.Repeat([]byte("a"), MaxBody+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/room/tok", bytes.NewReader(gros))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Talk-Recording-Backend", "https://cloud.exemple.org/")
	req.Header.Set("Talk-Recording-Random", "abc123")
	req.Header.Set("Talk-Recording-Checksum", signe(secret, "abc123", gros))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, attendu 400 (le refus que l'enregistreur oppose au même corps)", w.Code)
	}
	if len(rec.recus()) != 0 {
		t.Error("un corps au-delà de la limite a été transmis")
	}
}

// TestCorpsSansLongueur: chunked, or a lie about the size. The recorder refuses
// "not content_length", and so does the relay.
func TestCorpsSansLongueur(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	req := requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, attendu 400", w.Code)
	}
	if len(rec.recus()) != 0 {
		t.Error("une requête sans Content-Length a été transmise")
	}
}

// TestEnregistreurEnPanne: the recorder's error code is returned as it came,
// and no recording is announced.
func TestEnregistreurEnPanne(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusInternalServerError, `{"error":"boom"}`)
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`)))
	r.WaitNotifications()

	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d, attendu 500 — le code de l'enregistreur, tel quel", w.Code)
	}
	if w.Body.String() != `{"error":"boom"}` {
		t.Errorf("corps = %q, attendu celui de l'enregistreur", w.Body.String())
	}
	corps, _ := cap.alertes()
	if len(corps) != 0 {
		t.Errorf("la capture a été prévenue d'un enregistrement qui a échoué : %q", corps)
	}
}

// TestEnregistreurInjoignable: 502 to Nextcloud, and no notification.
func TestEnregistreurInjoignable(t *testing.T) {
	const secret = "partage"
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: portFerme(t), Notify: cap.srv.URL, Secret: secret})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`)))
	r.WaitNotifications()

	if w.Code != http.StatusBadGateway {
		t.Errorf("code = %d, attendu 502", w.Code)
	}
	corps, _ := cap.alertes()
	if len(corps) != 0 {
		t.Error("la capture a été prévenue alors que rien n'a été enregistré")
	}
}

// TestNotificationSignee: the capture receives what B3 needs, signed with the
// same scheme so it can refuse anything that does not come from the relay.
func TestNotificationSignee(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	corps := []byte(`{"type":"start","start":{"owner":"alice","actor":{"type":"users","id":"alice"}}}`)
	req := requeteDeTest(t, secret, "tok-du-salon", corps)
	req.Header.Set("Talk-Recording-Backend", "https://cloud.exemple.org/")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	r.WaitNotifications()

	recues, entetes := cap.alertes()
	if len(recues) != 1 {
		t.Fatalf("%d notification(s), attendu une", len(recues))
	}

	var avis map[string]any
	if err := json.Unmarshal(recues[0], &avis); err != nil {
		t.Fatalf("la notification n'est pas du JSON : %v", err)
	}
	if avis["type"] != "start" || avis["token"] != "tok-du-salon" || avis["owner"] != "alice" {
		t.Errorf("notification = %s", recues[0])
	}
	if avis["backend"] != "https://cloud.exemple.org/" {
		t.Errorf("backend = %v", avis["backend"])
	}
	if _, err := time.Parse(time.RFC3339, avis["at"].(string)); err != nil {
		t.Errorf("at = %v, attendu du RFC3339", avis["at"])
	}
	acteur, _ := avis["actor"].(map[string]any)
	if acteur["id"] != "alice" {
		t.Errorf("acteur = %v, attendu celui de la requête", avis["actor"])
	}

	// THE SIGNATURE IS VERIFIED HERE THE WAY THE CAPTURE WILL VERIFY IT.
	aleatoire := entetes[0].Get("Ceffio-Relay-Random")
	somme := entetes[0].Get("Ceffio-Relay-Checksum")
	if aleatoire == "" || somme == "" {
		t.Fatal("notification sans en-têtes de signature : la capture ne pourrait pas la refuser si elle était forgée")
	}
	if attendu := signe(secret, aleatoire, recues[0]); somme != attendu {
		t.Errorf("signature de la notification = %s, attendu %s", somme, attendu)
	}
}

// TestStopNotifieLeStop: the section read is the one the body names. Reading
// "start" on a stop would make the capture finalise at the wrong moment.
func TestStopNotifieLeStop(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	corps := []byte(`{"type":"stop","stop":{"owner":"bob","actor":{"type":"users","id":"bob"}}}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", corps))
	r.WaitNotifications()

	recues, _ := cap.alertes()
	if len(recues) != 1 {
		t.Fatalf("%d notification(s)", len(recues))
	}
	var avis map[string]any
	_ = json.Unmarshal(recues[0], &avis)
	if avis["type"] != "stop" || avis["owner"] != "bob" {
		t.Errorf("notification = %s", recues[0])
	}
}

// TestCaptureLenteNeRetardePasNextcloud: the response is written before the
// notification starts, and a capture that never answers costs nothing.
func TestCaptureLenteNeRetardePasNextcloud(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	cap := nouvelleCapture(t, 3*time.Second)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	debut := time.Now()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`)))
	duree := time.Since(debut)

	if duree > 500*time.Millisecond {
		t.Errorf("la réponse a pris %s : elle attend la capture", duree)
	}
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
	// The notification is still in flight; the test waits for it so nothing
	// outlives the test, and its failure (2 s timeout) is the expected
	// behaviour.
	r.WaitNotifications()
}

// TestSansCapture: no notify URL is the normal state without the module.
func TestSansCapture(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`)))
	r.WaitNotifications()
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, attendu 200", w.Code)
	}
}

// TestCaptureAbsente: the Service does not resolve, or nothing answers. One
// debug line, and the recording path is untouched.
func TestCaptureAbsente(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	var mu sync.Mutex
	var lignes []string
	r := relais(t, Options{
		Upstream: rec.srv.URL, Notify: portFerme(t), Secret: secret,
		Logf: func(f string, a ...any) { mu.Lock(); lignes = append(lignes, f); mu.Unlock() },
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, requeteDeTest(t, secret, "tok", []byte(`{"type":"start"}`)))
	r.WaitNotifications()

	if w.Code != http.StatusOK {
		t.Errorf("code = %d : une capture absente ne doit rien changer à l'enregistrement", w.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lignes) == 0 {
		t.Error("aucune ligne de journal : une capture absente serait invisible")
	}
}

// TestHealthzEtWelcome: the probe is ours, and the welcome is forwarded.
func TestHealthzEtWelcome(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/healthz = %d, attendu 200", w.Code)
	}
	if len(rec.recus()) != 0 {
		t.Error("/healthz a été transmis à l'enregistreur : une sonde ne doit pas dépendre de lui")
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/welcome", nil))
	if w.Code != http.StatusOK {
		t.Errorf("/api/v1/welcome = %d, attendu 200", w.Code)
	}
	recus := rec.recus()
	if len(recus) != 1 || recus[0].methode != http.MethodGet || recus[0].chemin != "/api/v1/welcome" {
		t.Errorf("welcome transmis %+v", recus)
	}
}

// TestCheminsRefuses: everything the recorder does not serve.
func TestCheminsRefuses(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	r := relais(t, Options{Upstream: rec.srv.URL, Secret: secret})

	for _, c := range []struct{ methode, chemin string }{
		{http.MethodGet, "/api/v1/room/tok"},   // the recorder serves POST only
		{http.MethodPost, "/api/v1/room/"},     // no token
		{http.MethodPost, "/api/v1/welcome"},   // not a recording
		{http.MethodGet, "/"},                  // nothing else
		{http.MethodPost, "/api/v1/roomx/tok"}, // a prefix is not a match
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(c.methode, c.chemin, nil))
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, attendu 404 ou 405", c.methode, c.chemin, w.Code)
		}
	}
	if len(rec.recus()) != 0 {
		t.Error("un chemin non servi a été transmis")
	}
}

// TestNewRefuse: a relay that cannot verify, or cannot reach, must not start.
func TestNewRefuse(t *testing.T) {
	cas := map[string]Options{
		"sans secret":       {Upstream: "http://127.0.0.1:1234"},
		"amont vide":        {Secret: "x"},
		"amont sans schéma": {Upstream: "127.0.0.1:1234", Secret: "x"},
		"amont en ftp":      {Upstream: "ftp://127.0.0.1:1234", Secret: "x"},
		"notify sans hôte":  {Upstream: "http://127.0.0.1:1234", Secret: "x", Notify: "http:///v1"},
	}
	for nom, o := range cas {
		if _, err := New(o); err == nil {
			t.Errorf("%s : accepté, attendu un refus", nom)
		}
	}
}

// TestStopEnTableauEstNotifie covers the shape that cost a real transcript.
//
// TALK SENDS `"stop": []` when the stop carries no participant — PHP encodes an
// empty array that way. A struct field of type map refused the body, no
// notification was sent, and the capture kept running: the meeting's .srt was
// never written. The array is legitimate; it simply has no fields.
func TestStopEnTableauEstNotifie(t *testing.T) {
	const secret = "partage"
	rec := nouvelEnregistreur(t, http.StatusOK, `{"ok":true}`)
	cap := nouvelleCapture(t, 0)
	r := relais(t, Options{Upstream: rec.srv.URL, Notify: cap.srv.URL, Secret: secret})

	for i, corps := range [][]byte{
		[]byte(`{"type":"stop","stop":[]}`),
		[]byte(`{"type":"stop","stop":{"actor":{"type":"users","id":"bob"}}}`),
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, requeteDeTest(t, secret, "tok"+strconv.Itoa(i), corps))
		if w.Code != http.StatusOK {
			t.Fatalf("corps %d : code = %d", i, w.Code)
		}
	}
	r.WaitNotifications()

	recues, _ := cap.alertes()
	if len(recues) != 2 {
		t.Fatalf("%d notification(s), attendu deux — un stop en tableau doit être notifié", len(recues))
	}
	var avis map[string]any
	_ = json.Unmarshal(recues[0], &avis)
	if avis["type"] != "stop" || avis["token"] != "tok0" {
		t.Errorf("notification = %s", recues[0])
	}
	// LE PREMIER N'A PAS D'ACTEUR, ET C'EST NORMAL : le champ est omis.
	if _, ok := avis["actor"]; ok {
		t.Errorf("un acteur a été inventé pour un stop qui n'en portait pas : %s", recues[0])
	}
	// LE SECOND LE PORTE, TEL QUEL.
	_ = json.Unmarshal(recues[1], &avis)
	acteur, _ := avis["actor"].(map[string]any)
	if acteur["id"] != "bob" {
		t.Errorf("acteur = %v, attendu celui de la requête", avis["actor"])
	}
}
