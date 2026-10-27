// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package relay sits in front of the recording server, forwards Talk's
// requests to it untouched, and tells the capture service that a recording
// started or stopped.
//
// WHY A RELAY AT ALL: Nextcloud sends its start/stop request to ONE recording
// server, even when it knows several. There is no fan-out and no hook. A relay
// in front of the recorder is therefore the only place where a second service
// can learn that a recording is happening — without touching Talk's
// configuration, and without the capture reading the database.
//
// THE ORDER IS THE CONTRACT: forward, answer Nextcloud, and only then notify
// the capture, in the background. Recording must never depend on the capture: a
// capture that is absent, down or slow changes nothing on the recording side. A
// notification that fails is one debug line, not an error, and it is never
// retried.
package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MaxBody is the largest request body the recorder accepts, in bytes.
//
// IT IS THE RECORDER'S LIMIT, NOT OURS. Config.getBackendMaximumMessageSize
// returns `maxmessagesize` from server.conf, defaulting to 1024
// (nextcloud/nextcloud-talk-recording, src/nextcloud/talk/recording/Config.py),
// and Server.py refuses a request whose Content-Length is missing or greater
// with BadRequest. Checked on the live installation: `maxmessagesize = 1024` in
// /conf/recording.conf. Forwarding a body the recorder will refuse would only
// move the refusal one hop further from its cause.
const MaxBody = 1024

// jetonValide is the only shape a room token may have.
//
// THE SIGNATURE DOES NOT COVER THE PATH. Talk signs `random || body`; the token
// in `/api/v1/room/<token>` is covered by nothing. Whatever receives it must
// therefore not trust it — and the capture puts it into file paths and, until
// this fix, into shell commands.
//
// THE ALPHABET IS A SUPERSET OF TALK'S, ON PURPOSE. Talk generates 8 characters
// from ISecureRandom::CHAR_LOWER + CHAR_DIGITS minus "l", "0" and "1"
// (nextcloud/spreed, lib/Manager.php, generateNewToken), or 10 digits when SIP
// is configured. [A-Za-z0-9]{4,64} contains all of those and rejects exactly what
// matters here: '/', '..', ';', '|', '$', spaces and quotes. Tightening it to
// the observed alphabet would reject tokens from another Talk version or
// configuration for no security gain: the property we need is "no metacharacter",
// not "Talk's exact generator".
var jetonValide = regexp.MustCompile(`^[A-Za-z0-9]{4,64}$`)

// maxResponse bounds what the relay reads back from the recorder. The recorder
// answers with a short JSON document; an unbounded copy would let a
// misbehaving upstream exhaust the relay's memory.
const maxResponse = 64 << 10

// notifyTimeout is the whole budget of one notification.
//
// A NOTIFICATION IS A COURTESY, NOT A STEP OF THE RECORDING: two seconds is
// enough on a cluster network, and waiting longer would only pile up goroutines
// behind a capture that is not coming back.
const notifyTimeout = 2 * time.Second

// Options configures a relay.
type Options struct {
	// Upstream is the recorder, e.g. "http://127.0.0.1:1234".
	Upstream string
	// Notify is the capture's endpoint, e.g.
	// "http://ceffio-capture.ceffio-video.svc:8080/v1/recording". Empty
	// disables the notification entirely — the relay then only forwards, which
	// is the normal state of an installation without capture.
	Notify string
	// Secret is the shared recording secret (RECORDING_SECRET), the same one
	// Talk signs with. Without it the relay could not verify anything, so an
	// empty secret is refused rather than silently accepted.
	Secret string
	// Logf receives the debug lines (one per failed notification). Defaults to
	// the standard logger.
	Logf func(format string, a ...any)
}

// Relay is the HTTP handler and the notifier.
type Relay struct {
	upstream  *url.URL
	notify    *url.URL
	secret    string
	client    *http.Client
	notifieur *http.Client
	logf      func(format string, a ...any)

	// envois tracks the background notifications so a test — or a graceful
	// shutdown — can wait for them. It never delays a response.
	envois sync.WaitGroup
}

// New validates the options and builds the relay.
func New(o Options) (*Relay, error) {
	amont, err := url.Parse(o.Upstream)
	if err != nil || amont.Scheme == "" || amont.Host == "" {
		return nil, fmt.Errorf("relay: upstream %q is not an absolute URL", o.Upstream)
	}
	if amont.Scheme != "http" && amont.Scheme != "https" {
		return nil, fmt.Errorf("relay: upstream %q must be http or https", o.Upstream)
	}
	if o.Secret == "" {
		// WITHOUT THE SECRET THE RELAY CANNOT VERIFY A SIGNATURE, and an
		// unchecked relay is worse than no relay: it would forward anything to
		// the recorder and notify the capture about it.
		return nil, fmt.Errorf("relay: RECORDING_SECRET is empty: the relay cannot verify a signature")
	}
	r := &Relay{
		upstream: amont,
		secret:   o.Secret,
		// THE FORWARDING CLIENT HAS NO REDIRECT POLICY OF ITS OWN: the recorder
		// does not redirect, and following one would hide a misconfiguration
		// behind a 200.
		client: &http.Client{Timeout: 30 * time.Second},
		logf:   o.Logf,
	}
	if r.logf == nil {
		r.logf = log.Printf
	}
	if o.Notify != "" {
		avis, err := url.Parse(o.Notify)
		if err != nil || avis.Scheme == "" || avis.Host == "" {
			return nil, fmt.Errorf("relay: notify %q is not an absolute URL", o.Notify)
		}
		r.notify = avis
		r.notifieur = &http.Client{Timeout: notifyTimeout}
	}
	return r, nil
}

// WaitNotifications blocks until every background notification has finished.
//
// IT EXISTS FOR THE TESTS AND FOR A CLEAN STOP: a test that asserts "a
// notification was sent" has to be able to wait for it, and a process that
// exits must not cut a notification in half. Nothing in the serving path calls
// it.
func (r *Relay) WaitNotifications() { r.envois.Wait() }

// ServeHTTP routes the three paths the recorder serves, and nothing else.
//
// NO ServeMux, ON PURPOSE: a mux answers "/api/v1/room" with a 301 to
// "/api/v1/room/", which would turn a refused request into a redirect that
// Nextcloud follows. Exact matching is the behaviour wanted here.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/healthz":
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// NEVER FORWARDED: the probe answers for the relay itself, and asking
		// the recorder would make a healthy relay look dead whenever the
		// recorder restarts.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")

	case req.URL.Path == "/api/v1/welcome":
		// NEXTCLOUD'S PROBE, forwarded as-is: it carries no signature, and
		// answering it ourselves would let the relay claim a recorder is
		// reachable when it is not.
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		r.transmettre(w, req, nil)

	case req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/api/v1/room/"):
		r.enregistrement(w, req)

	default:
		http.NotFound(w, req)
	}
}

// enregistrement handles the only request that matters: Talk asking to start or
// stop a recording.
func (r *Relay) enregistrement(w http.ResponseWriter, req *http.Request) {
	token := strings.TrimPrefix(req.URL.Path, "/api/v1/room/")
	// BEFORE ANYTHING ELSE, AND BEFORE ANY FORWARDING: an unauthenticated token
	// must not reach the recorder, and must not be notifiable — the capture
	// would put it in a path.
	if !jetonValide.MatchString(token) {
		http.Error(w, "invalid room token", http.StatusBadRequest)
		return
	}

	// THE SIZE IS CHECKED BEFORE THE SIGNATURE, exactly as the recorder does:
	// an oversized body is refused without being read into memory, so the
	// check cannot itself be the way in.
	//
	// A MISSING CONTENT-LENGTH IS REFUSED TOO: the recorder refuses it
	// ("not request.content_length"), and a chunked request would otherwise
	// pass our check and be refused one hop later.
	if req.ContentLength <= 0 || req.ContentLength > MaxBody {
		http.Error(w, "body size refused", http.StatusBadRequest)
		return
	}
	corps, err := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if len(corps) > MaxBody {
		// A LYING CONTENT-LENGTH: the declared size said 1024 and the stream
		// carried more. The recorder would refuse it too.
		http.Error(w, "body size refused", http.StatusBadRequest)
		return
	}

	// THE THREE HEADERS THE RECORDER REQUIRES. Talk-Recording-Backend names the
	// Nextcloud the request comes from; the recorder looks the secret up by
	// that URL and answers Forbidden when it is unknown. The relay has a single
	// secret, but it still requires the header: a request without it is refused
	// by the recorder, and nothing should be notified about a request that will
	// not become a recording.
	if req.Header.Get("Talk-Recording-Backend") == "" ||
		req.Header.Get("Talk-Recording-Random") == "" ||
		req.Header.Get("Talk-Recording-Checksum") == "" {
		http.Error(w, "missing recording header", http.StatusForbidden)
		return
	}
	if !r.signatureValide(req.Header.Get("Talk-Recording-Random"),
		req.Header.Get("Talk-Recording-Checksum"), corps) {
		http.Error(w, "bad signature", http.StatusForbidden)
		return
	}

	// FORWARDED BYTE FOR BYTE, and nothing is written for the capture before
	// the recorder has accepted the request.
	code, _, ok := r.transmettre(w, req, corps)
	if !ok {
		return // the error is already written
	}
	if code < 200 || code > 299 {
		return
	}
	r.notifier(req, token, corps)
}

// transmettre sends the request upstream and copies the answer back, and
// returns the recorder's status together with the body it produced.
//
// WHAT IS NOT COPIED, on purpose: X-Forwarded-For and every other header the
// proxy layers like to add. The recorder has its own logic about remote
// addresses (B2 of the plan), and a header added here would make the request
// look like it comes from somewhere it does not.
func (r *Relay) transmettre(w http.ResponseWriter, req *http.Request, corps []byte) (int, []byte, bool) {
	cible := *r.upstream
	cible.Path = singleJoiningSlash(r.upstream.Path, req.URL.EscapedPath())
	cible.RawQuery = req.URL.RawQuery

	var corpsReader io.Reader
	if corps != nil {
		corpsReader = bytes.NewReader(corps)
	}
	sortant, err := http.NewRequestWithContext(req.Context(), req.Method, cible.String(), corpsReader)
	if err != nil {
		http.Error(w, "relay: building the upstream request", http.StatusBadGateway)
		return 0, nil, false
	}
	for _, h := range []string{
		"Talk-Recording-Backend",
		"Talk-Recording-Random",
		"Talk-Recording-Checksum",
		"Content-Type",
	} {
		if v := req.Header.Get(h); v != "" {
			sortant.Header.Set(h, v)
		}
	}

	resp, err := r.client.Do(sortant)
	if err != nil {
		// THE RECORDER IS UNREACHABLE: 502 to Nextcloud, and NOTHING is
		// notified — no recording happened.
		r.logf("relay: upstream unreachable: %v", err)
		http.Error(w, "recorder unreachable", http.StatusBadGateway)
		return 0, nil, false
	}
	defer resp.Body.Close()

	reponse, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		http.Error(w, "recorder answer unreadable", http.StatusBadGateway)
		return 0, nil, false
	}

	// THE ANSWER IS RETURNED AS IT CAME: same status, same body, same content
	// type. Nextcloud has to see exactly what the recorder said, otherwise a
	// refusal would look like a success — or the reverse.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(reponse)
	return resp.StatusCode, reponse, true
}

// signatureValide recomputes the recorder's checksum and compares it in
// constant time.
//
// THE ALGORITHM IS THE RECORDER'S, AND ONLY THE RECORDER'S: hex string of
// HMAC-SHA256(secret, random || body), compared with hmac.Equal. A different
// encoding — padded base64, a digest of the body alone — would verify here and
// be refused there, which is the one failure this relay must not invent.
func (r *Relay) signatureValide(aleatoire, somme string, corps []byte) bool {
	attendu := signature(r.secret, aleatoire, corps)
	return hmac.Equal([]byte(somme), []byte(attendu))
}

// signature computes the recorder's checksum. Kept as a plain function so the
// notification signing and the verification provably use the same scheme.
func signature(secret, aleatoire string, corps []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(aleatoire))
	mac.Write(corps)
	return hex.EncodeToString(mac.Sum(nil))
}

// alerte is the notification sent to the capture.
type alerte struct {
	Type    string          `json:"type"`
	Token   string          `json:"token"`
	Owner   string          `json:"owner"`
	Actor   json.RawMessage `json:"actor,omitempty"`
	Backend string          `json:"backend"`
	At      string          `json:"at"`
}

// notifier tells the capture service, IN THE BACKGROUND, that a recording
// started or stopped.
//
// THE RESPONSE IS ALREADY WRITTEN when this runs: the goroutine is started
// after the recorder has answered and the answer has been copied, so a capture
// that is slow by two seconds costs Nextcloud nothing. There is no retry — a
// start/stop that arrived late is worse than a missing one, and B3 makes the
// capture idempotent for the case that matters.
func (r *Relay) notifier(req *http.Request, token string, corps []byte) {
	if r.notify == nil {
		return
	}

	// THE SECTIONS ARE READ AS RAW JSON, and that is not defensive style: Talk
	// sends `"stop": []` — an ARRAY — when no participant is given (PHP encodes
	// an empty array that way), and a struct field of type map refuses it. The
	// first live recording proved the cost: the body failed to decode, no
	// notification was sent, the capture never stopped, and the transcript was
	// never written. A decoding detail became a lost transcript.
	var requete struct {
		Type  string          `json:"type"`
		Start json.RawMessage `json:"start"`
		Stop  json.RawMessage `json:"stop"`
	}
	if err := json.Unmarshal(corps, &requete); err != nil {
		r.logf("relay: recording body unreadable, nothing notified: %v", err)
		return
	}
	partie := requete.Start
	if requete.Type == "stop" {
		partie = requete.Stop
	}

	// AN OBJECT CARRIES FIELDS; an array carries none. Both are legitimate, and
	// an absent section is simply an empty notification.
	var champs map[string]json.RawMessage
	if len(partie) > 0 && partie[0] == '{' {
		_ = json.Unmarshal(partie, &champs) // a malformed object yields no field
	}
	owner := ""
	if v, ok := champs["owner"]; ok {
		_ = json.Unmarshal(v, &owner) // a non-string owner is simply empty
	}

	charge, err := json.Marshal(alerte{
		Type:    requete.Type,
		Token:   token,
		Owner:   owner,
		Actor:   champs["actor"],
		Backend: req.Header.Get("Talk-Recording-Backend"),
		At:      time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		r.logf("relay: notification not built: %v", err)
		return
	}

	aleatoire, err := randomHex(16)
	if err != nil {
		r.logf("relay: notification not signed: %v", err)
		return
	}

	r.envois.Add(1)
	go func() {
		defer r.envois.Done()
		// THE REQUEST'S CONTEXT WOULD ALREADY BE CANCELLED: the handler has
		// returned by the time this runs, so it gets its own deadline.
		ctx, annuler := context.WithTimeout(context.Background(), notifyTimeout)
		defer annuler()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.notify.String(),
			bytes.NewReader(charge))
		if err != nil {
			r.logf("relay: notification not built: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Ceffio-Relay-Random", aleatoire)
		req.Header.Set("Ceffio-Relay-Checksum", signature(r.secret, aleatoire, charge))

		resp, err := r.notifieur.Do(req)
		if err != nil {
			// THE NORMAL CASE WITHOUT A CAPTURE: the Service does not resolve,
			// or nothing answers. One debug line, never an error, never a retry.
			r.logf("relay: capture not notified (%v)", err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			r.logf("relay: capture answered %d to a notification", resp.StatusCode)
		}
	}()
}

// randomHex produces the nonce the signature needs.
//
// A RANDOM NONCE PER REQUEST, not a constant: the checksum covers it, so it is
// what keeps one captured request from being replayed.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// singleJoiningSlash is the path join of net/http/httputil, kept local to avoid
// importing a package of proxy helpers for one line.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
