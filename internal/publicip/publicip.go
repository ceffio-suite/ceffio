// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package publicip discovers the machine's public IPv4 address and publishes
// it so that every other layer can read it instead of rediscovering it.
//
// WHY THIS PACKAGE EXISTS: Janus and coturn each discovered the address on
// their own, from the same STUN server. Two discoveries mean two chances of
// disagreeing, no single place to inspect, and no way for a third component to
// use the value. One reporter, one published value, many readers.
//
// THE VALUE IS NEVER FROZEN INTO THE INSTALLATION: it is discovered, published
// and refreshed, because an address that changes (ISP, move) makes a hardcoded
// one stop working silently.
package publicip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	// Namespace is where the published value lives: the platform namespace,
	// which already exists before any application layer.
	Namespace = "ceffio-system"

	// Nom is the ConfigMap carrying the published address.
	Nom = "ceffio-public-ip"

	CleIPv4      = "ipv4"
	CleSource    = "source"
	CleSources   = "sources"
	CleUpdatedAt = "updated-at"

	// LabelConsommateur marks a Deployment whose pods must be restarted when
	// the address changes. It is a CONVENTION, so the reporter never needs to
	// know the name "janus" or "coturn".
	LabelConsommateur = "ceffio.io/consumes-public-ip"

	// AnnotationIP carries the address the pods were last started with. The
	// reporter patches it: changing it rolls the Deployment, and the new pod
	// resolves its env from the ConfigMap.
	AnnotationIP = "ceffio.io/public-ip"

	// Settings storage: the same ConfigMap the other modules use, under the
	// same `<module>.<group>` key convention.
	NamespaceReglages = "ceffio-system"
	NomReglages       = "ceffio-settings"
	CleReglages       = "public-ip.network"
	GroupeReglages    = "network"
)

// DefaultSTUN is the ordered list of STUN servers used when nothing is
// configured. Google is DELIBERATELY absent: the product claims sovereignty,
// and a single vendor is a single point of trust as much as a single point of
// failure. Nextcloud comes first — it is the ecosystem Ceffio already runs,
// and port 443 crosses networks that filter 3478/19302.
var DefaultSTUN = []string{
	"stun.nextcloud.com:443",
	"stun.cloudflare.com:3478",
	"global.stun.twilio.com:3478",
}

// DefaultHTTP is the fallback when no STUN answer arrives (UDP filtered).
//
// THE `ipv4.` HOST IS NOT COSMETIC: on a dual-stack machine the generic
// endpoint answers with the IPv6 address — measured on the ceffio.org VPS,
// where icanhazip.com returned 2001:41d0:800:1044::1 — which the client
// refuses, because the media path is IPv4 only. The prefix is the vendor's
// documented way to ask for the A record.
var DefaultHTTP = []string{
	"https://ipv4.icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://api.ipify.org",
}

// Consensus is the number of agreeing answers required when several sources
// answered. Two is the smallest number that can disagree: one source cannot
// corroborate itself.
const Consensus = 2

// Adresse is a published address and what produced it.
type Adresse struct {
	IPv4      string    `json:"ipv4"`
	Source    string    `json:"source"`  // stun | http | static
	Sources   int       `json:"sources"` // how many agreed
	Total     int       `json:"total"`   // how many answered
	UpdatedAt time.Time `json:"updatedAt"`

	// Divergence lists the minority answers, when there were any. It is what
	// turns "the address changed" into "two NATs disagree", which is a
	// different problem with a different fix.
	Divergence []string `json:"divergence,omitempty"`
}

// Vide says whether nothing was ever published.
func (a Adresse) Vide() bool { return a.IPv4 == "" }

// Config is the operator-tunable part.
type Config struct {
	STUN     []string `json:"stun_servers"`
	HTTP     []string `json:"http_fallback"`
	Static   string   `json:"static_ip"`
	Interval string   `json:"interval"` // Go duration, default 60s
}

// Defaut returns the configuration an installation uses when the operator has
// set nothing.
func Defaut() Config {
	return Config{
		STUN:     append([]string(nil), DefaultSTUN...),
		HTTP:     append([]string(nil), DefaultHTTP...),
		Static:   "",
		Interval: "60s",
	}
}

func (c Config) intervalle() time.Duration {
	if c.Interval == "" {
		return 60 * time.Second
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d < 10*time.Second {
		return 60 * time.Second
	}
	return d
}

// Valeurs converts the configuration to the string map the settings store
// keeps, and back.
func (c Config) Valeurs() map[string]string {
	return map[string]string{
		"stun_servers":  strings.Join(c.STUN, ","),
		"http_fallback": strings.Join(c.HTTP, ","),
		"static_ip":     c.Static,
		"interval":      c.Interval,
	}
}

// DepuisValeurs reads a stored configuration, falling back to the defaults for
// every empty field.
func DepuisValeurs(v map[string]string) Config {
	c := Defaut()
	if s := strings.TrimSpace(v["stun_servers"]); s != "" {
		c.STUN = liste(s)
	}
	if s := strings.TrimSpace(v["http_fallback"]); s != "" {
		c.HTTP = liste(s)
	}
	c.Static = strings.TrimSpace(v["static_ip"])
	if s := strings.TrimSpace(v["interval"]); s != "" {
		c.Interval = s
	}
	return c
}

func liste(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Lire returns the published address, or false when nothing is published yet.
func Lire(ctx context.Context, c kubernetes.Interface) (Adresse, bool, error) {
	if c == nil {
		return Adresse{}, false, fmt.Errorf("publicip: no Kubernetes client")
	}
	cm, err := c.CoreV1().ConfigMaps(Namespace).Get(ctx, Nom, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Adresse{}, false, nil
	}
	if err != nil {
		return Adresse{}, false, fmt.Errorf("publicip: reading %s/%s: %w", Namespace, Nom, err)
	}
	return depuisConfigMap(cm), true, nil
}

func depuisConfigMap(cm *corev1.ConfigMap) Adresse {
	a := Adresse{
		IPv4:   strings.TrimSpace(cm.Data[CleIPv4]),
		Source: strings.TrimSpace(cm.Data[CleSource]),
	}
	fmt.Sscanf(cm.Data[CleSources], "%d/%d", &a.Sources, &a.Total)
	if t, err := time.Parse(time.RFC3339, cm.Data[CleUpdatedAt]); err == nil {
		a.UpdatedAt = t
	}
	return a
}

// Publier writes the address, creating the ConfigMap if needed. Only the keys
// this package owns are written: a ConfigMap shared with a future contributor
// must not be replaced wholesale.
// donneesDuConfigMap is the published payload: the address, where it came
// from, how many sources agreed, and when. ALL FOUR, because the age is what
// turns a plausible value into a diagnosable one.
func donneesDuConfigMap(a Adresse) map[string]string {
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = time.Now().UTC()
	}
	return map[string]string{
		CleIPv4:      a.IPv4,
		CleSource:    a.Source,
		CleSources:   fmt.Sprintf("%d/%d", a.Sources, a.Total),
		CleUpdatedAt: a.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// ecrireConfigMap creates or updates one ConfigMap holding the payload.
func ecrireConfigMap(ctx context.Context, c kubernetes.Interface, ns string, donnees map[string]string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "ceffio-public-ip",
		"app.kubernetes.io/managed-by": "ceffio",
	}
	cms := c.CoreV1().ConfigMaps(ns)
	actuel, err := cms.Get(ctx, Nom, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: Nom, Namespace: ns, Labels: labels},
			Data:       donnees,
		}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("publicip: creating %s/%s: %w", ns, Nom, err)
		}
		if err == nil {
			return nil
		}
		// AlreadyExists: another replica won the race, fall through to update.
		actuel, err = cms.Get(ctx, Nom, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("publicip: re-reading %s/%s: %w", ns, Nom, err)
		}
	case err != nil:
		return fmt.Errorf("publicip: reading %s/%s: %w", ns, Nom, err)
	}

	if actuel.Data == nil {
		actuel.Data = map[string]string{}
	}
	for k, v := range donnees {
		actuel.Data[k] = v
	}
	if _, err := cms.Update(ctx, actuel, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("publicip: updating %s/%s: %w", ns, Nom, err)
	}
	return nil
}

// Publier writes the source of truth, in the reporter's own namespace.
func Publier(ctx context.Context, c kubernetes.Interface, a Adresse) error {
	if c == nil {
		return fmt.Errorf("publicip: no Kubernetes client")
	}
	return ecrireConfigMap(ctx, c, Namespace, donneesDuConfigMap(a))
}

// Miroir publishes a copy in a CONSUMER namespace.
//
// WHY A COPY IS UNAVOIDABLE: a pod resolves a ConfigMap from ITS OWN namespace
// only — configMapKeyRef has no namespace field. A single ConfigMap in
// ceffio-system would therefore resolve to nothing in ceffio-video, and
// `optional: true` turns that into silence: the pod starts, the variable is
// empty, and the component falls back to its own discovery without saying so.
// MEASURED on the ceffio.org cluster: CEFFIO_PUBLIC_IP was empty in a
// ceffio-video pod reading the ceffio-system ConfigMap, with no error
// anywhere. The mirror is what makes the publication actually reach the pods.
func Miroir(ctx context.Context, c kubernetes.Interface, a Adresse, ns string) error {
	if c == nil {
		return fmt.Errorf("publicip: no Kubernetes client")
	}
	if ns == Namespace {
		return nil
	}
	return ecrireConfigMap(ctx, c, ns, donneesDuConfigMap(a))
}

// Propager mirrors the address into each consumer namespace, then rolls the
// Deployments that declared they consume it.
//
// THE MIRROR COMES FIRST AND ITS FAILURE PREVENTS THE ROLL: rolling a pod
// while the local ConfigMap is stale (or absent) would start it with an empty
// variable — exactly the silent no-op the mirror exists to prevent. Better to
// leave the running pods alone and report the permission problem.
func Propager(ctx context.Context, c kubernetes.Interface, a Adresse, namespaces []string) error {
	if c == nil {
		return fmt.Errorf("publicip: no Kubernetes client")
	}
	corps, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{AnnotationIP: a.IPv4},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	var premier error
	for _, ns := range namespaces {
		if err := Miroir(ctx, c, a, ns); err != nil {
			if premier == nil {
				premier = err
			}
			continue
		}
		dl, err := c.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{
			LabelSelector: LabelConsommateur + "=true",
		})
		if err != nil {
			if premier == nil {
				premier = fmt.Errorf("publicip: listing consumers in %s: %w", ns, err)
			}
			continue
		}
		for _, d := range dl.Items {
			if d.Spec.Template.Annotations[AnnotationIP] == a.IPv4 {
				continue
			}
			if _, err := c.AppsV1().Deployments(ns).Patch(
				ctx, d.Name, types.StrategicMergePatchType, corps, metav1.PatchOptions{}); err != nil && premier == nil {
				premier = fmt.Errorf("publicip: rolling %s/%s: %w", ns, d.Name, err)
			}
		}
	}
	return premier
}

// reponse is one source's answer, or its failure. Failures are kept: the
// operator needs to know WHICH source is down, not only that the total failed.
type reponse struct {
	ip     string
	source string
	err    error
}

// interroger queries every source IN PARALLEL and keeps the order of the
// configured list, so two runs are comparable.
func interroger(ctx context.Context, sources []string, f func(context.Context, string) (string, error)) []reponse {
	reponses := make([]reponse, len(sources))
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			ip, err := f(ctx, s)
			reponses[i] = reponse{ip: ip, source: s, err: err}
		}(i, s)
	}
	wg.Wait()
	return reponses
}

// consensus returns the address the sources agree on.
//
// THE THRESHOLD IS TWO when at least two sources answered: one source cannot
// corroborate itself, and a single answer that is wrong (a transparent proxy,
// a CDN, a NAT pool) is indistinguishable from a right one. When only one
// source answered at all, its answer is kept — one address is better than none
// on a filtered network, as long as it is labelled as such.
func consensus(reponses []reponse, source string) (Adresse, bool) {
	compte := map[string]int{}
	var valides int
	for _, r := range reponses {
		if r.err != nil || r.ip == "" {
			continue
		}
		valides++
		compte[r.ip]++
	}
	if valides == 0 {
		return Adresse{}, false
	}

	meilleur, n := "", 0
	for ip, c := range compte {
		if c > n || (c == n && ip < meilleur) {
			meilleur, n = ip, c
		}
	}
	seuil := Consensus
	if valides < seuil {
		seuil = valides
	}
	if n < seuil {
		return Adresse{}, false
	}

	var divergence []string
	for _, r := range reponses {
		if r.err == nil && r.ip != "" && r.ip != meilleur {
			divergence = append(divergence, r.source+"="+r.ip)
		}
	}
	return Adresse{
		IPv4: meilleur, Source: source, Sources: n, Total: valides,
		UpdatedAt: time.Now().UTC(), Divergence: divergence,
	}, true
}

// resume summarises a round of answers for an error message.
func resume(rep []reponse) string {
	parties := make([]string, 0, len(rep))
	for _, r := range rep {
		if r.err != nil {
			parties = append(parties, r.source+": "+r.err.Error())
		} else {
			parties = append(parties, r.source+"="+r.ip)
		}
	}
	return "[" + strings.Join(parties, ", ") + "]"
}

// Decouvrir finds the public address: static value, then STUN, then HTTP.
//
// THE ORDER IS A CONSEQUENCE OF THE MEDIA PATH, not a preference: STUN is
// queried over UDP from the same host and the same NAT the media crosses, so
// its answer is the one the browsers will actually be able to reach. HTTP says
// what an external server sees of the host's Web traffic, which can differ.
func Decouvrir(ctx context.Context, cfg Config, hc *http.Client) (Adresse, error) {
	if ip := ip4(cfg.Static); ip != "" {
		return Adresse{IPv4: ip, Source: "static", Sources: 1, Total: 1, UpdatedAt: time.Now().UTC()}, nil
	}

	var problemes []string
	if len(cfg.STUN) > 0 {
		rep := interroger(ctx, cfg.STUN, stunLookup)
		if a, ok := consensus(rep, "stun"); ok {
			return a, nil
		}
		problemes = append(problemes, "stun "+resume(rep))
	}
	if len(cfg.HTTP) > 0 {
		rep := interroger(ctx, cfg.HTTP, func(ctx context.Context, u string) (string, error) {
			return httpLookup(ctx, hc, u)
		})
		if a, ok := consensus(rep, "http"); ok {
			return a, nil
		}
		problemes = append(problemes, "http "+resume(rep))
	}
	return Adresse{}, fmt.Errorf("publicip: no address could be established (%s)", strings.Join(problemes, "; "))
}

// httpLookup reads an IPv4 address from an echo service. The body is capped:
// an echo service that starts returning a page must not be read wholesale.
func httpLookup(ctx context.Context, hc *http.Client, url string) (string, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	brut, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	if ip := ip4(string(brut)); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("not an IPv4 address: %q", strings.TrimSpace(string(brut)))
}

// ip4 returns the address if it is IPv4, and "" otherwise: the media path is
// IPv4 only, and silently accepting an IPv6 answer would announce an address
// no browser can reach.
func ip4(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.To4().String()
}

// Attendre polls until a first publication appears or the limit expires.
func Attendre(ctx context.Context, c kubernetes.Interface, limit time.Duration) (Adresse, bool) {
	fin := time.Now().Add(limit)
	for {
		if a, ok, err := Lire(ctx, c); err == nil && ok && !a.Vide() {
			return a, true
		}
		if time.Now().After(fin) {
			return Adresse{}, false
		}
		select {
		case <-ctx.Done():
			return Adresse{}, false
		case <-time.After(2 * time.Second):
		}
	}
}

// Surveiller is the reporter loop: discover, publish, propagate, sleep.
//
// The configuration is re-read every cycle, so changing the server list in the
// settings takes effect without restarting the pod — a restart would drop the
// very value the settings describe.
func Surveiller(ctx context.Context, c kubernetes.Interface, logf func(string, ...any), hc *http.Client) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		cfg := ChargerConfig(ctx, c)
		prec, existait, _ := Lire(ctx, c)

		a, err := Decouvrir(ctx, cfg, hc)
		switch {
		case err != nil:
			logf("public address: discovery failed: %v", err)
		default:
			a.UpdatedAt = time.Now().UTC()
			if err := Publier(ctx, c, a); err != nil {
				logf("public address: publish failed: %v", err)
			}
			if !existait || prec.IPv4 != a.IPv4 {
				logf("public address: %s (%s, %d/%d sources agree)", a.IPv4, a.Source, a.Sources, a.Total)
				if len(a.Divergence) > 0 {
					logf("public address: WARNING — sources disagree: %s", strings.Join(a.Divergence, ", "))
				}
			}
			// PROPAGATED EVERY CYCLE, not only on change. The patch is a no-op
			// when the annotation already carries the address, and running it
			// unconditionally heals the case where another apply (a re-run of
			// `ceffio talk`) removed it: without that, the Deployment would
			// never be rolled again and its pods would keep the old value from
			// the ConfigMap they read at start.
			if err := Propager(ctx, c, a, cfg.namespacesConsommateurs()); err != nil {
				logf("public address: propagation: %v", err)
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.intervalle()):
		}
	}
}

// namespacesConsommateurs is the list of namespaces scanned for consuming
// Deployments. ceffio-video is the only one today; extending it is a one-line
// change, not a new mechanism.
func (c Config) namespacesConsommateurs() []string {
	return []string{"ceffio-video"}
}
