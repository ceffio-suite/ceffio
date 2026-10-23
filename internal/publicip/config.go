// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package publicip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ChargerConfig reads the operator settings from the shared settings
// ConfigMap, and falls back to the defaults when nothing was ever saved.
//
// WHY NOT fail on a missing or unreadable ConfigMap: the reporter must be able
// to work on a fresh installation, before anyone opened the settings page.
// A discovery that refuses to start until configured is a discovery that
// never starts.
func ChargerConfig(ctx context.Context, c kubernetes.Interface) Config {
	if c == nil {
		return Defaut()
	}
	cm, err := c.CoreV1().ConfigMaps(NamespaceReglages).Get(ctx, NomReglages, metav1.GetOptions{})
	if err != nil {
		// Unreadable (missing, RBAC, API down): the defaults still beat a
		// reporter that does nothing.
		return Defaut()
	}
	brut := strings.TrimSpace(cm.Data[CleReglages])
	if brut == "" {
		return Defaut()
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(brut), &v); err != nil {
		return Defaut()
	}
	cfg := DepuisValeurs(v)
	// A static address is a deliberate air-gap choice: it must parse, or the
	// reporter would publish a value no component can bind to.
	if cfg.Static != "" && ip4(cfg.Static) == "" {
		cfg.Static = ""
	}
	return cfg
}

// ValiderConfig checks a configuration before it is stored. It returns every
// problem at once — telling an operator about one typo per save, on a field
// with six servers, is how a form gets abandoned.
func ValiderConfig(cfg Config) []string {
	var problemes []string
	if cfg.Static != "" && ip4(cfg.Static) == "" {
		problemes = append(problemes, fmt.Sprintf("static_ip: %q is not an IPv4 address", cfg.Static))
	}
	for _, s := range cfg.STUN {
		if !strings.Contains(s, ":") {
			problemes = append(problemes, fmt.Sprintf("stun_servers: %q has no port (expected host:port)", s))
		}
	}
	for _, u := range cfg.HTTP {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			problemes = append(problemes, fmt.Sprintf("http_fallback: %q is not an http(s) URL", u))
		}
	}
	if len(cfg.STUN) == 0 && len(cfg.HTTP) == 0 && cfg.Static == "" {
		problemes = append(problemes, "at least one STUN server, one HTTP fallback or a static address is required")
	}
	if cfg.Interval != "" {
		if d, err := time.ParseDuration(cfg.Interval); err != nil {
			problemes = append(problemes, fmt.Sprintf("interval: %q is not a duration (e.g. 60s)", cfg.Interval))
		} else if d < 10*time.Second {
			problemes = append(problemes, "interval: the minimum is 10s")
		}
	}
	return problemes
}

// Verifier interroge chaque source séparément et renvoie le détail, pour
// `ceffio publicip check`.
//
// WHY ONE SOURCE AT A TIME HERE AND NOT THE CONSENSUS PATH: the consensus
// answers "what is the address"; the check answers "which source is broken".
// Mixing them would make a dead server invisible as long as two others agree —
// which is exactly the state an operator is trying to diagnose.
func Verifier(ctx context.Context, cfg Config, hc *http.Client) []Resultat {
	var out []Resultat
	if cfg.Static != "" {
		out = append(out, Resultat{Source: "static", IP: cfg.Static, OK: ip4(cfg.Static) != ""})
	}
	for _, s := range cfg.STUN {
		ip, d, err := chrono(ctx, func(ctx context.Context) (string, error) { return stunLookup(ctx, s) })
		out = append(out, Resultat{Source: "stun " + s, IP: ip, Duree: d, OK: err == nil, Erreur: erreur(err)})
	}
	for _, u := range cfg.HTTP {
		ip, d, err := chrono(ctx, func(ctx context.Context) (string, error) { return httpLookup(ctx, hc, u) })
		out = append(out, Resultat{Source: "http " + u, IP: ip, Duree: d, OK: err == nil, Erreur: erreur(err)})
	}
	return out
}

// Resultat is one line of `ceffio publicip check`.
type Resultat struct {
	Source string
	IP     string
	Duree  time.Duration
	OK     bool
	Erreur string
}

func chrono(ctx context.Context, f func(context.Context) (string, error)) (string, time.Duration, error) {
	debut := time.Now()
	ip, err := f(ctx)
	return ip, time.Since(debut).Round(time.Millisecond), err
}

func erreur(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
