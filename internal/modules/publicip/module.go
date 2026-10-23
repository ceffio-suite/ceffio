// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package publicip declares the "public-ip" Core module: the reporter that
// discovers the machine's public address and publishes it for every other
// layer.
//
// WHY A MODULE AND NOT A HIDDEN STEP OF talk: the registry is the catalog every
// frontend reads — status, doctor, the console, `module list`. A component that
// exists on the cluster but not in the registry is invisible exactly when
// someone is trying to understand what runs where.
package publicip

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	couchePublicip "github.com/ceffio-suite/ceffio/internal/publicip"
)

const (
	nsSystem = "ceffio-system"

	// fraicheurMax is how old a published value may be before the module
	// reports Degraded. Three refresh intervals: one missed poll is normal,
	// three in a row means the reporter is stuck.
	fraicheurMax = 10 * time.Minute
)

type publicIPModule struct{}

func init() { module.Register(&publicIPModule{}) }

func (m *publicIPModule) Info() module.Info {
	return module.Info{
		ID:          "public-ip",
		Title:       "Public address",
		Description: "Discovers the machine's public IPv4 address and publishes it (ConfigMap ceffio-public-ip), so that Janus, coturn and every future layer read one value instead of rediscovering it.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsSystem},
		Resources:   "negligible: one pod, 24 MiB, no disk",
		// NO PERMISSION DECLARATION BEYOND THE STANDARD NAMESPACE SET: the
		// module lives in ceffio-system, which the platform already declares.
		// Declaring it again would not widen the console's sum (the union is
		// idempotent), but it would suggest this module owns a namespace it
		// merely shares.
		Permissions: []module.Permission{socle.StandardPermission(nsSystem)},
	}
}

// Install deploys the reporter. Idempotent, like every layer.
func (m *publicIPModule) Install(ctx context.Context, env module.Env) error {
	return couchePublicip.Deploy(ctx, env.Kube)
}

// State: the Deployment must be ready AND the published value fresh. A ready
// pod that stopped publishing is worse than a stopped pod — the value it serves
// looks authoritative and is stale.
func (m *publicIPModule) State(ctx context.Context, env module.Env) module.State {
	etat := socle.EtatDuDeploiement(ctx, env, nsSystem, couchePublicip.NomDeploiement)
	if etat.Status != module.Installed {
		return etat
	}
	a, ok, err := couchePublicip.Lire(ctx, env.Kube)
	switch {
	case err != nil:
		return module.State{Status: module.Unknown, Detail: err.Error()}
	case !ok || a.Vide():
		return module.State{Status: module.Degraded, Detail: "reporter ready, no address published yet"}
	case time.Since(a.UpdatedAt) > fraicheurMax:
		return module.State{Status: module.Degraded, Detail: fmt.Sprintf(
			"address %s not refreshed for %s", a.IPv4, time.Since(a.UpdatedAt).Round(time.Minute))}
	}
	return module.State{Status: module.Installed, Detail: fmt.Sprintf(
		"public address %s (%s, %d/%d sources)", a.IPv4, a.Source, a.Sources, a.Total)}
}

// Uninstall refuses: it is a Core layer, removed with the cluster.
func (m *publicIPModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}

// --- Settings --------------------------------------------------------------

// Settings declares the discovery sources. THE LIST IS A SETTING, not a
// constant: a public STUN server can disappear, and an operator whose network
// filters UDP must be able to point the reporter somewhere else without a new
// release.
func (m *publicIPModule) Settings() []module.Group {
	defaut := couchePublicip.Defaut()
	return []module.Group{{
		ID:    couchePublicip.GroupeReglages,
		Title: "Public address discovery",
		Description: "Where the public IPv4 address is read from. Several sources are " +
			"queried and must agree: a single answer cannot corroborate itself.",
		Fields: []module.Field{
			{
				Key:   "stun_servers",
				Label: "STUN servers",
				Help: "Comma-separated host:port, queried over UDP. These traverse the " +
					"same NAT path as the media, so they are preferred.",
				Type:    module.Text,
				Default: strings.Join(defaut.STUN, ","),
			},
			{
				Key:   "http_fallback",
				Label: "HTTP fallback",
				Help: "Comma-separated URLs, used only when no STUN server answers " +
					"(UDP often filtered on corporate networks).",
				Type:    module.Text,
				Default: strings.Join(defaut.HTTP, ","),
			},
			{
				Key:   "static_ip",
				Label: "Static address (air-gap)",
				Help: "Leave empty to discover. Setting an address disables discovery " +
					"entirely — the reporter republishes it unchanged.",
				Type:    module.Text,
				Default: "",
			},
			{
				Key:     "interval",
				Label:   "Refresh interval",
				Help:    "How often the address is checked. Minimum 10s.",
				Type:    module.Text,
				Default: defaut.Interval,
				Pattern: `^\d+(\.\d+)?(s|m|h)$`,
			},
		},
	}}
}

// Current reads the stored settings. Absent values read as the defaults: the
// page must show what the reporter would actually use, not an empty form.
func (m *publicIPModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != couchePublicip.GroupeReglages {
		return nil, fmt.Errorf("public-ip: unknown settings group %q", groupe)
	}
	if env.Settings == nil {
		return couchePublicip.Defaut().Valeurs(), nil
	}
	brut, err := env.Settings.Lire(ctx, couchePublicip.NamespaceReglages, couchePublicip.NomReglages, couchePublicip.CleReglages)
	if err != nil {
		return nil, err
	}
	valeurs := map[string]string{}
	if strings.TrimSpace(brut) != "" {
		if err := json.Unmarshal([]byte(brut), &valeurs); err != nil {
			return nil, fmt.Errorf("public-ip: stored settings are not valid JSON: %w", err)
		}
	}
	return couchePublicip.DepuisValeurs(valeurs).Valeurs(), nil
}

// Apply validates and stores. The reporter re-reads the settings on every
// cycle, so NO RESTART is needed: the change applies at the next refresh.
func (m *publicIPModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if groupe != couchePublicip.GroupeReglages {
		return fmt.Errorf("public-ip: unknown settings group %q", groupe)
	}
	cfg := couchePublicip.DepuisValeurs(v)
	if problemes := couchePublicip.ValiderConfig(cfg); len(problemes) > 0 {
		return fmt.Errorf("public-ip: %s", strings.Join(problemes, "; "))
	}
	if env.Settings == nil {
		return fmt.Errorf("public-ip: no settings store")
	}
	donnees, err := json.Marshal(cfg.Valeurs())
	if err != nil {
		return fmt.Errorf("public-ip: encoding settings: %w", err)
	}
	return env.Settings.Ecrire(ctx, couchePublicip.NamespaceReglages, couchePublicip.NomReglages,
		map[string]string{couchePublicip.CleReglages: string(donnees)})
}
