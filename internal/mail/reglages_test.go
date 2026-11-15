// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

import (
	"context"
	"testing"
)

// TestUneInstallationSansServeurMaisAvecRelaisResteEnRelais covers the upgrade
// from 0.10.x (§4.10 of docs/plan-mail.md).
//
// WHY THIS TEST EXISTS: before the `server` group, the only mail setting stored
// was the relay. An upgraded installation has no `mail.server` key, and
// defaulting it to `direct` would switch off outbound mail on a host whose port
// 25 is blocked — the exact reason the relay was configured. The historical
// mode must survive the upgrade.
func TestUneInstallationSansServeurMaisAvecRelaisResteEnRelais(t *testing.T) {
	cfg, err := reglagesDepuis(context.Background(), map[string]string{
		CleRelais: `{"hote":"smtp.example.com","port":"587","utilisateur":"ceffio"}`,
	})
	if err != nil {
		t.Fatalf("reading the settings: %v", err)
	}
	if cfg.Envoi.Mode != ModeRelais {
		t.Fatalf("mode = %q, expected %q: an upgraded installation that has a relay must keep it",
			cfg.Envoi.Mode, ModeRelais)
	}
	if cfg.Envoi.Hote != "smtp.example.com" || cfg.Envoi.Port != 587 || cfg.Envoi.Utilisateur != "ceffio" {
		t.Errorf("relay = %s:%d/%s, expected the stored values",
			cfg.Envoi.Hote, cfg.Envoi.Port, cfg.Envoi.Utilisateur)
	}
	// The rest of the server settings keep their defaults: the upgrade must not
	// invent a volume size or a quota the operator never chose.
	if cfg.VolumeGio != 0 || cfg.QuotaDefautGio != QuotaDefautGio || !cfg.ClientsExternes {
		t.Errorf("server defaults = %+v, expected the historical values", cfg)
	}
}

// TestUnServeurExpliciteGardeSonMode: once `mail.server` exists, it is the
// authority — a stored `direct` must not be turned back into `relais` just
// because a relay is still stored for a later switch.
func TestUnServeurExpliciteGardeSonMode(t *testing.T) {
	cfg, err := reglagesDepuis(context.Background(), map[string]string{
		CleServeur: `{"envoi":"direct"}`,
		CleRelais:  `{"hote":"smtp.example.com","port":"587","utilisateur":"ceffio"}`,
	})
	if err != nil {
		t.Fatalf("reading the settings: %v", err)
	}
	if cfg.Envoi.Mode != ModeDirect {
		t.Errorf("mode = %q, expected %q: an explicit server setting wins", cfg.Envoi.Mode, ModeDirect)
	}
}

// TestSansReglageAucunLesDefautsSAppliquent: a fresh installation with nothing
// stored deploys the historical defaults.
func TestSansReglageAucunLesDefautsSAppliquent(t *testing.T) {
	cfg, err := reglagesDepuis(context.Background(), nil)
	if err != nil {
		t.Fatalf("reading the settings: %v", err)
	}
	defaut := ReglagesParDefaut()
	if cfg.Envoi.Mode != defaut.Envoi.Mode || cfg.VolumeGio != defaut.VolumeGio ||
		cfg.QuotaDefautGio != defaut.QuotaDefautGio || cfg.ClientsExternes != defaut.ClientsExternes {
		t.Errorf("reglages = %+v, expected the defaults %+v", cfg, defaut)
	}
}
