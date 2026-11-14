// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mail layer's STORED settings, read by everything that applies them.
//
// WHY THEY LIVE HERE AND NOT IN internal/modules/mail: the console's settings
// page is not the only caller. `ceffio install`, `ceffio mail` and
// `ceffio upgrade` (through internal/cluster) all deploy Stalwart, and they
// must apply the same values. Putting the format in the module package would
// have forced the deploy path to import the module package — or, worse, to
// duplicate the key names, which is how two readers end up disagreeing about
// what `mail.server` contains.
//
// THE STORE IS THE `ceffio-settings` ConfigMap in `ceffio-system`, one key per
// settings group (`mail.relay`, `mail.server`). The relay PASSWORD is not
// there: it lives in OpenBao, at `kv/ceffio/mail/relay`, like every other
// secret of the suite.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// CleServeur is the ConfigMap key holding the `server` group.
	CleServeur = "mail.server"
	// CleRelais is the ConfigMap key holding the `relay` group. It is written by
	// internal/modules/mail, whose form field names (`hote`, `port`,
	// `utilisateur`, `exiger_tls`) are therefore this file's wire format.
	CleRelais = "mail.relay"

	// QuotaDefautGio is the default per-mailbox quota.
	QuotaDefautGio = 1
)

// Reglages is the mail layer's effective configuration: everything needed to
// deploy it, in one value.
type Reglages struct {
	Envoi           Envoi // how outgoing mail leaves
	VolumeGio       int   // mailbox store size; 0 = keep what is in place
	QuotaDefautGio  int   // default per-mailbox quota
	ClientsExternes bool  // publish IMAP/SMTPS to the outside
}

// ReglagesParDefaut returns what an installation with no stored settings uses:
// the values the deployment used before there was a settings page.
func ReglagesParDefaut() Reglages {
	return Reglages{
		Envoi:           Envoi{Mode: ModeDirect},
		VolumeGio:       0, // keep the claim in place, create it at the default
		QuotaDefautGio:  QuotaDefautGio,
		ClientsExternes: true,
	}
}

// Valider checks the rules that depend on each other, which the per-field
// validation of a form cannot express.
//
// THE RULE FROM THE PLAN (§4.2): 1 ≤ quota_defaut_gio ≤ volume_gio. A default
// quota above the whole store is not a setting, it is a typo — the first
// mailbox created would immediately be unable to grow, and the cause would be
// in a field three lines above.
func (r Reglages) Valider() error {
	if err := r.Envoi.Valider(); err != nil {
		return err
	}
	if r.VolumeGio < 0 {
		return fmt.Errorf("the volume size cannot be negative (%d GiB)", r.VolumeGio)
	}
	if r.QuotaDefautGio < 1 {
		return fmt.Errorf("the default quota must be at least 1 GiB (%d GiB)", r.QuotaDefautGio)
	}
	if r.VolumeGio > 0 && r.QuotaDefautGio > r.VolumeGio {
		return fmt.Errorf("the default quota (%d GiB) cannot exceed the volume size (%d GiB): "+
			"a mailbox would not fit in the store", r.QuotaDefautGio, r.VolumeGio)
	}
	return nil
}

// serveurJSON is the wire format of `mail.server`.
//
// POINTERS, because "absent" and "zero" mean different things: an absent
// volume_gio means KEEP the claim in place (an installation that has 30 GiB
// must not be silently asked for 20), while a stored 0 is refused.
type serveurJSON struct {
	Envoi           string `json:"envoi,omitempty"`
	VolumeGio       *int   `json:"volume_gio,omitempty"`
	QuotaDefautGio  *int   `json:"quota_defaut_gio,omitempty"`
	ClientsExternes *bool  `json:"clients_externes,omitempty"`
}

// JSON renders the settings for the ConfigMap.
func (r Reglages) JSON() (string, error) {
	brut := serveurJSON{Envoi: r.Envoi.Mode}
	if r.VolumeGio > 0 {
		v := r.VolumeGio
		brut.VolumeGio = &v
	}
	if r.QuotaDefautGio > 0 {
		q := r.QuotaDefautGio
		brut.QuotaDefautGio = &q
	}
	c := r.ClientsExternes
	brut.ClientsExternes = &c
	octets, err := json.Marshal(brut)
	if err != nil {
		return "", err
	}
	return string(octets), nil
}

// LireServeur decodes `mail.server`, filling the absent fields with the
// defaults. The boolean says whether anything was stored at all.
func LireServeur(brut string) (Reglages, bool, error) {
	r := ReglagesParDefaut()
	if strings.TrimSpace(brut) == "" {
		return r, false, nil
	}
	var st serveurJSON
	if err := json.Unmarshal([]byte(brut), &st); err != nil {
		return r, true, fmt.Errorf("mail: the %s entry is not valid JSON: %w", CleServeur, err)
	}
	if st.Envoi != "" {
		r.Envoi.Mode = st.Envoi
	}
	if st.VolumeGio != nil {
		r.VolumeGio = *st.VolumeGio
	}
	if st.QuotaDefautGio != nil {
		r.QuotaDefautGio = *st.QuotaDefautGio
	}
	if st.ClientsExternes != nil {
		r.ClientsExternes = *st.ClientsExternes
	}
	return r, true, nil
}

// Relais is the relay as stored in `mail.relay`.
type Relais struct {
	Hote        string
	Port        int
	Utilisateur string
}

// LireRelais decodes `mail.relay`. The stored form is a map of strings (the
// module form stores every field as text), so the port is parsed rather than
// unmarshalled as a number.
func LireRelais(brut string) (Relais, error) {
	r := Relais{Port: 587}
	if strings.TrimSpace(brut) == "" {
		return r, nil
	}
	stoc := map[string]string{}
	if err := json.Unmarshal([]byte(brut), &stoc); err != nil {
		return r, fmt.Errorf("mail: the %s entry is not valid JSON: %w", CleRelais, err)
	}
	r.Hote = strings.TrimSpace(stoc["hote"])
	r.Utilisateur = strings.TrimSpace(stoc["utilisateur"])
	if p := strings.TrimSpace(stoc["port"]); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return r, fmt.Errorf("mail: the %s entry has a non-numeric port (%q)", CleRelais, p)
		}
		r.Port = port
	}
	return r, nil
}

// LireReglages reads the stored configuration from the cluster.
//
// IT DOES NOT FAIL WHEN NOTHING IS STORED: an installation made before the
// settings page existed has no `mail.server` entry, and it must keep deploying
// with the historical defaults rather than refusing to deploy at all.
//
// THE RELAY PASSWORD IS READ SEPARATELY, and its absence is not an error here:
// a direct installation has no use for it, and a relais installation discovers
// the problem in `Valider` with a message that says where to store it.
func LireReglages(ctx context.Context) (Reglages, error) {
	client, err := clientK8s()
	if err != nil {
		return Reglages{}, fmt.Errorf("mail settings: %w", err)
	}
	donnees, err := client.LireConfigMap(ctx, nsReglages, "ceffio-settings")
	if err != nil {
		return Reglages{}, fmt.Errorf("mail settings: %w", err)
	}
	return reglagesDepuis(ctx, donnees)
}

// nsReglages is where the suite's settings ConfigMap lives.
const nsReglages = "ceffio-system"

// reglagesDepuis is the pure part of the read, so a test can present a
// ConfigMap without a cluster.
func reglagesDepuis(ctx context.Context, donnees map[string]string) (Reglages, error) {
	if donnees == nil {
		return ReglagesParDefaut(), nil
	}
	cfg, _, err := LireServeur(donnees[CleServeur])
	if err != nil {
		return Reglages{}, err
	}

	// The relay's ordinary fields are shared with `mail.server`'s mode: the
	// password never appears in a ConfigMap, so it is fetched from the vault.
	if cfg.Envoi.Mode == ModeRelais || donnees[CleRelais] != "" {
		relais, err := LireRelais(donnees[CleRelais])
		if err != nil {
			return Reglages{}, err
		}
		cfg.Envoi.Hote = relais.Hote
		cfg.Envoi.Port = relais.Port
		cfg.Envoi.Utilisateur = relais.Utilisateur
		cfg.Envoi.MotDePasse = motDePasseRelais(ctx)
	}
	return cfg, nil
}

// motDePasseRelais reads the relay credential from OpenBao.
//
// BEST EFFORT, deliberately: this function is called on the `direct` path too
// (to keep one code path), and a vault that is momentarily unreadable must not
// make a direct deployment fail — while a relais deployment will fail a moment
// later on the empty password, with a message that names the vault.
func motDePasseRelais(ctx context.Context) string {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return ""
	}
	val, err := secrets.LireEntreeCoffre(ctx, cfg, "mail", "relay")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(val["mot_de_passe"])
}
