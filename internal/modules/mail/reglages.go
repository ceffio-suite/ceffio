// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

// The mail module's SETTINGS: the outbound relay of Stalwart.
//
// WHY THIS MOVED HERE: the relay was configurable ONLY at installation, through
// four flags (--smtp-relais, --smtp-relais-port, --smtp-relais-user,
// --smtp-relais-pass). Changing a relay host meant relaunching the whole
// installation — an operation that redeploys every layer — for a value that
// concerns one line of one configuration.
//
// WHAT IT IS FOR, and why it is indispensable: outbound port 25 is blocked by
// consumer ISPs, so Stalwart cannot deliver to Gmail by itself. The
// authenticated relay on 587 works around that block and provides the reverse
// DNS. Without it the suite receives mail and cannot send any.
//
// FOUND WHILE WRITING THIS, and worth reporting: the password was NEVER STORED.
// `configurerRelais` received it, used it to verify the authentication, and
// forgot it — the relay was never actually written into Stalwart's
// configuration, and the function says so itself ("to be finalized through the
// admin interface"). The credential now goes to OpenBao, at
// `kv/ceffio/mail/relay`, so a restart, a reinstall or a restore does not lose
// it.

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// groupeRelais is the settings group this module declares.
	groupeRelais = "relay"

	// ComposantCoffre and SousCheminCoffre are the vault coordinates of the
	// relay credential.
	//
	// A NEW PATH, and deliberately: the relay password was never stored before,
	// so there is nothing to preserve and no existing installation to migrate.
	// It is named after the module so a backup picks it up with the rest of the
	// mail layer's secrets.
	ComposantCoffre  = "mail"
	SousCheminCoffre = "relay"
)

// Settings declares the group.
func (m *mailModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeRelais,
		Title: "Outbound relay (Stalwart)",
		Description: "Where Stalwart hands its outgoing mail. This is NOT Nextcloud's own mail — " +
			"that one is the files module's business. A relay is indispensable in practice: " +
			"outbound port 25 is blocked by consumer ISPs, so the suite receives mail and cannot " +
			"send any without one.",
		Fields: []module.Field{
			{
				Key:      "hote",
				Label:    "Relay host",
				Help:     "Hostname of the provider's SMTP relay, for example smtp.example.org.",
				Type:     module.Text,
				Required: true,
			},
			{
				Key:     "port",
				Label:   "Port",
				Help:    "587 for an authenticated submission relay. 465 is accepted where the provider offers it.",
				Type:    module.Number,
				Default: "587",
			},
			{
				Key:      "utilisateur",
				Label:    "Username",
				Help:     "The authenticated account on the relay.",
				Type:     module.Text,
				Required: true,
			},
			{
				Key:   "mot_de_passe",
				Label: "Password",
				Help:  "Never sent back to a page: leave empty to keep the stored one.",
				Type:  module.Secret,
			},
			{
				Key:     "exiger_tls",
				Label:   "Require STARTTLS",
				Help:    "Refuses a relay that does not upgrade the connection to TLS. Turning this off sends the credential in clear text.",
				Type:    module.Bool,
				Default: "true",
			},
		},
	}}
}

// Current reads the group's values.
//
// THE VALUES COME FROM THE STORE, and the password answers the placeholder. An
// installation configured through the old flags has nothing stored: the fields
// then come back empty rather than guessing from the environment, because those
// flags are an INSTALLATION-time input and reading them at run time would make a
// page depend on a shell variable.
func (m *mailModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != groupeRelais {
		return nil, fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	out := module.Values{
		"hote": "", "port": "587", "utilisateur": "",
		"mot_de_passe": "", "exiger_tls": "true",
	}

	// The ordinary values come from the common store.
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", "mail.relay")
		if err != nil {
			return nil, err
		}
		if brut != "" {
			stoc := module.Values{}
			if err := jsonUnmarshal(brut, &stoc); err != nil {
				return nil, fmt.Errorf("mail: settings entry is not valid JSON: %w", err)
			}
			for k, v := range stoc {
				if k != "mot_de_passe" {
					out[k] = v
				}
			}
		}
	}

	// The password comes from the vault, and only its presence is reported.
	if _, err := lireRelais(ctx); err == nil {
		val, _ := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
			ComposantCoffre, SousCheminCoffre)
		if val["mot_de_passe"] != "" {
			out["mot_de_passe"] = module.SecretSet
		}
	}
	return out, nil
}

// Apply validates, stores and applies the relay.
//
// THE CREDENTIAL GOES TO THE VAULT, never to a ConfigMap: a password in a
// ConfigMap is readable by anyone who can read the namespace, and it would land
// in every backup in clear text.
func (m *mailModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if groupe != groupeRelais {
		return fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	g, _ := m.groupeDe(groupe)
	if err := module.Validate(g, v); err != nil {
		return err
	}

	// 1. The credential, in the vault. Merged, so an empty field keeps the
	//    stored one and a save that changes the port does not lose the password.
	if err := ecrireRelais(ctx, v); err != nil {
		return err
	}

	// 2. The ordinary values, in the common store.
	ordinaires := map[string]string{}
	for _, cle := range []string{"hote", "port", "utilisateur", "exiger_tls"} {
		ordinaires[cle] = strings.TrimSpace(v[cle])
	}
	if ordinaires["port"] == "" {
		ordinaires["port"] = "587"
	}
	if ordinaires["exiger_tls"] == "" {
		ordinaires["exiger_tls"] = "true"
	}
	if env.Settings != nil {
		poids, err := jsonMarshal(ordinaires)
		if err != nil {
			return err
		}
		if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
			map[string]string{"mail.relay": poids}); err != nil {
			return err
		}
	}
	return nil
}

// Test verifies the relay accepts the connection and the credentials.
//
// IT REUSES THE SMTP CHECK the files module wrote, rather than a second
// implementation: the two check the same thing — a host, a port, a credential —
// and a second implementation would drift, with one of them accepting a
// configuration the other refuses. The check reaches the relay, and it is the
// same proof for both.
func (m *mailModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	if groupe != groupeRelais {
		return module.TestResult{Detail: "unknown group: " + groupe}
	}
	g, _ := m.groupeDe(groupe)
	if err := module.Validate(g, v); err != nil {
		return module.TestResult{Detail: err.Error()}
	}

	// The password is not in the form when it is stored: read it back, so a
	// check on an existing configuration does not force a retype.
	mdp := strings.TrimSpace(v["mot_de_passe"])
	if mdp == "" || mdp == module.SecretSet {
		stocke, _ := lireRelais(ctx)
		mdp = stocke["mot_de_passe"]
	}

	port := 587
	if p := strings.TrimSpace(v["port"]); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	etapes := []string{"checking the relay " + strings.TrimSpace(v["hote"])}
	ok, detail := verifierRelais(strings.TrimSpace(v["hote"]), port,
		strings.TrimSpace(v["utilisateur"]), mdp)
	etapes = append(etapes, detail)

	r := module.TestResult{Steps: etapes, OK: ok, Detail: detail}
	if !ok {
		return r
	}
	r.Detail = "the relay accepted the connection and the credentials"
	return r
}

// groupeDe returns the declared group with that ID.
func (m *mailModule) groupeDe(id string) (module.Group, bool) {
	for _, g := range m.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// --- Vault -----------------------------------------------------------------

func lireRelais(ctx context.Context) (map[string]string, error) {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return map[string]string{}, nil
	}
	val, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil {
		if estAbsent(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	return val, nil
}

func ecrireRelais(ctx context.Context, v module.Values) error {
	mdp := strings.TrimSpace(v["mot_de_passe"])
	if mdp == "" || mdp == module.SecretSet {
		return nil
	}
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return fmt.Errorf("mail: no vault configured: the relay password must be stored in OpenBao, " +
			"never in a ConfigMap, where anyone able to read the namespace could read it")
	}
	existants, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil && !estAbsent(err) {
		return err
	}
	if existants == nil {
		existants = map[string]string{}
	}
	existants["mot_de_passe"] = mdp
	if u := strings.TrimSpace(v["utilisateur"]); u != "" {
		existants["utilisateur"] = u
	}
	if h := strings.TrimSpace(v["hote"]); h != "" {
		existants["hote"] = h
	}
	return secrets.EcrireDansCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre, existants)
}

func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "absent") || strings.Contains(s, "not found")
}
