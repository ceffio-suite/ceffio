// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package files

// The files module's SETTINGS: how NEXTCLOUD ITSELF sends its mail.
//
// WHY THIS MOVED HERE: the SMTP page was written by hand in the console — the
// form, its validation, its check, its storage. It worked, and it was a console
// change that every future feature with settings would have had to imitate. The
// module now DECLARES the group, and every frontend serves it.
//
// WHAT IT CONFIGURES, precisely: the mail Nextcloud sends on its own — share
// invitations, notifications, password resets. It is NOT the same thing as the
// Stalwart relay (which carries mail BETWEEN domains, and is the mail module's
// business): confusing the two is why an operator can fix one and still receive
// no invitation.
//
// WHERE THE CREDENTIAL IS STORED, AND WHY IT DOES NOT MOVE: the vault path
// `smtp/relais`, which is what the console already wrote and what `ceffio mail`
// reads. An existing installation therefore finds its password where it already
// is, with no migration. The value ALSO goes into Nextcloud's own config, which
// only `occ` can write — that is how Nextcloud works, and there is no other
// supported path.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// groupeSmtp is the settings group this module declares.
	groupeSmtp = "outgoing_mail"

	// ComposantCoffre and SousCheminCoffre are the vault coordinates of the
	// relay credential — the SAME entry the console wrote and `ceffio mail`
	// reads. Moving it would lose the password of every existing installation.
	ComposantCoffre  = "smtp"
	SousCheminCoffre = "relais"
)

// Settings declares the group.
//
// THE FIELD NAMES FOLLOW SmtpConfig EXACTLY — hote, port, securite, utilisateur,
// mot_de_passe, expediteur — so the values already stored, the page that reads
// them and the CLI that writes them agree without translation. A renamed field
// would be a silent migration of every installation's configuration.
func (m *filesModule) SettingsOfSmtp() []module.Group {
	return []module.Group{{
		ID:    groupeSmtp,
		Title: "Outgoing mail (Nextcloud)",
		Description: "How Nextcloud sends its own mail: share invitations, notifications, password " +
			"resets. This is NOT the Stalwart relay, which carries mail between domains — that one " +
			"is the mail module's business.",
		Fields: []module.Field{
			{
				Key:      "hote",
				Label:    "Relay host",
				Help:     "Hostname of the SMTP server Nextcloud sends through.",
				Type:     module.Text,
				Required: true,
			},
			{
				Key:     "port",
				Label:   "Port",
				Help:    "587 for STARTTLS, 465 for implicit TLS, 25 only if the network allows it.",
				Type:    module.Number,
				Default: "587",
			},
			{
				Key:   "securite",
				Label: "Security",
				Help:  "STARTTLS upgrades a plain connection; SSL wraps it from the first byte. \"None\" sends the credential in clear text and should not leave a private network.",
				Type:  module.Choice,
				Options: []module.Option{
					{Value: "tls", Label: "STARTTLS (port 587)"},
					{Value: "ssl", Label: "SSL/TLS (port 465)"},
					{Value: "aucune", Label: "None (do not use over the Internet)"},
				},
				Default: "tls",
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
				Key:      "expediteur",
				Label:    "Sender address",
				Help:     "The local part Nextcloud writes in From, for example no-reply. The domain is filled in from the installation.",
				Type:     module.Text,
				Required: true,
				Pattern:  `^[A-Za-z0-9._%+-]+$`,
			},
			{
				Key:   "nom_expediteur",
				Label: "Sender name",
				Help:  "The display name recipients see, for example \"Company cloud\".",
				Type:  module.Text,
			},
		},
	}}
}

// Current reads the group's values.
//
// THE VALUES COME FROM NEXTCLOUD ITSELF, through `occ config:list system`, then
// each key individually — that is where the configuration actually lives, and a
// copy in the store could disagree with what the mail server is really using.
// The password comes from the vault and answers the placeholder.
func (m *filesModule) CurrentSmtp(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != groupeSmtp {
		return nil, fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}

	// A read without a Nextcloud that answers returns the declared defaults:
	// the form must draw on an installation whose pods are down, which is
	// exactly when an operator wants to look at the configuration.
	out := module.Values{
		"hote": "", "port": "587", "securite": "tls", "utilisateur": "",
		"mot_de_passe": "", "expediteur": "", "nom_expediteur": "",
	}
	if env.Kube == nil {
		return out, nil
	}

	// Each key is read individually: `config:list system` MASKS the mail_smtp*
	// keys (they carry the username, treated as sensitive), so the map is
	// incomplete and the individual read is the only one that gives the value.
	for cle, cible := range map[string]string{
		"mail_smtphost":     "hote",
		"mail_smtpport":     "port",
		"mail_smtpsecure":   "securite",
		"mail_smtpname":     "utilisateur",
		"mail_from_address": "expediteur",
		"mail_domain":       "nom_expediteur",
	} {
		if v := lireOcc(ctx, env, "config:system:get", cle); v != "" {
			out[cible] = v
		}
	}
	// Nextcloud writes an empty secure value for "none", and the form expects
	// the literal the operator chose.
	if out["securite"] == "" {
		out["securite"] = "aucune"
	}

	// The password: the vault answers the placeholder when it holds one.
	if _, err := secrets.LireEntreeCoffre(ctx, secrets.DepuisEnvironnement(),
		ComposantCoffre, SousCheminCoffre); err == nil {
		if mdp := lireOcc(ctx, env, "config:system:get", "mail_smtppassword"); mdp != "" {
			out["mot_de_passe"] = module.SecretSet
		}
	}
	return out, nil
}

// Apply validates, stores and makes the change effective.
//
// TWO DESTINATIONS: the vault (the credential, where it already lives) and
// Nextcloud's own configuration (everything, through occ — the only supported
// path). The password is written to Nextcloud ONLY when one is given: writing an
// empty value there would erase it, and the relay would start refusing.
func (m *filesModule) ApplySmtp(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if groupe != groupeSmtp {
		return fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	g, _ := m.groupeDeSmtp(groupe)
	if err := module.Validate(g, v); err != nil {
		return err
	}

	// 1. The credential, at the path `ceffio mail` and the console already use.
	if err := ecrireMotDePasse(ctx, env, v); err != nil {
		return err
	}

	// 2. Nextcloud's own configuration.
	port := strings.TrimSpace(v["port"])
	if port == "" {
		port = "587"
	}
	reglages := [][]string{
		{"mail_smtpmode", "smtp"},
		{"mail_smtphost", strings.TrimSpace(v["hote"])},
		{"mail_smtpport", port},
		{"mail_smtpsecure", strings.TrimSpace(v["securite"])},
		{"mail_smtpauth", "1"},
		{"mail_smtpauthtype", "LOGIN"},
		{"mail_smtpname", strings.TrimSpace(v["utilisateur"])},
	}
	if e := strings.TrimSpace(v["expediteur"]); e != "" {
		reglages = append(reglages, []string{"mail_from_address", e})
	}
	if n := strings.TrimSpace(v["nom_expediteur"]); n != "" {
		reglages = append(reglages, []string{"mail_domain", n})
	}
	// ONLY when one was given: an empty value here would erase the stored one,
	// and Nextcloud would start sending unauthenticated.
	if mdp := strings.TrimSpace(v["mot_de_passe"]); mdp != "" && mdp != module.SecretSet {
		reglages = append(reglages, []string{"mail_smtppassword", mdp})
	}

	for _, r := range reglages {
		if err := ecrireOcc(ctx, env, "config:system:set", r[0], "--value", r[1]); err != nil {
			return fmt.Errorf("setting %q in Nextcloud: %w", r[0], err)
		}
	}
	return nil
}

// Test checks the relay without storing anything.
//
// IT REPRODUCES THE CONSOLE'S CHECK, steps included — that sequence is one of
// the best things about the old page and it must not lose anything: the operator
// sees which of the connection, the TLS handshake and the authentication failed,
// instead of a single "could not send".
func (m *filesModule) TestSmtp(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	if groupe != groupeSmtp {
		return module.TestResult{Detail: "unknown group: " + groupe}
	}

	// The password is NOT in the form when it is already stored: read it back,
	// so a test on an existing configuration does not force a retype.
	mdp := strings.TrimSpace(v["mot_de_passe"])
	if mdp == "" || mdp == module.SecretSet {
		mdp = motDePasseStocke(ctx, env)
	}

	port := 587
	if p := strings.TrimSpace(v["port"]); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	destinataire := strings.TrimSpace(v["expediteur"])

	etapes, err := testerRelais(strings.TrimSpace(v["hote"]), port,
		strings.TrimSpace(v["securite"]), strings.TrimSpace(v["utilisateur"]),
		mdp, strings.TrimSpace(v["expediteur"]), destinataire, 25*time.Second)

	r := module.TestResult{Steps: etapes, OK: err == nil}
	if err != nil {
		r.Detail = err.Error()
		return r
	}
	r.Detail = "the relay accepted the connection and the credentials"
	return r
}

// groupeDeSmtp returns the declared group with that ID.
func (m *filesModule) groupeDeSmtp(id string) (module.Group, bool) {
	for _, g := range m.SettingsOfSmtp() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// --- Vault -----------------------------------------------------------------

func ecrireMotDePasse(ctx context.Context, env module.Env, v module.Values) error {
	mdp := strings.TrimSpace(v["mot_de_passe"])
	// An empty value keeps the stored one; the placeholder is not a value.
	if mdp == "" || mdp == module.SecretSet {
		return nil
	}
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return fmt.Errorf("files: no vault configured: the relay password must be stored in " +
			"OpenBao, which is where `ceffio mail` reads it")
	}
	existants, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil && !estAbsent(err) {
		return err
	}
	if existants == nil {
		existants = map[string]string{}
	}
	// The username travels with the password: the entry is read by the mail
	// layer, which needs both to authenticate.
	if u := strings.TrimSpace(v["utilisateur"]); u != "" {
		existants["utilisateur"] = u
	}
	existants["mot_de_passe"] = mdp
	return secrets.EcrireDansCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre, existants)
}

func motDePasseStocke(ctx context.Context, env module.Env) string {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return ""
	}
	val, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil {
		return ""
	}
	return val["mot_de_passe"]
}

func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "absent") || strings.Contains(s, "not found")
}

// --- occ -------------------------------------------------------------------

func lireOcc(ctx context.Context, env module.Env, args ...string) string {
	out, err := occSortie(ctx, env, args...)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(out)
	if strings.Contains(v, "REMOVED SENSITIVE") {
		return ""
	}
	return v
}

func ecrireOcc(ctx context.Context, env module.Env, args ...string) error {
	_, err := occSortie(ctx, env, args...)
	return err
}

// occSortie runs a php occ command inside the Nextcloud container.
//
// THE SAME HELPER AS THE OLD CONSOLE PAGE, moved here so the module owns its
// own calls: a shared implementation in the console would make the module depend
// on the console, which is the direction the whole chantier forbids.
func occSortie(ctx context.Context, env module.Env, args ...string) (string, error) {
	complet := append([]string{
		"exec", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--",
		"php", "occ",
	}, args...)
	cmd := k8sCommand(ctx, complet...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// testerRelais reproduces the console's SMTP check, steps included.
//
// THE STEPS ARE THE POINT: a check that fails is only useful if the operator
// sees WHERE it failed — "connection refused" and "authentication refused" have
// nothing to do with each other, and a single message would leave them guessing
// between the hostname, the port and the credential.
func testerRelais(hote string, port int, securite, utilisateur, motdepasse, expediteur, destinataire string, delai time.Duration) ([]string, error) {
	var etapes []string

	if hote == "" {
		return etapes, fmt.Errorf("no relay host given")
	}
	adresse := net.JoinHostPort(hote, fmt.Sprint(port))
	etapes = append(etapes, "connecting to "+adresse)

	dialer := &net.Dialer{Timeout: delai}
	var conn net.Conn
	var err error
	if securite == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", adresse, &tls.Config{ServerName: hote})
		if err != nil {
			return append(etapes, "TLS connection failed"), fmt.Errorf("TLS connection to %s: %w", adresse, err)
		}
		etapes = append(etapes, "TLS connection established")
	} else {
		conn, err = dialer.Dial("tcp", adresse)
		if err != nil {
			return append(etapes, "TCP connection failed"), fmt.Errorf("connection to %s: %w", adresse, err)
		}
		etapes = append(etapes, "TCP connection established")
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, hote)
	if err != nil {
		return append(etapes, "SMTP handshake failed"), fmt.Errorf("SMTP handshake with %s: %w", hote, err)
	}
	defer c.Close()
	etapes = append(etapes, "SMTP greeting received")

	if securite == "tls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			etapes = append(etapes, "server does not offer STARTTLS")
			return etapes, fmt.Errorf("the relay does not offer STARTTLS: use SSL (port 465) or none")
		}
		if err := c.StartTLS(&tls.Config{ServerName: hote}); err != nil {
			return append(etapes, "STARTTLS failed"), fmt.Errorf("STARTTLS with %s: %w", hote, err)
		}
		etapes = append(etapes, "STARTTLS established")
	}

	if utilisateur != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			etapes = append(etapes, "server does not offer AUTH")
			return etapes, fmt.Errorf("the relay offers no authentication while a username was given")
		}
		if err := c.Auth(smtp.PlainAuth("", utilisateur, motdepasse, hote)); err != nil {
			return append(etapes, "authentication refused"), fmt.Errorf("authentication refused by %s for %q: %w", hote, utilisateur, err)
		}
		etapes = append(etapes, "authenticated as "+utilisateur)
	}

	// The envelope is checked without sending: a test that delivered a real
	// message would fill a mailbox on every click.
	if expediteur != "" && destinataire != "" {
		if err := c.Mail(expediteur + "@" + hote); err != nil {
			return append(etapes, "sender refused"), fmt.Errorf("the relay refused the sender %q: %w", expediteur, err)
		}
		if err := c.Rcpt(destinataire + "@" + hote); err != nil {
			return append(etapes, "recipient refused"), fmt.Errorf("the relay refused the recipient %q: %w", destinataire, err)
		}
		etapes = append(etapes, "sender and recipient accepted")
	}

	etapes = append(etapes, "nothing was sent: this is a check")
	return etapes, nil
}
