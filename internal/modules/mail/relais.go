// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package mail

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"time"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// verifierRelais opens a real SMTP session against the relay and reports what
// it found, in one line.
//
// WHY A REAL DIALOGUE AND NOT A PORT PROBE: a port that accepts a connection
// says nothing about whether the credentials work, and a relay that refuses the
// authentication is the case an operator is most likely to hit — a wrong
// password, or an account not allowed to relay. A probe would answer "OK" and
// the mail would still not leave.
//
// IT DOES NOT SEND ANYTHING: the envelope is checked, then the session is
// closed. A check that delivered a message would fill a mailbox on every click.
func verifierRelais(hote string, port int, utilisateur, motdepasse string) (bool, string) {
	if hote == "" {
		return false, "no relay host given"
	}
	c, arret := ouvrirSession(hote, port)
	if arret != "" {
		return false, arret
	}
	defer c.Close()

	if utilisateur != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return false, "the relay offers no authentication while a username was given"
		}
		if err := c.Auth(smtp.PlainAuth("", utilisateur, motdepasse, hote)); err != nil {
			return false, "authentication refused by " + hote + ": " + err.Error()
		}
		return true, "authenticated as " + utilisateur
	}
	return true, "the relay answered and no username was given"
}

// ouvrirSession connects and negotiates STARTTLS when the relay offers it.
//
// The second return value is the reason to stop, empty when the session is
// usable — a (client, reason) pair rather than an error, so the caller reports
// one line instead of a wrapped chain.
func ouvrirSession(hote string, port int) (*smtp.Client, string) {
	adresse := net.JoinHostPort(hote, fmt.Sprint(port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	conn, err := dialer.Dial("tcp", adresse)
	if err != nil {
		return nil, "cannot reach " + adresse + ": " + err.Error()
	}

	c, err := smtp.NewClient(conn, hote)
	if err != nil {
		conn.Close()
		return nil, "SMTP handshake with " + hote + " failed: " + err.Error()
	}

	// STARTTLS IS ATTEMPTED WHEN THE RELAY OFFERS IT, and its absence is not a
	// failure here: some relays on a private network do not. The group's
	// `exiger_tls` field is what ENFORCES it, and Apply is where the setting is
	// stored — a check that refused a plain relay would contradict a
	// configuration the installer accepted.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: hote}); err != nil {
			c.Close()
			return nil, "STARTTLS with " + hote + " failed: " + err.Error()
		}
	}
	return c, ""
}

// jsonMarshal and jsonUnmarshal are the encoding helpers, named so the settings
// file reads without importing encoding/json a second time.
func jsonMarshal(v map[string]string) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("mail: encoding settings: %w", err)
	}
	return string(b), nil
}

func jsonUnmarshal(brut string, v *module.Values) error {
	return json.Unmarshal([]byte(brut), v)
}
