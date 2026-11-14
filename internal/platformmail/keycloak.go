// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/identity"
)

// executerKcadm runs an authenticated kcadm command in the keycloak pod. It is a
// variable so a test injects canned output instead of a cluster.
var executerKcadm = identity.ExecuterKcadm

// ApplyKeycloak writes the platform sender into the `ceffio` realm's SMTP settings.
//
// KEYCLOAK SENDS THE MAILS NOBODY CAN AFFORD TO LOSE: the invitation that creates an
// account, the password reset, the verification of an address. Left unconfigured, it
// silently drops them; configured with a relay that has since disappeared, it fails
// after a timeout nobody reads. The realm is therefore brought in line with the
// platform sender on every install and every uninstall.
//
// A NIL SENDER EMPTIES `smtpServer` — an empty map, not an absent field. Keycloak's
// realm update ignores fields it is not given (`RepresentationToModel.updateRealm`
// writes each one only when non-null), so "remove the SMTP settings" cannot be
// expressed by omission; it is expressed by an empty map, which leaves the realm
// with no host to connect to.
func ApplyKeycloak(ctx context.Context, s *Sender) error {
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("connecting to the cluster: %w", err)
	}
	hote := ""
	if s != nil {
		hote = s.Host
	}
	// THE ALIAS IS INSTALLED FIRST, for the same reason as Nextcloud's: it can
	// replace the pod, and that pod is where the exec goes.
	if err := alignerAlias(ctx, cli, nsIdentity, deploiementKeycloak,
		etiquetteKeycloak, conteneurKeycloak, hote); err != nil {
		return fmt.Errorf("applying the platform sender to Keycloak: %w", err)
	}

	voulu := chargeKeycloak(s)
	actuel, err := lireSmtpServerKeycloak(ctx)
	if err != nil {
		return fmt.Errorf("applying the platform sender to Keycloak: %w", err)
	}
	if memeSmtpServer(actuel, voulu) {
		notifier("  ∙ Keycloak's outgoing mail is already the platform sender\n")
		return nil
	}

	if err := ecrireSmtpServerKeycloak(ctx, voulu); err != nil {
		return fmt.Errorf("applying the platform sender to Keycloak: %w", err)
	}

	// READ BACK: kcadm exits 0 even when the realm rejects a field it does not
	// know, and the settings page would then show a configured Keycloak that never
	// sends a mail. Comparing what the realm holds is the only proof.
	relu, err := lireSmtpServerKeycloak(ctx)
	if err != nil {
		return fmt.Errorf("applying the platform sender to Keycloak: %w", err)
	}
	if !memeSmtpServer(relu, voulu) {
		return fmt.Errorf("applying the platform sender to Keycloak: the realm reads back %v, expected %v",
			relu, voulu)
	}
	if s == nil {
		notifier("  ∙ Keycloak no longer has an outgoing mail server configured\n")
	} else {
		notifier("  ∙ Keycloak sends through %s:%d (%s)\n", s.Host, s.Port, s.Security)
	}
	return nil
}

// chargeKeycloak is the payload, kept pure so a test reads it without a cluster.
//
// THE FIELDS ARE KEYCLOAK'S OWN SPELLING (`smtpServer` is a Map<String,String>):
// booleans travel as "true"/"false" strings, and `ssl` and `starttls` are mutually
// exclusive — Keycloak picks implicit TLS when `ssl` is true, STARTTLS when
// `starttls` is true and plaintext otherwise.
//
// `fromDisplayName` IS THE PLATFORM NAME, not the operator's relay display name:
// what the recipient sees must say Ceffio whatever infrastructure answers the
// SMTP dialogue.
func chargeKeycloak(s *Sender) map[string]string {
	if s == nil {
		// AN EMPTY MAP, and it is deliberately not nil: `json.Marshal` of a nil map
		// writes `null`, which the realm update ignores — the settings would stay.
		return map[string]string{}
	}
	ssl, starttls := "false", "false"
	switch s.Security {
	case "ssl":
		ssl = "true"
	case "starttls":
		starttls = "true"
	}
	nom := s.FromName
	if nom == "" {
		nom = identity.ReglagesParDefaut().DisplayName
	}
	return map[string]string{
		"host":            s.Host,
		"port":            fmt.Sprintf("%d", s.Port),
		"ssl":             ssl,
		"starttls":        starttls,
		"auth":            "true",
		"user":            s.User,
		"password":        s.Password,
		"from":            s.From,
		"fromDisplayName": nom,
	}
}

// ecrireSmtpServerKeycloak sends the payload to kcadm.
//
// THE DOCUMENT IS A REALM REPRESENTATION THAT CARRIES `smtpServer`, not the bare
// map. `kcadm update realms/<realm> -f` decodes its file into a
// RealmRepresentation and rejects every unknown field, so sending the map itself
// fails with `Unrecognized field "auth"` — the realm then keeps no sender at all,
// which is the silent drop this function exists to prevent. (Found by the live
// upgrade to 0.11.0-rc.1, not by the tests: they read the map's fields directly.)
//
// THE DOCUMENT GOES THROUGH A TEMPORARY FILE, NOT THROUGH `-s`. A `-s` argument puts
// the SMTP password in kcadm's command line, which every process in the pod can read
// (/proc/<pid>/cmdline) for as long as the call lasts; the codebase refuses that
// shape for the bootstrap credential and must refuse it here too. The file is mode
// 0600 and removed in the same shell, and `-f` accepts a partial representation
// exactly like `-s` does.
func ecrireSmtpServerKeycloak(ctx context.Context, charge map[string]string) error {
	doc, err := json.Marshal(struct {
		SmtpServer map[string]string `json:"smtpServer"`
	}{SmtpServer: charge})
	if err != nil {
		return fmt.Errorf("encoding the SMTP settings: %w", err)
	}
	commande := `umask 077; f=$(mktemp) || exit 1; cat > "$f"; ` +
		`/opt/keycloak/bin/kcadm.sh update realms/` + identity.RealmCeffio + ` -f "$f" >/dev/null; ` +
		`rc=$?; rm -f "$f"; exit $rc`
	if _, err := executerKcadm(ctx, nsIdentity, string(doc), commande); err != nil {
		return err
	}
	return nil
}

// lireSmtpServerKeycloak reads the realm's SMTP settings back.
//
// THE WHOLE REALM IS READ, WITHOUT `--fields`. Keycloak 26.8 answers
// `?fields=smtpServer` with `{"smtpServer": {}}`: the server-side field filter
// empties the map it just selected, so the read-back compared "no sender" against a
// realm that had one and every install reported a mismatch it had itself invented.
// Measured on the live demo, 2026-11-14: the same realm answers `--fields
// smtpServer` with `{}` and the plain document with all nine values.
//
// THE FULL DOCUMENT IS SMALL AND CARRIES NO SECRETS: 5 877 bytes on the demo, zero
// `secret` keys, zero `clientId` entries — the realm representation does not expand
// its clients. The only credential in it is `smtpServer.password`, which Keycloak
// masks as `**********`.
//
// A REALM WITH NO SETTINGS ANSWERS `{}` (the field is absent), which decodes to an
// empty map — the same value as an emptied one. Both mean "no sender", which is
// exactly the comparison the caller needs.
func lireSmtpServerKeycloak(ctx context.Context) (map[string]string, error) {
	out, err := executerKcadm(ctx, nsIdentity, "", `/opt/keycloak/bin/kcadm.sh get realms/`+identity.RealmCeffio)
	if err != nil {
		return nil, err
	}
	var doc struct {
		SmtpServer map[string]string `json:"smtpServer"`
	}
	corps := identity.CorpsJSON(out)
	if strings.TrimSpace(corps) == "" {
		// BOUNDED: the document is small but it is not quoted back in full — the
		// caller's error travels into install logs.
		return nil, fmt.Errorf("the realm read-back returned no JSON document: %.200q", strings.TrimSpace(out))
	}
	if err := json.Unmarshal([]byte(corps), &doc); err != nil {
		return nil, fmt.Errorf("decoding the realm's SMTP settings: %w", err)
	}
	// A NIL MAP AND AN EMPTY ONE ARE THE SAME ANSWER here; normalizing avoids a
	// comparison that depends on which of the two the API happened to return.
	if doc.SmtpServer == nil {
		return map[string]string{}, nil
	}
	return doc.SmtpServer, nil
}

// memeSmtpServer compares the fields this package writes, and ONLY those: Keycloak
// keeps whatever else an operator put in the map (an "enabled" flag, a debug
// setting), and a comparison over the whole map would rewrite the realm forever.
//
// THE PASSWORD IS COMPARED, although it never appears in the output of the writers:
// a realm whose password did not land would authenticate with the old one and fail
// to send, which is the failure mode this whole function exists to prevent.
func memeSmtpServer(actuel, voulu map[string]string) bool {
	cles := []string{"host", "port", "ssl", "starttls", "auth", "user", "password", "from", "fromDisplayName"}
	for _, cle := range cles {
		// A MASKED PASSWORD IS "UNKNOWN", NOT "DIFFERENT": Keycloak's realm
		// representation masks some secret values it returns, and comparing the
		// mask would make every read-back fail — the write would then be repeated
		// on every install and reported as a mismatch that does not exist. The
		// password is compared when the API returns it in clear.
		if cle == "password" && masque(actuel[cle]) {
			continue
		}
		if actuel[cle] != voulu[cle] {
			return false
		}
	}
	return true
}

// masque reports whether a value looks like a masked secret.
func masque(v string) bool {
	return v != "" && strings.Trim(v, "*") == ""
}
