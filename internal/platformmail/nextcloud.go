// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package platformmail

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Sortie is where the writers report what they changed.
//
// IT IS A PACKAGE VARIABLE so a test captures the text instead of printing to the
// terminal; production leaves it on stdout, which is what the installer's own
// report uses.
var Sortie io.Writer = os.Stdout

func notifier(format string, args ...any) {
	if Sortie == nil {
		return
	}
	fmt.Fprintf(Sortie, format, args...)
}

// occDans runs `php occ` inside a pod and returns its output.
type occDans func(args ...string) (string, error)

// ApplyNextcloud writes the platform sender into Nextcloud's system configuration.
//
// NEXTCLOUD OWNS THE OUTGOING MAIL OF SHARES, PASSWORD RESETS AND NOTIFICATIONS,
// so a platform whose mail server is installed but whose Nextcloud still points at
// an external relay is a platform where half the mail leaves by another door.
//
// A NIL SENDER CLEARS THE MODE, and only the mode: deleting the transport returns
// Nextcloud to its default (`smtp` to localhost), which sends nothing through the
// platform. Removing every `mail_*` key instead would also erase values an
// operator typed by hand outside Ceffio, which is not this function's business.
func ApplyNextcloud(ctx context.Context, s *Sender) error {
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("connecting to the cluster: %w", err)
	}
	hote := ""
	if s != nil {
		hote = s.Host
	}
	// THE ALIAS COMES FIRST: it rewrites the Deployment, and an exec into a pod
	// that is about to be replaced fails with "pod not found" — a confusing error
	// for a step that had nothing to do with it.
	if err := alignerAlias(ctx, cli, nsFiles, deploiementNextcloud,
		etiquetteNextcloud, conteneurNextcloud, hote); err != nil {
		return fmt.Errorf("applying the platform sender to Nextcloud: %w", err)
	}
	pod, err := cli.PodDuDeploiement(ctx, nsFiles, deploiementNextcloud, etiquetteNextcloud)
	if err != nil {
		return fmt.Errorf("applying the platform sender to Nextcloud: %w", err)
	}
	occ := func(args ...string) (string, error) {
		return cli.Executer(ctx, nsFiles, pod, conteneurNextcloud,
			append([]string{"php", "occ"}, args...)...)
	}
	if s == nil {
		return effacerNextcloud(occ)
	}
	return ecrireNextcloud(s, occ)
}

// reglagesNextcloud is the translation table, kept pure so a test can read it.
//
// `mail_from_address` TAKES THE LOCAL PART and `mail_domain` THE DOMAIN: that is
// what Nextcloud composes the From header from. The previous writer put the
// DISPLAY NAME into `mail_domain`, which produced an address whose domain was
// free text (or, on the default sender, an address as long as the name) — a
// defect that only shows up when Nextcloud actually sends.
//
// `mail_smtpsecure="aucune"` IS KEPT, and it is Nextcloud's "no encryption": the
// value is unknown to Nextcloud's mailer (it treats anything but ssl/tls as
// plaintext), writing it keeps the read-back truthful and the form's three-way
// choice intact.
func reglagesNextcloud(s *Sender) [][2]string {
	return [][2]string{
		{"mail_smtpmode", "smtp"},
		{"mail_smtphost", s.Host},
		{"mail_smtpport", strconv.Itoa(s.Port)},
		{"mail_smtpsecure", securiteVersReglage(s.Security)},
		{"mail_smtpauth", "1"},
		{"mail_smtpauthtype", "LOGIN"},
		{"mail_smtpname", s.User},
		{"mail_from_address", localPart(s.From)},
		{"mail_domain", domaineDe(s.From)},
	}
}

// ecrireNextcloud writes the values and READS EVERY ONE BACK.
//
// The read-back is the whole point: `occ config:system:set` can succeed while the
// value does not land (a typo in the key prints a warning and exits 0), and a
// platform sender that does not apply is invisible until someone opens a share and
// the mail never arrives. Comparing the stored value is what turns that silent
// failure into an error naming the key.
func ecrireNextcloud(s *Sender, occ occDans) error {
	domaine := domaineDe(s.From)
	if domaine == "" {
		return fmt.Errorf("the platform sender %q has no domain, so Nextcloud cannot compose a From address", s.From)
	}
	for _, paire := range reglagesNextcloud(s) {
		cle, valeur := paire[0], paire[1]
		if valeur == "" {
			// AN EMPTY VALUE IS A DELETION, not a write: `config:system:set --value ""`
			// stores an empty string, which Nextcloud reads as "set to nothing".
			if err := supprimerCleOcc(occ, cle); err != nil {
				return err
			}
			continue
		}
		if _, err := occ("config:system:set", cle, "--value", valeur); err != nil {
			return fmt.Errorf("configuring Nextcloud's outgoing mail (%s): %w", cle, err)
		}
		if lu := valeurOcc(occ, cle); lu != valeur {
			return fmt.Errorf("configuring Nextcloud's outgoing mail: %s reads back %q, expected %q",
				cle, lu, valeur)
		}
	}

	// THE PASSWORD IS NEVER REQUIRED: a relay that authenticates by source IP is a
	// real configuration. An empty one DELETES the previous password instead of
	// leaving a stale credential that would make the relay refuse the next mail.
	if s.Password == "" {
		return supprimerCleOcc(occ, "mail_smtppassword")
	}
	if _, err := occ("config:system:set", "mail_smtppassword", "--value", s.Password); err != nil {
		return fmt.Errorf("configuring Nextcloud's outgoing mail (mail_smtppassword): %w", err)
	}
	// THE PASSWORD IS NOT READ BACK FOR COMPARISON: Nextcloud masks it in `occ
	// config:system:get` ("REMOVED SENSITIVE VALUE") on some versions, and comparing
	// a masked value would fail every installation. Its presence is what is checked.
	presence, _ := occ("config:system:get", "mail_smtppassword")
	if strings.TrimSpace(presence) == "" {
		return fmt.Errorf("configuring Nextcloud's outgoing mail: mail_smtppassword did not stick")
	}
	notifier("  ∙ Nextcloud sends through %s:%d (%s)\n", s.Host, s.Port, s.Security)
	return nil
}

// effacerNextcloud removes the sender, leaving Nextcloud with no working transport.
func effacerNextcloud(occ occDans) error {
	if err := supprimerCleOcc(occ, "mail_smtpmode"); err != nil {
		return err
	}
	notifier("  ∙ Nextcloud no longer has an outgoing mail server configured\n")
	return nil
}

// supprimerCleOcc deletes a system-config key, and does nothing when it is
// already absent — `occ config:system:delete` on a missing key prints an error,
// which would fail an installation that is simply already in the wanted state.
func supprimerCleOcc(occ occDans, cle string) error {
	if valeurOcc(occ, cle) == "" {
		return nil
	}
	if _, err := occ("config:system:delete", cle); err != nil {
		return fmt.Errorf("removing Nextcloud's outgoing mail setting %s: %w", cle, err)
	}
	if lu := valeurOcc(occ, cle); lu != "" {
		return fmt.Errorf("removing Nextcloud's outgoing mail setting %s: it reads back %q", cle, lu)
	}
	return nil
}

// valeurOcc reads one system-config key; absent, unreadable and masked all read
// as "" — the three answer the same question ("is there a value?").
func valeurOcc(occ occDans, cle string) string {
	out, err := occ("config:system:get", cle)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(out)
	if strings.Contains(v, "REMOVED SENSITIVE") {
		return ""
	}
	return v
}
