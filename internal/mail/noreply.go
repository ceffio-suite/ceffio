// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The platform sender: `noreply@<domain>`, its single app password, and the
// vault entry the rest of the platform reads that password from.
//
// WHY A DEDICATED ACCOUNT AT ALL: Nextcloud and Keycloak must send mail from a
// stable address that is not a person's. Reusing the admin mailbox would make
// every notification look like it comes from the administrator and would put
// bounces in an inbox someone reads; a shared SMTP relay account would live
// outside Stalwart, where nothing can revoke it.
//
// WHY APP PASSWORD AND NOT A PASSWORD: the mail domain is attached to the OIDC
// directory, and that directory OWNS the account credentials — writing
// `credentials` in `x:Account/set` is refused with `forbidden` (§9.A). The one
// credential a locally created account can carry is an APP PASSWORD, and its
// secret is returned exactly once at creation — hence the vault, which is its
// only copy.
//
// WHY inbound mail IS DISABLED: a message sent to the sender address must not
// pile up in a mailbox nobody reads. Measured on 1.0.3 (§9.F): with `Merge`
// permissions and `emailReceive` disabled, inbound SMTP accepts the message
// then bounces it with a DSN from `MAILER-DAEMON@<domain>`, and `usedDiskQuota`
// stays at 0 — which is exactly the behaviour a "do not reply" address should
// have.
//
// WHY THE SUBMISSION LOGIN IS THE FRESHNESS PROOF: the app password secret
// cannot be read back (§9.A). The only way to know the copy stored in the vault
// still works is to authenticate with it — and a platform sender that only
// fails on the first Nextcloud notification fails at the worst possible moment,
// far from anyone looking at the mail module.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// The vault entry: `ceffio/mail/noreply` (§4.5). The component is `mail`
	// like the module, and the name is the account: read left to right, an
	// operator knows where the value comes from.
	composantCoffre = "mail"
	entreeCoffre    = "noreply"

	// nomCompteNoreply is the account NAME, not an address: `x:Account/set`
	// takes a name plus a domain, and the server derives the address from them.
	nomCompteNoreply = "noreply"

	// descriptionMotDePasse marks the one app password this step owns. It is
	// also the filter that finds STALE ones to destroy: app passwords are
	// capped at five per account (§9.A), so an old password left behind would
	// eventually make the rotation fail with `overQuota`.
	descriptionMotDePasse = "platform-sender"

	// portSoumission is the SMTPS port, implicit TLS. 465 is the port the plan
	// keeps for the platform sender (§9.E): Nextcloud and Keycloak are both
	// configured with `<mail domain>:465`, so the verification must use it
	// rather than a port chosen for convenience.
	portSoumission = 465
)

// The seams: the vault, and the submission login. They are variables so the
// tests can run without OpenBao and without a mail server; each defaults to the
// real implementation and a test replaces it, restoring it with t.Cleanup.
var (
	lireEntreeCoffre   = secrets.LireEntreeCoffre
	ecrireDansCoffre   = secrets.EcrireDansCoffre
	verifierSoumission = verifierSoumissionReelle
)

// errIdentifiantsRefuses marks a REFUSED authentication, as opposed to a server
// that cannot be reached.
//
// ONLY A REFUSAL JUSTIFIES ROTATING: rotating on a timeout, a closed port or a
// failed TLS handshake would delete a working password because the network was
// down — and the new secret would be unusable for the same reason, while the
// old one is gone for good.
var errIdentifiantsRefuses = errors.New("submission credentials refused")

// AssurerNoreply creates or repairs the platform sender account and its
// credential. It is idempotent: a stored credential that still authenticates is
// kept as is.
//
// THE ORDER OF THE CHECKS IS THE IDEMPOTENCE, and it is deliberate:
//
//  1. the vault entry exists, is complete, and an SMTP login on the submission
//     port accepts it: NOTHING is read from or written to JMAP. This is the
//     path taken on every upgrade replay, and a write per replay would bump the
//     account's modification counter for a credential that has not changed.
//  2. the login is REFUSED: the stored secret is a lie, so the app password is
//     rotated (stale ones destroyed first, because of the five-password cap),
//     the vault is rewritten, and the new secret is verified.
//  3. the submission port cannot be reached, or its certificate cannot be
//     negotiated: the credential is KEPT and the step only warns. A network
//     problem says nothing about the password, and failing here would block a
//     mail installation that is otherwise correct.
//  4. no entry, or an incomplete one: the account is ensured, a password is
//     created, stored, then verified.
func AssurerNoreply(ctx context.Context, domaine string) error {
	// THE VAULT IS NOT OPTIONAL HERE, unlike elsewhere in the platform: the app
	// password secret is returned once and the vault is its only copy. Without
	// a vault, either an existing credential cannot be read, or a new secret
	// would be lost at the end of the call — and `EcrireDansCoffre` silently
	// does nothing when no vault is configured, which would turn that loss into
	// a success message. So this is an error, not a warning.
	coffre := secrets.DepuisEnvironnement()
	if coffre == nil {
		return fmt.Errorf("no vault configured: the platform sender credential lives in ceffio/%s/%s, so the mail module requires OpenBao (BAO_ADDR)",
			composantCoffre, entreeCoffre)
	}

	identifiants, err := lireEntreeCoffre(ctx, coffre, composantCoffre, entreeCoffre)
	if err != nil && !secrets.EntreeAbsente(err) {
		// AN UNREACHABLE VAULT IS NOT "ABSENT": proceeding would create a new
		// password and rotate a working one that this call cannot read.
		return fmt.Errorf("reading the platform sender credential: %w", err)
	}
	if identifiants == nil {
		identifiants = map[string]string{}
	}
	utilisateur := strings.TrimSpace(identifiants["user"])
	motDePasse := strings.TrimSpace(identifiants["password"])

	if utilisateur != "" && motDePasse != "" {
		err := verifierSoumission(ctx, DomaineMessagerie(domaine), utilisateur, motDePasse)
		switch {
		case err == nil:
			// ONE LINE, AND NOTHING ELSE: this is the nominal replay path, and
			// the install output is read by operators — repeating the account
			// description on every run is noise that hides real changes.
			fmt.Printf("  ✓ platform sender credential unchanged: %s\n", utilisateur)
			return nil
		case errors.Is(err, errIdentifiantsRefuses):
			fmt.Printf("  ∙ platform sender credential refused: rotating the app password\n")
		default:
			// UNREACHABLE IS NOT A REFUSAL, see errIdentifiantsRefuses. The
			// reachability itself is the job of the `smtp` and `tls` checks;
			// here, keeping the credential is the only safe decision.
			fmt.Printf("  ⚠ platform sender credential not verified, kept as is: %v\n", err)
			return nil
		}
	}

	idDomaine, err := chercherID(ctx, "x:Domain/get", "name", domaine)
	if err != nil {
		return fmt.Errorf("reading the mail domain %s: %w", domaine, err)
	}
	if idDomaine == "" {
		// NOT AN EXTERNAL PREREQUISITE: the SSO step creates this domain, so its
		// absence means the installation is genuinely incomplete.
		return fmt.Errorf("the mail domain %s does not exist: the SSO setup did not complete", domaine)
	}

	idCompte, adresse, err := assurerCompteNoreply(ctx, domaine, idDomaine)
	if err != nil {
		return err
	}

	secret, err := poserMotDePassePlateforme(ctx, idCompte)
	if err != nil {
		return err
	}

	// THE VAULT IS WRITTEN ONLY ONCE THE CREDENTIAL EXISTS: writing before would
	// store a password the server never returned, and the next run would test it
	// (failing) and rotate for nothing.
	if err := ecrireDansCoffre(ctx, coffre, composantCoffre, entreeCoffre, map[string]string{
		"user":     adresse,
		"password": secret,
	}); err != nil {
		return fmt.Errorf("storing the platform sender credential: %w", err)
	}

	// A FAILED VERIFICATION IS A WARNING, NOT A FAILURE: rotation runs inside a
	// working mail installation, and the account itself is proven by the JMAP
	// reads above. Returning an error would abort `module install mail` — and
	// the upgrade replay — for a connectivity problem the `smtp` check reports
	// with an actionable message.
	if err := verifierSoumission(ctx, DomaineMessagerie(domaine), adresse, secret); err != nil {
		fmt.Printf("  ⚠ platform sender credential stored but not verified: %v\n", err)
		return nil
	}
	fmt.Printf("  ✓ platform sender ready: %s (submission login accepted)\n", adresse)
	return nil
}

// assurerCompteNoreply ensures the sender account exists in the mail domain and
// returns its identifier with the address to authenticate as.
//
// THE ADDRESS IS READ BACK, NEVER COMPOSED: `emailAddress` is derived by the
// server from the account name and its domain, and a domain attached to an OIDC
// directory can map addresses unexpectedly (the directory's `usernameDomain`,
// §9.B). Composing `noreply@<domain>` here would store a login the server does
// not know, and the rotation would loop for ever.
func assurerCompteNoreply(ctx context.Context, domaine, idDomaine string) (string, string, error) {
	comptes, err := clientJMAP().Get(ctx, "x:Account/get", nil,
		[]string{"id", "name", "domainId", "emailAddress", "permissions"})
	if err != nil {
		return "", "", fmt.Errorf("reading the mail accounts: %w", err)
	}

	idCompte, compte, err := choisirCompteNoreply(comptes, idDomaine)
	if err != nil {
		return "", "", err
	}

	switch {
	case idCompte == "":
		cree, err := creerObjet(ctx, "x:Account/set", map[string]any{
			"@type":       "User",
			"name":        nomCompteNoreply,
			"domainId":    idDomaine,
			"permissions": permissionsNoreply(),
		})
		if err != nil {
			return "", "", fmt.Errorf("creating the platform sender account: %w", err)
		}
		// THE CREATE ANSWER GIVES THE ID ONLY, not the derived fields: the
		// address and the effective permissions must be read back, and they are
		// what the rest of this function judges.
		compte, err = lireCompte(ctx, cree)
		if err != nil {
			return "", "", err
		}
		idCompte = cree
		fmt.Printf("  ∙ platform sender account created: %s@%s\n", nomCompteNoreply, domaine)

	default:
		champs := champsAReparer(compte, idDomaine)
		if len(champs) > 0 {
			if err := majJMAPObjet(ctx, "x:Account/set", idCompte, champs); err != nil {
				return "", "", fmt.Errorf("repairing the platform sender account: %w", err)
			}
			fmt.Println("  ∙ platform sender account repaired")
			// THE ADDRESS MAY FOLLOW THE DOMAIN: repairing `domainId` changes
			// the address the server derives, so the value read before the
			// write cannot be trusted when it is the field that changed.
			if _, change := champs["domainId"]; change {
				compte, err = lireCompte(ctx, idCompte)
				if err != nil {
					return "", "", err
				}
			}
		}
	}

	attendue := nomCompteNoreply + "@" + domaine
	adresse := valeurChaine(compte["emailAddress"])
	if !strings.EqualFold(adresse, attendue) {
		return "", "", fmt.Errorf("the platform sender account reads back with the address %q instead of %q: the credential would not log in as the sender", adresse, attendue)
	}
	return idCompte, adresse, nil
}

// choisirCompteNoreply picks the sender account among the accounts named
// `noreply`, and returns a nil id when there is none.
//
// THE DOMAIN IDENTIFIER DECIDES FIRST: a server can hold accounts with the same
// name in several domains (the admin domain is one), and taking the first match
// would move the wrong account's permissions. A SOLE candidate in another domain
// is still taken, and repaired, rather than duplicated: a second account named
// `noreply` is never what an operator wants, while a moved one is a repair.
func choisirCompteNoreply(comptes []map[string]any, idDomaine string) (string, map[string]any, error) {
	var candidats []map[string]any
	for _, compte := range comptes {
		if valeurChaine(compte["id"]) == "" || valeurChaine(compte["name"]) != nomCompteNoreply {
			continue
		}
		candidats = append(candidats, compte)
	}
	for _, compte := range candidats {
		if valeurChaine(compte["domainId"]) == idDomaine {
			return valeurChaine(compte["id"]), compte, nil
		}
	}
	switch len(candidats) {
	case 0:
		return "", nil, nil
	case 1:
		return valeurChaine(candidats[0]["id"]), candidats[0], nil
	}
	return "", nil, fmt.Errorf("several accounts are named %q and none belongs to the mail domain %s: cannot tell which one is the platform sender", nomCompteNoreply, idDomaine)
}

// lireCompte reads one account back, and fails when it is absent.
//
// A CREATED ACCOUNT THAT DOES NOT READ BACK IS AN ERROR: the write was refused
// silently or the object was deleted between the calls, and continuing would
// store a credential nobody can use.
func lireCompte(ctx context.Context, idCompte string) (map[string]any, error) {
	comptes, err := clientJMAP().Get(ctx, "x:Account/get", []string{idCompte},
		[]string{"id", "name", "domainId", "emailAddress", "permissions"})
	if err != nil {
		return nil, fmt.Errorf("reading the platform sender account: %w", err)
	}
	for _, compte := range comptes {
		if valeurChaine(compte["id"]) == idCompte {
			return compte, nil
		}
	}
	return nil, fmt.Errorf("the platform sender account %s does not read back after it was written", idCompte)
}

// champsAReparer returns the account fields that differ from what the sender
// must carry.
//
// ONLY THE FIELDS THIS STEP OWNS are compared: `emailAddress` is derived by the
// server and cannot be written directly, and comparing it here would produce a
// patch that never empties. An EMPTY patch is what makes the step idempotent.
func champsAReparer(compte map[string]any, idDomaine string) map[string]any {
	champs := map[string]any{}
	if valeurChaine(compte["domainId"]) != idDomaine {
		champs["domainId"] = idDomaine
	}
	if !permissionsNoreplyConformes(compte["permissions"]) {
		champs["permissions"] = permissionsNoreply()
	}
	return champs
}

// permissionsNoreply returns the permissions the sender account must carry.
//
// MERGE, NOT INHERIT: Merge applies the disabled list ON TOP of the account's
// inherited permissions, so the account keeps the right to authenticate and to
// send — the only two things it is for — while reception is refused. Inherit
// would replace the whole permission set, including permissions the server
// grants on account creation.
func permissionsNoreply() map[string]any {
	return map[string]any{
		"@type":               "Merge",
		"disabledPermissions": map[string]any{"emailReceive": true},
	}
}

// permissionsNoreplyConformes reports whether a read-back permission object is
// the one the sender needs.
//
// THE SHAPE IS JUDGED, NOT DEEP-EQUALED: the server may add fields to the
// object it returns (type normalisation, extra enabled entries) without
// changing the effective permissions, and a deep equality would then write on
// every run. What matters is that Merge is the type and that emailReceive is
// the ONLY disabled permission — anything else disabled (authenticate, send)
// would break the account's purpose.
func permissionsNoreplyConformes(brut any) bool {
	permissions, ok := brut.(map[string]any)
	if !ok || valeurChaine(permissions["@type"]) != "Merge" {
		return false
	}
	desactivees, ok := permissions["disabledPermissions"].(map[string]any)
	if !ok || len(desactivees) != 1 {
		return false
	}
	reception, ok := desactivees["emailReceive"].(bool)
	return ok && reception
}

// poserMotDePassePlateforme destroys the sender's stale app passwords and
// creates a fresh one, returning its secret.
//
// It is `poserMotDePasse` with the sender's description: the mailbox accounts
// created for internal users need exactly the same dance with their own
// description (`nextcloud-mail`, comptes.go), and duplicating the cap
// handling twice is how one copy ends up without the read-back.
//
// THE DESTRUCTION COMES FIRST, and it is not hygiene: the account is capped at
// five app passwords (§9.A), so a rotation that created before destroying would
// fail as soon as an operator's own passwords fill the remaining slots. Only
// the ones carrying our description are touched.
func poserMotDePassePlateforme(ctx context.Context, idCompte string) (string, error) {
	return poserMotDePasse(ctx, idCompte, descriptionMotDePasse)
}

// poserMotDePasse destroys the app passwords carrying `description` and
// creates a fresh one, returning its secret.
//
// THE DESCRIPTION IS THE OWNERSHIP MARKER: it is how a stale credential is
// told from one the user created in the WebUI, and only ours are destroyed.
func poserMotDePasse(ctx context.Context, idCompte, description string) (string, error) {
	perimes, err := appPasswordsDescription(ctx, idCompte, description)
	if err != nil {
		return "", err
	}
	if len(perimes) > 0 {
		if err := detruireAppPasswords(ctx, idCompte, perimes, description); err != nil {
			return "", err
		}
		// THE READ-BACK IS THE AUTHORITY (§9.I): 1.0.3 sometimes answers
		// `notDestroyed:notFound` for an object that is already gone, so the
		// destroy response cannot decide whether the cap was freed.
		restants, err := appPasswordsDescription(ctx, idCompte, description)
		if err != nil {
			return "", err
		}
		if len(restants) > 0 {
			return "", fmt.Errorf("the %d stale app password(s) %q are still present after their deletion", len(restants), description)
		}
	}

	corps, err := clientJMAP().Appel(ctx, "x:AppPassword/set", map[string]any{
		// THE accountId IS AT THE REQUEST LEVEL AND IS THE USER ACCOUNT, not
		// the management account the client injects by default: an app
		// password belongs to the account that will authenticate with it.
		"accountId": idCompte,
		"create": map[string]any{
			"p1": map[string]any{"description": description},
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating the app password %q: %w", description, err)
	}
	crees, _ := corps["created"].(map[string]any)
	cree, _ := crees["p1"].(map[string]any)
	secret := valeurChaine(cree["secret"])
	if secret == "" {
		// THE SECRET IS SHOWN ONCE: a create answer without it means the
		// password exists but can never be used. It is left in place on
		// purpose — the next run recognises it by its description and destroys
		// it before creating a usable one.
		return "", fmt.Errorf("the server created the app password %q but returned no secret: it is returned only once, so the credential cannot be stored", description)
	}
	return secret, nil
}

// appPasswordsDescription lists an account's app passwords carrying `description`.
//
// THE accountId IS EXPLICIT HERE: `jmap.Client.Get` injects the MANAGEMENT
// account, and a `x:AppPassword/get` sent with it lists another account's
// passwords — or answers `accountNotFound`. The request-level field is the only
// way to address the user account (§9.A).
func appPasswordsDescription(ctx context.Context, idCompte, description string) ([]string, error) {
	corps, err := clientJMAP().Appel(ctx, "x:AppPassword/get", map[string]any{
		"accountId":  idCompte,
		"ids":        nil,
		"properties": []string{"id", "description"},
	})
	if err != nil {
		return nil, fmt.Errorf("reading the app passwords %q: %w", description, err)
	}
	liste, _ := corps["list"].([]any)
	var ids []string
	for _, element := range liste {
		motDePasse, ok := element.(map[string]any)
		if !ok || valeurChaine(motDePasse["description"]) != description {
			continue
		}
		if id := valeurChaine(motDePasse["id"]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// detruireAppPasswords destroys the given app passwords.
//
// BRUT ON PURPOSE: the refusal of a destroy is not judged here, because the
// caller decides on the read-back (§9.I). A transport failure is still an
// error: it says nothing about the server's state.
func detruireAppPasswords(ctx context.Context, idCompte string, ids []string, description string) error {
	if _, _, err := clientJMAP().AppelBrut(ctx, "x:AppPassword/set", map[string]any{
		"accountId": idCompte,
		"destroy":   ids,
	}); err != nil {
		return fmt.Errorf("deleting the stale app passwords %q: %w", description, err)
	}
	return nil
}

// verifierSoumissionReelle authenticates on the submission port.
//
// IMPLICIT TLS, NOT STARTTLS: port 465 speaks TLS from the first byte. The
// handshake is done HERE, before `smtp.NewClient`, so the client receives a
// `*tls.Conn` — that is how it learns the session is encrypted, and
// `smtp.PlainAuth` refuses to send credentials over a session it believes is
// clear. A STARTTLS upgrade would work too, but it is not what 465 does.
//
// THE CERTIFICATE IS NOT VERIFIED, ON PURPOSE: trust in the platform's
// certificate belongs to the `tls` check (§4.4), and this step runs during an
// installation where the certificate may not have been issued yet. Verifying
// here would report "credentials refused" for a self-signed certificate — the
// POC measured exactly that (§9.A), and it would make the first install rotate
// a password that is perfectly valid.
func verifierSoumissionReelle(ctx context.Context, hote, utilisateur, motDePasse string) error {
	adresse := net.JoinHostPort(hote, strconv.Itoa(portSoumission))
	conn, err := dialTCP(ctx, adresse)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", adresse, err)
	}
	defer conn.Close()
	// A FILTERED PORT ACCEPTS THE CONNECTION AND THEN SAYS NOTHING: without a
	// deadline the SMTP greeting would block for ever, and the module install
	// with it.
	borner(ctx, conn)
	securise := tls.Client(conn, &tls.Config{ServerName: hote, InsecureSkipVerify: true})
	if err := securise.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake with %s: %w", adresse, err)
	}
	client, err := smtp.NewClient(securise, hote)
	if err != nil {
		return fmt.Errorf("SMTP greeting from %s: %w", adresse, err)
	}
	defer client.Close()
	if ok, _ := client.Extension("AUTH"); !ok {
		// NOT A CREDENTIAL PROBLEM: rotating would not make a server that
		// offers no AUTH accept the password.
		return fmt.Errorf("%s offers no AUTH: the platform sender cannot authenticate", adresse)
	}
	if err := client.Auth(smtp.PlainAuth("", utilisateur, motDePasse, hote)); err != nil {
		var refus *textproto.Error
		if errors.As(err, &refus) {
			// A 4xx/5xx AUTH ANSWER IS THE SERVER'S VERDICT ON THE CREDENTIALS
			// (POC measured `454 4.7.0` for a wrong app password, §9.A). This
			// is the only error that justifies a rotation.
			return fmt.Errorf("%w: %w", errIdentifiantsRefuses, err)
		}
		// A DROPPED CONNECTION, A TIMEOUT OR A PROTOCOL MISMATCH says nothing
		// about the password: kept, not rotated.
		return fmt.Errorf("authentication on %s: %w", adresse, err)
	}
	return client.Quit()
}
