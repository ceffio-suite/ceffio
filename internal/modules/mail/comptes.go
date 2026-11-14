// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The mail module's participation in the Users page (§4.7): the two creation
// fields it adds, the validation that runs before anything is created, the
// mailbox it provisions, and the actions the page offers on it.
//
// # What is NOT here
//
// The Stalwart side lives in `internal/mail` (`comptes.go`,
// `comptes_nextcloud.go`), because talking to the server is that package's job
// and the module layer's job is the contract: fields, validation order, and the
// translation of a refusal into a sentence an operator can act on. Every JMAP
// and occ call crosses a seam below, so the tests of this file exercise the
// contract without a cluster.
package mail

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	mailcore "github.com/ceffio-suite/ceffio/internal/mail"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// The keys of the fields this module adds to the creation form. They are the
// keys of the stored form and of `--set mail.<key>=<value>`, so they are stable
// snake_case, not labels.
const (
	cleBoite    = "boite"
	cleQuotaGio = "quota_gio"
	// groupeComptes is the synthetic group the two fields are validated
	// against. It is not a Settings group: it exists so the field labels and
	// types are declared once and `module.Validate` does the type checking both
	// frontends would otherwise reimplement.
	groupeComptes = "comptes"
)

// attributInterne marks a user whose mailbox this module owns.
//
// IT IS THE ONLY MARKER, and it is written by `EnsureAccount` through
// `AccountResult`: the module must not write the directory itself (one writer
// per object, and the console owns the platform account).
const attributInterne = "ceffio_kind"

// valeurInterne is what `attributInterne` holds for an internal user.
//
// WHY A STRING AND NOT A BOOLEAN: Keycloak attributes are strings, and the
// page reads them back as strings; "internal" also leaves room for other kinds
// (an alias-only user, an external one) without repurposing a flag.
const valeurInterne = "internal"

// nomsReserves are the local parts the mail server or the outside world already
// means something by (§4.7).
//
// REFUSED BEFORE THE SERVER IS ASKED: `postmaster` and `abuse` are already
// aliases of the admin account (RFC 2142), and letting a user take them would
// either collide with that alias or silently redirect the domain's complaint
// address. The rest are names mail operators, registrars or scanners send to
// automatically, so a user owning one receives third-party traffic.
var nomsReserves = map[string]bool{
	"postmaster":    true,
	"abuse":         true,
	"noreply":       true,
	"no-reply":      true,
	"hostmaster":    true,
	"webmaster":     true,
	"admin":         true,
	"administrator": true,
	"root":          true,
	"mailer-daemon": true,
	"dmarc":         true,
	"security":      true,
	"adminceffio":   true,
}

// nomLocalValide is the local-part rule: two or more characters framed by
// alphanumerics, or exactly one character.
//
// THE EDGES ARE ALNUM ON PURPOSE: a local part may contain dots, underscores
// and dashes, but a leading or trailing one is either a typo (`jean.`) or a
// mail-server convention we do not want to hand to a user (a leading `.` is
// legal SMTP but refused by many clients and by this server).
var nomLocalValide = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62}[a-z0-9]|[a-z0-9])$`)

// THE MAIL SEAMS: the account operations of `internal/mail`. They are variables
// so the contract can be tested against a fake server, and so this file never
// calls the real cluster connection directly.
var (
	lireComptesCourriel     = mailcore.LireComptesCourriel
	adressePriseCourriel    = mailcore.AdressePrise
	assurerCompteCourriel   = mailcore.AssurerCompteCourriel
	assurerMotDePasseCompte = mailcore.AssurerMotDePasseCompte
	supprimerCompteCourriel = mailcore.SupprimerCompteCourriel
	reglerQuotaCompte       = mailcore.ReglerQuotaCompte
	suspendreCompte         = mailcore.SuspendreCompte
	reprendreCompte         = mailcore.ReprendreCompte
	assurerMailNextcloud    = mailcore.AssurerCompteNextcloudMail
	supprimerMailNextcloud  = mailcore.SupprimerCompteNextcloudMail
	checksMessagerie        = mailcore.Checks
)

// AccountFields declares the two inputs of a user creation (§4.7).
//
// THE QUOTA DEFAULT IS READ, NOT CONSTANT: the operator configured a default
// per-mailbox quota in the module settings, and offering anything else would
// make every created user depart from the platform's own policy on the first
// click. A missing or unreadable setting falls back to the built-in default
// rather than failing the page: the field is a convenience, and `ValidateAccount`
// still refuses a quota the volume cannot hold.
func (m *mailModule) AccountFields(ctx context.Context, env module.Env) []module.AccountField {
	return []module.AccountField{
		{
			Field: module.Field{
				Key:   cleBoite,
				Label: "Internal user with a mailbox",
				Help: "Adds a mailbox on " + env.Domain + " and its Nextcloud Mail account. " +
					"The address is <username>@" + env.Domain + ".",
				Type:     module.Bool,
				Default:  "true",
				Required: true,
			},
			// THE EMAIL INPUT DISAPPEARS WHEN THIS IS TRUE: the address is the
			// username on the platform domain, not something the operator types.
			ReplacesEmail: true,
		},
		{
			Field: module.Field{
				Key:   cleQuotaGio,
				Label: "Mailbox quota (GiB)",
				Help: "Between 1 and the size of the mail volume. Raise it for a user who needs " +
					"more, and check the volume's free space in the module's checks.",
				Type:     module.Number,
				Default:  m.quotaDefautCompte(ctx, env),
				Required: true,
			},
		},
	}
}

// quotaDefautCompte returns the stored default quota, as a string for a form
// field.
func (m *mailModule) quotaDefautCompte(ctx context.Context, env module.Env) string {
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", mailcore.CleServeur)
		if err == nil && brut != "" {
			if cfg, _, err := mailcore.LireServeur(brut); err == nil && cfg.QuotaDefautGio > 0 {
				return strconv.Itoa(cfg.QuotaDefautGio)
			}
		}
	}
	return strconv.Itoa(mailcore.QuotaDefautGio)
}

// ValidateAccount refuses a user creation before anything exists (§4.7).
//
// IT RUNS BEFORE KEYCLOAK, and every refusal names the field and the rule,
// because the page shows the message as written: a validation error that says
// "invalid" would leave the operator guessing which input to change.
func (m *mailModule) ValidateAccount(ctx context.Context, env module.Env, u module.User, v module.Values) error {
	boite, err := boiteDemandee(v)
	if err != nil {
		return err
	}
	if !boite {
		// AN EXTERNAL USER KEEPS THEIR OWN ADDRESS, but not one on the platform
		// domain: that domain is what the internal mailboxes serve, and an
		// address there that no mailbox owns receives nothing.
		email := strings.TrimSpace(u.Email)
		if email == "" {
			return fmt.Errorf("%w: %s: a user without a mailbox needs an email address",
				module.ErrInvalidSettings, cleBoite)
		}
		if domaineDeAdresse(email) == env.Domain {
			return fmt.Errorf("%w: %s: %q is on the platform domain, and an address on the platform domain belongs to an internal user",
				module.ErrInvalidSettings, cleBoite, email)
		}
		return nil
	}

	// THE FIELD TYPES FIRST, from the same declarations the forms are drawn
	// from: a quota that is not a whole number must be refused as a quota
	// problem, not as a mysterious failure later.
	if err := module.Validate(m.groupeCompte(), v); err != nil {
		return err
	}
	quota, err := m.quotaDemandee(ctx, env, v)
	if err != nil {
		return err
	}

	nom := strings.TrimSpace(u.Username)
	if err := validerNomLocal(nom); err != nil {
		return err
	}
	// THE ADDRESS MUST BE FREE, as an account address AND as an alias (AdressePrise
	// looks at both): an address that only exists as an alias already receives
	// somebody's mail.
	//
	// EXCEPT WHEN THE MAILBOX IS THIS USER'S OWN. The platform account exists
	// before this module is called, and every step of a creation is idempotent,
	// so a creation stopped half-way — the mailbox there, its credential not —
	// must CONVERGE on the retry the CLI and the page advertise
	// (`cmd/ceffio/users.go`: "run the same command again"). Refusing here would
	// leave a mailbox with no credential and no way to finish it, which is the
	// jail the account contract's ordering exists to prevent. A mailbox bearing
	// the very name we are creating is that user's mailbox — this module names
	// mailboxes after the platform username and nothing else — so completing it
	// duplicates no object and takes nothing from anybody else.
	for _, adresse := range adressesDuNom(nom, env.Domain) {
		titulaire, prise, err := adressePriseCourriel(ctx, adresse)
		if err != nil {
			return fmt.Errorf("checking that the address %s is free: %w", adresse, err)
		}
		if prise && !strings.EqualFold(titulaire, nom) {
			return fmt.Errorf("%w: %s: the address %s is already used by the mailbox %q",
				module.ErrInvalidSettings, cleBoite, adresse, titulaire)
		}
	}

	// THE MESSAGE THE MAIL SERVER CANNOT RECEIVE FOR IS A REASON NOT TO CREATE
	// A MAILBOX: a blocking check is a fact about the deployment (no MX record,
	// port 25 closed, certificate invalid), and provisioning a mailbox behind it
	// would create an object that silently does not work. The error LISTS them,
	// because one run of the checks tab should not be needed to know which.
	bloquants := module.Bloquants(checksMessagerie(ctx, env.Domain))
	if len(bloquants) > 0 {
		return fmt.Errorf("%w: %s: the mail server reports blocking problems: %s",
			module.ErrInvalidSettings, cleBoite, listerChecks(bloquants))
	}

	// THE QUOTA CANNOT EXCEED THE VOLUME: §4.7's rule, and the one thing that
	// keeps an installation from promising a user more space than the disk that
	// holds every mailbox can ever provide.
	volume := m.volumeCompteGio(ctx, env)
	if quota < 1 || quota > volume {
		return fmt.Errorf("%w: %s (%s) must be between 1 and %d, the mail volume size; got %d",
			module.ErrInvalidSettings, cleQuotaGio, "Mailbox quota (GiB)", volume, quota)
	}
	return nil
}

// boiteDemandee reads the `boite` field, defaulting to true when it is absent.
//
// THE DEFAULT IS TRUE because the field's declared default is true: a frontend
// that sends no value for an optional field means "the default", not "no
// mailbox".
func boiteDemandee(v module.Values) (bool, error) {
	brut, ok := v[cleBoite]
	if !ok {
		return true, nil
	}
	brut = strings.TrimSpace(brut)
	if brut == "" {
		return true, nil
	}
	if brut != "true" && brut != "false" {
		return false, fmt.Errorf("%w: %s (Internal user with a mailbox) must be true or false, got %q",
			module.ErrInvalidSettings, cleBoite, brut)
	}
	return brut == "true", nil
}

// quotaDemandee returns the quota of a creation or of a quota action.
func (m *mailModule) quotaDemandee(ctx context.Context, env module.Env, v module.Values) (int, error) {
	brut := strings.TrimSpace(v[cleQuotaGio])
	if brut == "" {
		brut = m.quotaDefautCompte(ctx, env)
	}
	quota, err := strconv.Atoi(brut)
	if err != nil {
		return 0, fmt.Errorf("%w: %s (Mailbox quota (GiB)) must be a whole number, got %q",
			module.ErrInvalidSettings, cleQuotaGio, brut)
	}
	return quota, nil
}

// groupeCompte is the field set of the creation form, for `module.Validate`.
func (m *mailModule) groupeCompte() module.Group {
	return module.Group{
		ID:    groupeComptes,
		Title: "Mailbox",
		Fields: []module.Field{
			{Key: cleBoite, Label: "Internal user with a mailbox", Type: module.Bool, Required: true},
			{Key: cleQuotaGio, Label: "Mailbox quota (GiB)", Type: module.Number, Required: true},
		},
	}
}

// validerNomLocal applies the local-part rule and the reserved names.
func validerNomLocal(nom string) error {
	if nom == "" {
		return fmt.Errorf("%w: %s: the username is required to build the address", module.ErrInvalidSettings, cleBoite)
	}
	if !nomLocalValide.MatchString(nom) {
		return fmt.Errorf("%w: %s: %q is not a valid local part: use lower-case letters, digits, dots, "+
			"underscores or dashes, 1 to 64 characters, starting and ending with a letter or a digit",
			module.ErrInvalidSettings, cleBoite, nom)
	}
	// `..` IS REFUSED EVEN THOUGH THE REGEXP ALLOWS IT: the regexp describes
	// every character, not the sequences, and a consecutive dot is refused by
	// the mail server's own address parser — better here, where the message can
	// name the username.
	if strings.Contains(nom, "..") {
		return fmt.Errorf("%w: %s: the username %q must not contain two consecutive dots",
			module.ErrInvalidSettings, cleBoite, nom)
	}
	if nomsReserves[nom] {
		return fmt.Errorf("%w: %s: the name %q is reserved: it is an operational address of the mail server",
			module.ErrInvalidSettings, cleBoite, nom)
	}
	return nil
}

// adressesDuNom returns the two addresses a user's mailbox would take: the
// directory address of the account and the public alias.
func adressesDuNom(nom, domaine string) []string {
	return []string{nom + "@" + mailcore.DomaineComptes, nom + "@" + domaine}
}

// domaineDeAdresse returns the domain part of an address, lower-cased.
func domaineDeAdresse(adresse string) string {
	_, domaine, ok := strings.Cut(adresse, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(domaine)
}

// volumeCompteGio returns the size of the mail volume, for the quota bound.
//
// THE SIZE IN PLACE WINS over the stored request (the same rule as the server
// settings page): the quota must fit the disk that exists, not the one an
// operator asked for and that the claim has not grown to yet. An unreadable
// setting falls back to the built-in default rather than blocking user
// creation.
func (m *mailModule) volumeCompteGio(ctx context.Context, env module.Env) int {
	if valeurs, err := m.currentServeur(ctx, env); err == nil {
		if n, err := strconv.Atoi(valeurs["volume_gio"]); err == nil && n > 0 {
			return n
		}
	}
	return mailcore.TailleVolumeDefautGio
}

// listerChecks renders the blocking checks of one line, for an error message.
func listerChecks(checks []module.Check) string {
	parties := make([]string, 0, len(checks))
	for _, check := range checks {
		detail := strings.TrimSpace(check.Detail)
		if detail == "" {
			parties = append(parties, check.ID)
			continue
		}
		parties = append(parties, check.ID+" ("+detail+")")
	}
	return strings.Join(parties, "; ")
}

// EnsureAccount provisions the mailbox, its app password, and its Nextcloud
// Mail account (§4.7).
//
// THE ORDER IS THE CONTRACT: the Stalwart account first (the object everything
// else refers to), the credential second (the account must exist for an app
// password to be created for it), the Nextcloud Mail account last (it
// authenticates with that credential, so it cannot come before it). Each step
// is idempotent, so a retry after a failure at any point converges.
func (m *mailModule) EnsureAccount(ctx context.Context, env module.Env, u module.User, v module.Values) (module.AccountResult, error) {
	boite, err := boiteDemandee(v)
	if err != nil {
		return module.AccountResult{}, err
	}
	if !boite {
		return module.AccountResult{}, nil
	}
	quota, err := m.quotaDemandee(ctx, env, v)
	if err != nil {
		return module.AccountResult{}, err
	}
	adresse := u.Username + "@" + env.Domain
	if err := m.provisionnerBoite(ctx, env, u.Username, quota, false); err != nil {
		return module.AccountResult{}, err
	}
	return module.AccountResult{
		Email:      adresse,
		Attributes: map[string]string{attributInterne: valeurInterne},
	}, nil
}

// provisionnerBoite creates or completes one user's mailbox.
//
// `recreation` is the `recreate-mailbox` action: the account is absent and the
// page asked for it back. The steps are identical — the difference is the
// narrative printed for the operator, who needs to know whether the mailbox was
// created or completed.
func (m *mailModule) provisionnerBoite(ctx context.Context, env module.Env, nom string, quota int, recreation bool) error {
	sortie := sortieDe(env)
	adresse := nom + "@" + env.Domain
	if recreation {
		fmt.Fprintf(sortie, "  ∙ mailbox: recreating %s\n", adresse)
	}

	compte, err := assurerCompteCourriel(ctx, nom, env.Domain, quota)
	if err != nil {
		return err
	}
	secret, err := assurerMotDePasseCompte(ctx, nom, compte.Adresse, compte.ID)
	if err != nil {
		return err
	}
	// THE LOGIN IS THE ACCOUNT ADDRESS, THE ADDRESS SHOWN IS THE ALIAS: the user
	// signs in with `<username>@ceffio.local` — the name the SSO directory maps
	// — and their mail is addressed to `<username>@<domain>`.
	if err := assurerMailNextcloud(ctx, nom, adresse, adresse, mailcore.DomaineMessagerie(env.Domain), compte.Adresse, secret); err != nil {
		return err
	}
	fmt.Fprintf(sortie, "  ∙ mailbox: %s ready (quota %d GiB)\n", adresse, quota)
	return nil
}

// AccountInfos reports every user's mailbox in ONE JMAP read (§4.7).
//
// # Which users are "internal"
//
// Three signals, in decreasing order of authority: the attribute this module
// writes, an email on the platform domain, and the existence of an account. The
// last one is what makes an SSO auto-provisioned mailbox visible before Ceffio
// ever wrote its marker: the user signed in to the WebUI, Stalwart created
// `<username>@ceffio.local`, and the page must say so rather than show "no
// mailbox" over an object that exists (§9.B).
func (m *mailModule) AccountInfos(ctx context.Context, env module.Env, users []module.User) (map[string]module.AccountInfo, error) {
	comptes, err := lireComptesCourriel(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string]mailcore.CompteCourriel, len(comptes))
	for _, compte := range comptes {
		index[strings.ToLower(compte.Nom)] = compte
	}

	infos := make(map[string]module.AccountInfo, len(users))
	for _, u := range users {
		compte, present := index[strings.ToLower(u.Username)]
		interne := present ||
			u.Attributes[attributInterne] == valeurInterne ||
			domaineDeAdresse(u.Email) == strings.ToLower(env.Domain)

		info := module.AccountInfo{Present: present}
		if present {
			info.Suspended = compte.Suspendu
			info.Summary = resumeCompte(compte)
			if compte.Suspendu {
				info.Actions = []module.AccountAction{actionReprendreMail()}
			} else {
				info.Actions = []module.AccountAction{actionSuspendreMail()}
			}
			info.Actions = append(info.Actions, actionQuotaMail(), actionSupprimerMail(u.Username))
		} else if interne {
			// INTERNAL BUT ABSENT: the marker or the address says this user has a
			// mailbox, and the server has none. The page offers to create it
			// instead of pretending the user is external.
			info.Summary = "mailbox missing on " + env.Domain
			info.Actions = []module.AccountAction{actionRecreerMail()}
		}
		// AN EXTERNAL USER GETS NO ACTION (D3): this module owns nothing for
		// them, and offering "create a mailbox" on every user list row would turn
		// the page into a bulk-mailbox button.
		infos[u.ID] = info
	}
	return infos, nil
}

// resumeCompte renders "address — usage / quota" for one mailbox, which is what
// the page shows and what tells the operator whether it is the right mailbox.
func resumeCompte(compte mailcore.CompteCourriel) string {
	utilise := tailleLisible(compte.Utilise)
	if compte.Quota <= 0 {
		return fmt.Sprintf("%s — %s / no quota", compte.Adresse, utilise)
	}
	return fmt.Sprintf("%s — %s / %s", compte.Adresse, utilise, tailleLisible(compte.Quota))
}

// tailleLisible formats a byte count in the largest binary unit that reads
// naturally: the page shows usage, not exact bytes.
func tailleLisible(octets int64) string {
	if octets <= 0 {
		return "0 B"
	}
	const unite = 1024
	if octets < unite {
		return fmt.Sprintf("%d B", octets)
	}
	diviseur, exposant := int64(unite), 0
	for n := octets / unite; n >= unite && exposant < 4; n /= unite {
		diviseur *= unite
		exposant++
	}
	valeur := float64(octets) / float64(diviseur)
	unites := "KMGTP"
	if exposant >= len(unites) {
		exposant = len(unites) - 1
	}
	if valeur < 10 {
		return fmt.Sprintf("%.1f %ciB", valeur, unites[exposant])
	}
	return fmt.Sprintf("%.0f %ciB", valeur, unites[exposant])
}

// AccountAction runs one action the page offered (§4.7).
//
// AN UNKNOWN ACTION IS AN ERROR, NOT A NO-OP: the page and the module
// disagreeing about an action id is a bug, and doing nothing would hide it
// behind a success the operator believes.
func (m *mailModule) AccountAction(ctx context.Context, env module.Env, u module.User, action string, v module.Values) error {
	switch action {
	case "suspend":
		return m.suspendreCompteBoite(ctx, env, u)
	case "resume":
		return m.reprendreCompteBoite(ctx, env, u)
	case "quota":
		return m.changerQuota(ctx, env, u, v)
	case "delete-mailbox":
		return m.supprimerBoite(ctx, env, u)
	case "recreate-mailbox":
		quota, err := m.quotaDemandee(ctx, env, v)
		if err != nil {
			return err
		}
		return m.provisionnerBoite(ctx, env, u.Username, quota, true)
	}
	return fmt.Errorf("unknown mailbox action %q for the user %s", action, u.Username)
}

// SuspendAccount refuses the mailbox's logins when the user is deactivated.
//
// AN ABSENT MAILBOX IS NOT AN ERROR: deactivating a user must work whether or
// not they ever had one, and the page calls every module for every user.
func (m *mailModule) SuspendAccount(ctx context.Context, env module.Env, u module.User) error {
	return m.suspendreCompteBoite(ctx, env, u)
}

// ResumeAccount gives the mailbox's logins back when the user is reactivated.
func (m *mailModule) ResumeAccount(ctx context.Context, env module.Env, u module.User) error {
	return m.reprendreCompteBoite(ctx, env, u)
}

// suspendreCompteBoite suspends one user's mailbox, tolerating its absence.
func (m *mailModule) suspendreCompteBoite(ctx context.Context, env module.Env, u module.User) error {
	compte, present, err := compteDe(ctx, u.Username)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := suspendreCompte(ctx, compte.Nom); err != nil {
		return err
	}
	fmt.Fprintf(sortieDe(env), "  ∙ mailbox: %s suspended\n", compte.Adresse)
	return nil
}

// reprendreCompteBoite reactivates one user's mailbox, tolerating its absence.
func (m *mailModule) reprendreCompteBoite(ctx context.Context, env module.Env, u module.User) error {
	compte, present, err := compteDe(ctx, u.Username)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := reprendreCompte(ctx, compte.Nom); err != nil {
		return err
	}
	fmt.Fprintf(sortieDe(env), "  ∙ mailbox: %s reactivated\n", compte.Adresse)
	return nil
}

// changerQuota applies the `quota` action.
//
// THE BOUND IS CHECKED AGAIN, and not only at creation: the volume can have
// been shrunk by an operator, and a quota the disk cannot hold would make the
// server refuse mail in a way nobody asked for.
func (m *mailModule) changerQuota(ctx context.Context, env module.Env, u module.User, v module.Values) error {
	if err := module.Validate(m.groupeCompte(), v); err != nil {
		return err
	}
	quota, err := m.quotaDemandee(ctx, env, v)
	if err != nil {
		return err
	}
	volume := m.volumeCompteGio(ctx, env)
	if quota < 1 || quota > volume {
		return fmt.Errorf("%w: %s (%s) must be between 1 and %d, the mail volume size; got %d",
			module.ErrInvalidSettings, cleQuotaGio, "Mailbox quota (GiB)", volume, quota)
	}
	if err := reglerQuotaCompte(ctx, u.Username, quota); err != nil {
		return err
	}
	fmt.Fprintf(sortieDe(env), "  ∙ mailbox: quota of %s set to %d GiB\n", u.Username, quota)
	return nil
}

// supprimerBoite applies `delete-mailbox` and `DeleteAccount`.
//
// THE NEXTCLOUD SIDE WARNS AND THE STALWART SIDE DECIDES: the mailbox is the
// object the user's address refers to, so its deletion is the operation; the
// Nextcloud Mail account is a client pointed at it, and a failure there leaves
// a broken client row the operator can delete by hand — refusing the whole
// deletion over it would leave the mailbox alive, the opposite of the request.
// The `delete-mailbox` action and the page's own user deletion therefore share
// this path, and the address stays reserved: the marker and the email stay in
// Keycloak (they are the console's, not ours).
func (m *mailModule) supprimerBoite(ctx context.Context, env module.Env, u module.User) error {
	sortie := sortieDe(env)
	compte, present, err := compteDe(ctx, u.Username)
	if err != nil {
		return err
	}
	if !present {
		fmt.Fprintf(sortie, "  ∙ mailbox: %s had none\n", u.Username)
		return nil
	}
	adresse := u.Username + "@" + env.Domain
	if err := supprimerMailNextcloud(ctx, u.Username, adresse); err != nil {
		// THE WARNING NAMES THE CONSEQUENCE: the user's Nextcloud Mail app will
		// show an account that cannot connect until it is deleted by hand.
		fmt.Fprintf(sortie, "  ! Nextcloud Mail account of %s could not be removed: %v — "+
			"delete it from the user's Mail settings\n", u.Username, err)
	}
	if err := supprimerCompteCourriel(ctx, compte.Nom); err != nil {
		return err
	}
	fmt.Fprintf(sortie, "  ∙ mailbox: %s deleted (its address stays reserved)\n", compte.Adresse)
	return nil
}

// DeleteAccount removes the module's objects for a user the page is deleting.
func (m *mailModule) DeleteAccount(ctx context.Context, env module.Env, u module.User) error {
	return m.supprimerBoite(ctx, env, u)
}

// compteDe reads one user's mailbox from the server's account list.
//
// IT READS THE WHOLE LIST rather than looking the account up by name: the
// caller always needs at least two facts about it (the id and the address), and
// one JMAP read answers every question this file asks.
func compteDe(ctx context.Context, nom string) (mailcore.CompteCourriel, bool, error) {
	comptes, err := lireComptesCourriel(ctx)
	if err != nil {
		return mailcore.CompteCourriel{}, false, err
	}
	for _, compte := range comptes {
		if strings.EqualFold(compte.Nom, nom) {
			return compte, true, nil
		}
	}
	return mailcore.CompteCourriel{}, false, nil
}

// actionSuspendreMail is the page's "suspend" action.
func actionSuspendreMail() module.AccountAction {
	return module.AccountAction{ID: "suspend", Label: "Suspend the mailbox"}
}

// actionReprendreMail is the page's "resume" action.
func actionReprendreMail() module.AccountAction {
	return module.AccountAction{ID: "resume", Label: "Reactivate the mailbox"}
}

// actionQuotaMail carries its own input: the new quota.
func actionQuotaMail() module.AccountAction {
	return module.AccountAction{
		ID:    "quota",
		Label: "Change the mailbox quota",
		Fields: []module.Field{{
			Key:      cleQuotaGio,
			Label:    "New quota (GiB)",
			Type:     module.Number,
			Required: true,
		}},
	}
}

// actionSupprimerMail requires the username to be typed: the mailbox's contents
// go with it and nothing can bring them back.
func actionSupprimerMail(nom string) module.AccountAction {
	return module.AccountAction{ID: "delete-mailbox", Label: "Delete the mailbox", Confirm: nom}
}

// actionRecreerMail creates the mailbox of an internal user who lost it.
func actionRecreerMail() module.AccountAction {
	return module.AccountAction{
		ID:    "recreate-mailbox",
		Label: "Create the mailbox",
		Fields: []module.Field{{
			Key:      cleQuotaGio,
			Label:    "Mailbox quota (GiB)",
			Type:     module.Number,
			Required: true,
		}},
	}
}

// sortieDe returns the operation log, discarding it when there is none.
//
// A NIL WRITER IS THE CONSOLE'S NORMAL CASE (it passes the operation log, but a
// test may not), and `fmt.Fprintf` on a nil interface panics — the guard is the
// difference between a silent no-op and a crash in the middle of a user
// creation.
func sortieDe(env module.Env) io.Writer {
	if env.Out == nil {
		return io.Discard
	}
	return env.Out
}
