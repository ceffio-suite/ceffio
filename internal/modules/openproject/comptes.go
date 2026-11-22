// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// The module's part in the Users page (module.Accounts).
//
// # Why OpenProject accounts must be created at all
//
// Header SSO only LOGS IN an account that exists (auth_source_sso.rb redirects
// to a failure page when the login matches nobody). So creating a Ceffio user
// creates its OpenProject account, and a user created before the module was
// installed gets a "create" action on the page.
//
// # How an account is created
//
// Through Rails, in the application pod (`rails runner`), and not with SQL:
// OpenProject's validations, defaults and callbacks (preferences, notification
// settings) belong to the application. Each account is linked to an LDAP auth
// source named "Ceffio SSO": the link is what marks the account as
// authenticated from outside, and it leaves the account WITHOUT a password, so
// the OpenProject login form cannot be used against it.
//
// # The lookup the link triggers
//
// A linked account is not enough: OpenProject resolves the header's login
// THROUGH THE AUTH SOURCE, by an LDAP search (auth_source_sso.rb →
// LdapAuthSource.find_user). A source pointing at nothing makes every sign-in
// fail with
//
//	Error during authentication: Connection refused - connect(2) for 127.0.0.1:389
//
// which is what this module did until it shipped a responder: the source now
// names openproject-ldap, one pod answering that one search from the query
// itself (repondant.go). No directory, no password, no state — the account row
// is still what decides whether the answer opens a session.
//
// # How accounts are listed
//
// With ONE SQL query on the module's database, not Rails: the Users page lists
// every user on each load, and a Rails boot per page load would cost tens of
// seconds. Reading two columns is the database's job.
package openproject

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/sso"
)

var metaGet = metav1.GetOptions{}

func estIntrouvable(err error) bool { return err != nil && apierrors.IsNotFound(err) }

// The Ceffio administrator, provisioned by Install as an OpenProject admin.
// Same identifiers as internal/identity (compteAdminIdentifiant/Email).
const (
	compteAdmin = "adminceffio"
	mailAdmin   = "adminceffio@ceffio.local"
)

// actionCreer is the action offered to a user who has no account yet.
const actionCreer = "create"

// OpenProject user statuses (app/models/principal.rb): 1 active, 2 registered,
// 3 locked, 4 invited.
const (
	statutActif      = 1
	statutVerrouille = 3
)

// reLogin is what a login must look like before it reaches Ruby or SQL.
//
// A LOGIN IS INTERPOLATED NOWHERE — Ruby receives it through JSON, SQL through
// a literal built here — but refusing anything outside Keycloak's own username
// alphabet means the quoting never has to be relied upon.
var reLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$`)

// loginsReserves cannot be provisioned: "admin" is the seeded, LOCKED account,
// and handing it to a Keycloak user of that name would make that user the
// instance administrator.
var loginsReserves = map[string]bool{"admin": true, "system": true, "anonymous": true}

// compteOP is one account to ensure.
type compteOP struct {
	Login string `json:"login"`
	Mail  string `json:"mail"`
	Admin bool   `json:"admin"`
}

func verifierLogin(login string) error {
	if !reLogin.MatchString(login) {
		return fmt.Errorf("openproject: %q is not a username OpenProject can receive "+
			"(letters, digits, '.', '_', '@', '-')", login)
	}
	if loginsReserves[strings.ToLower(login)] {
		return fmt.Errorf("openproject: %q is reserved by OpenProject itself and cannot be "+
			"given to a user", login)
	}
	return nil
}

// scriptCompte renders the Ruby that ensures one account. IDEMPOTENT: it finds
// the account by login and only fills what is missing.
func scriptCompte(c compteOP) (string, error) {
	if err := verifierLogin(c.Login); err != nil {
		return "", err
	}
	if c.Mail == "" {
		return "", fmt.Errorf("openproject: user %q has no e-mail address, and OpenProject "+
			"refuses an account without one — set it on the Users page first", c.Login)
	}
	donnees, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return enteteScript("d", string(donnees)) + corpsCompte("d", false) + `puts "CEFFIO_OK #{u.id}"
`, nil
}

// scriptComptes renders the Ruby that ensures MANY accounts in ONE Rails boot.
// The installation uses it to provision every user of the realm that has no
// account yet (assurerComptesDuRealm).
//
// ONE BOOT FOR ALL OF THEM: `rails runner` spends tens of seconds starting the
// application, so provisioning a hundred users one boot at a time would look
// hung — and be one failure point per user.
//
// ONE FAILURE DOES NOT STOP THE OTHERS: an address already taken in OpenProject
// (two realm accounts sharing one) raises on save!, and every remaining user
// must still get an account. The failures are printed one per line and counted;
// the caller reports them as warnings.
func scriptComptes(comptes []compteOP) (string, error) {
	if len(comptes) == 0 {
		return "", fmt.Errorf("openproject: no account to create")
	}
	for _, c := range comptes {
		if err := verifierLogin(c.Login); err != nil {
			return "", err
		}
		if c.Mail == "" {
			return "", fmt.Errorf("openproject: user %q has no e-mail address, and OpenProject "+
				"refuses an account without one", c.Login)
		}
	}
	donnees, err := json.Marshal(comptes)
	if err != nil {
		return "", err
	}
	return enteteScript("cs", string(donnees)) + `crees = 0
presents = 0
echecs = []
cs.each do |c|
  begin
` + indenter(corpsCompte("c", true), "    ") + `  rescue => e
    echecs << (c["login"] + ": " + e.message)
  end
end
puts "CEFFIO_COMPTES created=#{crees} present=#{presents} failed=#{echecs.size}"
echecs.each { |e| puts "CEFFIO_ECHEC " + e }
puts "CEFFIO_OK"
`, nil
}

// enteteScript returns the preamble shared by every account script: the JSON
// document `donnees`, parsed into the variable `variable`, then the LDAP auth
// source, created or corrected.
//
// ONE RENDERING FOR EVERY PATH: the source block is where a sign-in breaks when
// it is wrong, and two copies of it drift.
//
// THE DATA TRAVELS AS JSON IN A SINGLE-QUOTED HEREDOC: <<~'CEFFIO' disables
// interpolation, so nothing in a username or an address can become Ruby code —
// not even "#{...}". json.Marshal never emits a newline, so the terminator
// cannot appear inside the data.
func enteteScript(variable, donnees string) string {
	return `require "json"
` + variable + ` = JSON.parse(<<~'CEFFIO')
` + donnees + `
CEFFIO
# THE SOURCE POINTS AT THE MODULE'S OWN RESPONDER (repondant.go), and it is
# UPDATED even when it already exists: an installation created by an earlier
# release carries host "127.0.0.1", port 389 — the upstream documentation's
# placeholder for a directory on the same machine — where this module runs
# nothing. Every sign-in then failed with
#   Error during authentication: Connection refused - connect(2) for 127.0.0.1:389
# and the account page could not say why.
src = LdapAuthSource.find_or_initialize_by(name: "Ceffio SSO")
src.host = "` + hoteRespondant() + `"
src.port = ` + strconv.Itoa(portRepondant) + `
src.attr_login = "uid"
# PLAIN LDAP IS DELIBERATE: the traffic never leaves the cluster — one pod
# querying another in the same namespace, and a NetworkPolicy lets only the
# application reach the responder. The default, start_tls, would make the client
# negotiate TLS with a server that speaks no TLS, and the lookup would fail on
# the handshake instead of answering.
src.tls_mode = :plain_ldap
# THE BASE IS NAMED because OpenProject only uses it to build the answer's DN: a
# real directory narrows a search with it, the responder echoes it.
src.base_dn = "dc=ceffio"
# ON-THE-FLY REGISTRATION STAYS OFF, and that is deliberate: with it on,
# OpenProject creates the user from the LDAP answer, which carries neither name
# nor address (the responder serves uid and objectClass by design), so the
# creation fails with "First name can't be blank. Last name can't be blank.
# Email can't be blank." — measured on a live instance. Accounts are created
# here, with the address the person actually has.
src.onthefly_register = false
src.save!
`
}

// corpsCompte is the Ruby that ensures ONE account from the hash held by `h`
// (the variable naming it), against the source in `src`.
//
// `compte` adds the batch counters: the reconciliation reports what it created
// and what was already there, so the installation says what it did instead of
// only that it finished.
//
// THE NAME: Keycloak's first and last names are not part of module.User, and
// OpenProject requires both. The login fills them; the user can change them in
// OpenProject, and a later ensure never overwrites them.
func corpsCompte(h string, compte bool) string {
	cree, present := "", ""
	if compte {
		// THE COUNTERS ARE INCREMENTED EXACTLY ONCE PER ACCOUNT, whichever
		// branch ran: an uncounted branch would make the reconciliation report
		// fewer accounts than it saw.
		cree, present = "  crees += 1\n", "  presents += 1\n"
	}
	return `u = User.find_by(login: ` + h + `["login"])
if u.nil?
  u = User.new(login: ` + h + `["login"], mail: ` + h + `["mail"], firstname: ` + h + `["login"], lastname: ` + h + `["login"])
  u.ldap_auth_source = src
  u.admin = ` + h + `["admin"]
  u.status = User.statuses[:active]
  u.save!
` + cree + `else
  if u.ldap_auth_source_id != src.id
    # AN ACCOUNT CREATED BY HAND IN OPENPROJECT is adopted, not duplicated: it
    # becomes reachable through the sign-in and loses nothing it already had.
    u.ldap_auth_source = src
    u.admin = true if ` + h + `["admin"]
    u.save!
  end
  if ` + h + `["admin"] && !u.admin?
    u.update!(admin: true)
  end
` + present + `end
`
}

// indenter prefixes every non-empty line of a script block.
func indenter(corps, prefixe string) string {
	lignes := strings.Split(strings.TrimSuffix(corps, "\n"), "\n")
	for i, l := range lignes {
		if l != "" {
			lignes[i] = prefixe + l
		}
	}
	return strings.Join(lignes, "\n") + "\n"
}

// scriptSuppression renders the Ruby that deletes one account through
// OpenProject's own service, so its memberships and references are handled the
// way the application handles them. An absent account is the normal case on a
// retry.
//
// THE SETTING IS OPENED FOR THE DURATION OF THE CALL. OpenProject decides who
// may delete an account in Users::DeleteContract#deletion_allowed?, which asks
// Setting.users_deletable_by_admins — and that setting ships FALSE. With it
// false, no administrator may delete anybody, so every deletion was refused
// with "may not be accessed." and the account stayed: the console reported a
// failure it could not explain, and a user whose duplicate had to go was stuck.
//
// IT IS RESTORED AFTERWARDS, in an ensure: the setting belongs to the instance,
// not to this script, and leaving it flipped would widen what every
// administrator may delete from then on. The restore runs even when the
// deletion raises, which is why it is an ensure and not a plain reassignment.
func scriptSuppression(login string) (string, error) {
	if err := verifierLogin(login); err != nil {
		return "", err
	}
	donnees, _ := json.Marshal(map[string]string{"login": login})
	return `require "json"
d = JSON.parse(<<~'CEFFIO')
` + string(donnees) + `
CEFFIO
u = User.find_by(login: d["login"])
if u
  precedent = Setting.users_deletable_by_admins
  Setting.users_deletable_by_admins = true
  begin
    r = Users::DeleteService.new(model: u, user: User.system).call
    raise "deletion refused: #{r.errors.full_messages.join(', ')}" unless r.success?
  ensure
    Setting.users_deletable_by_admins = precedent
  end
end
puts "CEFFIO_OK"
`, nil
}

// executerRails runs a Ruby script in the web container, with the injected
// secrets sourced (DATABASE_URL lives in /secrets/env, see k8s.AvecSecrets).
func executerRails(ctx context.Context, cli *k8sapi.Client, script string) error {
	_, err := executerRailsSortie(ctx, cli, script)
	return err
}

// executerRailsSortie is executerRails, returning what the script printed: the
// reconciliation reports its counts there.
//
// THE SCRIPT GOES THROUGH STANDARD INPUT (`rails runner -`): it carries
// addresses, and stdin leaves nothing in the process table.
//
// THE MARKER IS CHECKED, not the exit code alone: Rails prints deprecation
// warnings on stderr and a script that raised still prints them — "CEFFIO_OK"
// is the proof the last line ran.
func executerRailsSortie(ctx context.Context, cli *k8sapi.Client, script string) (string, error) {
	pod, err := cli.PodDuDeploiement(ctx, nsProjets, nomApp, nomApp)
	if err != nil {
		return "", fmt.Errorf("openproject: no application pod to create the account in: %w", err)
	}
	out, err := cli.ExecuterAvecEntree(ctx, nsProjets, pod, "web", script,
		"bash", "-c", k8s.AvecSecrets("cd /app && bundle exec rails runner -"))
	if err != nil {
		return out, fmt.Errorf("openproject: rails runner: %w: %.400s", err, out)
	}
	if !strings.Contains(out, "CEFFIO_OK") {
		return out, fmt.Errorf("openproject: rails runner did not confirm the change: %.400s", out)
	}
	return out, nil
}

func assurerCompteOpenProject(ctx context.Context, cli *k8sapi.Client, c compteOP) error {
	script, err := scriptCompte(c)
	if err != nil {
		return err
	}
	return executerRails(ctx, cli, script)
}

// utilisateursDuRealm is the seam the reconciliation is tested through.
var utilisateursDuRealm = sso.UtilisateursRealm

// comptesDuRealm turns the realm's accounts into the ones OpenProject must
// have, SKIPPING WHAT IT CANNOT REPRESENT — and saying so, because a silent
// skip is a user who will read "Nom d'utilisateur ou mot de passe incorrect"
// and have nothing to act on.
//
// THE ADMINISTRATOR IS STEP 6'S JOB: it is created there as an administrator.
// Reconciling it here would either duplicate the call or, worse, disagree with
// it — one place decides what the administrator is.
func comptesDuRealm(utilisateurs []sso.UtilisateurRealm, out io.Writer) []compteOP {
	comptes := make([]compteOP, 0, len(utilisateurs))
	for _, u := range utilisateurs {
		switch {
		case u.Login == "" || strings.HasPrefix(u.Login, "service-account-"):
			// A CLIENT'S SERVICE ACCOUNT IS NOT A PERSON: it never signs in
			// through the browser, so it needs no OpenProject account.
			continue
		case u.Login == compteAdmin:
			continue
		case !u.Enabled:
			fmt.Fprintf(out, "  ⚠ %s is disabled in Keycloak: no OpenProject account "+
				"(re-run the installation once it is enabled)\n", u.Login)
			continue
		}
		if err := verifierLogin(u.Login); err != nil {
			fmt.Fprintf(out, "  ⚠ %s gets no OpenProject account: %v\n", u.Login, err)
			continue
		}
		if u.Mail == "" {
			fmt.Fprintf(out, "  ⚠ %s gets no OpenProject account: it has no e-mail address "+
				"in Keycloak, and OpenProject refuses an account without one — set it on "+
				"the Users page\n", u.Login)
			continue
		}
		comptes = append(comptes, compteOP{Login: u.Login, Mail: u.Mail})
	}
	return comptes
}

// assurerComptesDuRealm creates the OpenProject account of every user of the
// realm that has none, in ONE Rails boot.
//
// WHY IT EXISTS: header SSO creates no account (docs/openproject.md). A user who
// existed before this module was installed, or who was created straight in
// Keycloak, reached projects.<domain> and read
//
//	Single Sign-On (SSO) pour l'utilisateur "<login>" a échoué: Nom
//	d'utilisateur ou mot de passe incorrect
//
// which names nothing to fix — the account simply did not exist. Creating the
// account when the console creates the user covers the users created from then
// on; this step covers the others, INCLUDING ON AN INSTALLATION CREATED BY AN
// EARLIER RELEASE, because re-running the installation is the upgrade path.
//
// IT IS IDEMPOTENT: the script finds each account by login and fills only what
// is missing, so a second run creates nothing.
func assurerComptesDuRealm(ctx context.Context, cli *k8sapi.Client, out io.Writer) error {
	utilisateurs, err := utilisateursDuRealm(ctx)
	if err != nil {
		return fmt.Errorf("openproject: reading the realm's accounts to provision them: %w", err)
	}
	comptes := comptesDuRealm(utilisateurs, out)
	if len(comptes) == 0 {
		fmt.Fprintf(out, "  no account to create among the realm's %d accounts\n",
			len(utilisateurs))
		return nil
	}
	script, err := scriptComptes(comptes)
	if err != nil {
		return err
	}
	sortie, err := executerRailsSortie(ctx, cli, script)
	if err != nil {
		return err
	}
	resume, echecs := lireResumeComptes(sortie)
	// A FAILED ACCOUNT IS A WARNING, NOT AN INSTALLATION FAILURE: the instance
	// works and the other accounts exist; refusing the whole installation would
	// leave the operator unable to re-apply a working configuration, and the
	// remedy (a distinct address, a missing one) is on the Users page.
	for _, e := range echecs {
		fmt.Fprintf(out, "  ⚠ account not created: %s\n", e)
	}
	if resume != "" {
		fmt.Fprintf(out, "  accounts: %s\n", resume)
	}
	return nil
}

// lireResumeComptes extracts the batch summary and the per-account failures
// printed by scriptComptes.
func lireResumeComptes(sortie string) (resume string, echecs []string) {
	for _, brute := range strings.Split(sortie, "\n") {
		ligne := strings.TrimSpace(brute)
		if apres, ok := strings.CutPrefix(ligne, "CEFFIO_COMPTES "); ok {
			resume = apres
		}
		if apres, ok := strings.CutPrefix(ligne, "CEFFIO_ECHEC "); ok {
			echecs = append(echecs, apres)
		}
	}
	return resume, echecs
}

// litteralSQL quotes a string for SQL. The value was already checked by
// verifierLogin; doubling the quotes is the belt to that braces.
func litteralSQL(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// psqlOpenProject runs SQL on the module's database, as the superuser, in the
// PostgreSQL pod — the path internal/files takes for its own database.
func psqlOpenProject(ctx context.Context, cli *k8sapi.Client, sql string) (string, error) {
	out, err := cli.ExecuterAvecEntree(ctx, pgNS, pgPod, "postgres", sql,
		"psql", "-U", "postgres", "-d", dbName, "-v", "ON_ERROR_STOP=1", "-qtAX", "-F", "\t")
	if err != nil {
		return out, fmt.Errorf("openproject: psql: %w: %.300s", err, out)
	}
	return out, nil
}

// lireComptes reads every OpenProject user's login and status, in one query.
func lireComptes(ctx context.Context, cli *k8sapi.Client) (map[string]int, error) {
	out, err := psqlOpenProject(ctx, cli,
		"SELECT login, status FROM users WHERE type = 'User';\n")
	if err != nil {
		return nil, err
	}
	return analyserComptes(out), nil
}

// analyserComptes parses psql's unaligned output: "login<TAB>status" per line.
// Lines that do not parse are skipped: an unexpected line must not invent an
// account.
func analyserComptes(out string) map[string]int {
	res := map[string]int{}
	for _, ligne := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(ligne), "\t")
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		var statut int
		if _, err := fmt.Sscanf(parts[1], "%d", &statut); err != nil {
			continue
		}
		res[strings.ToLower(parts[0])] = statut
	}
	return res
}

// changerStatut locks or reactivates an account.
//
// SQL, NOT RAILS, and on purpose: the change is one column, the Users page waits
// for it, and locking must work even when the application pod is restarting —
// a deactivated Ceffio user must not keep project access because OpenProject
// happened to be down at that moment. Its sessions end at the next request:
// a locked user fails the header check.
func changerStatut(ctx context.Context, cli *k8sapi.Client, login string, statut int) error {
	if err := verifierLogin(login); err != nil {
		return err
	}
	_, err := psqlOpenProject(ctx, cli, fmt.Sprintf(
		"UPDATE users SET status = %d WHERE type = 'User' AND lower(login) = lower(%s);\n",
		statut, litteralSQL(login)))
	return err
}

// ---------------------------------------------------------------------------
// module.Accounts
// ---------------------------------------------------------------------------

// AccountFields: the account needs nothing beyond what the page already asks.
func (m *openprojectModule) AccountFields(ctx context.Context, env module.Env) []module.AccountField {
	return nil
}

// ValidateAccount refuses, BEFORE Keycloak is touched, a username OpenProject
// would refuse later: a half-created user is what this step exists to prevent.
func (m *openprojectModule) ValidateAccount(ctx context.Context, env module.Env, u module.User, v module.Values) error {
	return verifierLogin(u.Username)
}

// EnsureAccount creates the user's OpenProject account. Idempotent.
func (m *openprojectModule) EnsureAccount(ctx context.Context, env module.Env, u module.User, v module.Values) (module.AccountResult, error) {
	cli, err := nouveauClient()
	if err != nil {
		return module.AccountResult{}, err
	}
	return module.AccountResult{}, assurerCompteOpenProject(ctx, cli, compteOP{
		Login: u.Username, Mail: u.Email,
		// THE CEFFIO ADMINISTRATOR administers OpenProject too; nobody else is
		// made an admin from here — that is OpenProject's own decision.
		Admin: strings.EqualFold(u.Username, compteAdmin),
	})
}

// AccountInfos reports every user's account in one query.
func (m *openprojectModule) AccountInfos(ctx context.Context, env module.Env, users []module.User) (map[string]module.AccountInfo, error) {
	cli, err := nouveauClient()
	if err != nil {
		return nil, err
	}
	comptes, err := lireComptes(ctx, cli)
	if err != nil {
		return nil, err
	}
	res := make(map[string]module.AccountInfo, len(users))
	for _, u := range users {
		statut, ok := comptes[strings.ToLower(u.Username)]
		if !ok {
			// THE USER PREDATES THE MODULE (or the creation failed): offer
			// the one action that fixes it, instead of a silent absence.
			res[u.ID] = module.AccountInfo{
				Present: false,
				Summary: "no OpenProject account",
				Actions: []module.AccountAction{{ID: actionCreer, Label: "Create the OpenProject account"}},
			}
			continue
		}
		info := module.AccountInfo{Present: true, Summary: "OpenProject account"}
		if statut == statutVerrouille {
			info.Suspended = true
			info.Summary = "OpenProject account (locked)"
		}
		res[u.ID] = info
	}
	return res, nil
}

// AccountAction runs the "create" action. Any other id is an error: the page
// and the module disagreeing about an action is a bug.
func (m *openprojectModule) AccountAction(ctx context.Context, env module.Env, u module.User, action string, v module.Values) error {
	if action != actionCreer {
		return fmt.Errorf("openproject: unknown account action %q", action)
	}
	_, err := m.EnsureAccount(ctx, env, u, v)
	return err
}

// SuspendAccount locks the OpenProject account.
func (m *openprojectModule) SuspendAccount(ctx context.Context, env module.Env, u module.User) error {
	cli, err := nouveauClient()
	if err != nil {
		return err
	}
	return changerStatut(ctx, cli, u.Username, statutVerrouille)
}

// ResumeAccount reactivates it.
func (m *openprojectModule) ResumeAccount(ctx context.Context, env module.Env, u module.User) error {
	cli, err := nouveauClient()
	if err != nil {
		return err
	}
	return changerStatut(ctx, cli, u.Username, statutActif)
}

// DeleteAccount deletes the OpenProject account through OpenProject's service.
func (m *openprojectModule) DeleteAccount(ctx context.Context, env module.Env, u module.User) error {
	cli, err := nouveauClient()
	if err != nil {
		return err
	}
	script, err := scriptSuppression(u.Username)
	if err != nil {
		return err
	}
	return executerRails(ctx, cli, script)
}

// The module takes part in the Users page; the compiler checks the contract.
var _ module.Accounts = (*openprojectModule)(nil)
