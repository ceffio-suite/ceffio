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
	"regexp"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
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
//
// THE DATA TRAVELS AS JSON IN A SINGLE-QUOTED HEREDOC: <<~'CEFFIO' disables
// interpolation, so nothing in a username or an address can become Ruby code —
// not even "#{...}". json.Marshal never emits a newline, so the terminator
// cannot appear inside the data.
//
// THE NAME: Keycloak's first and last names are not part of module.User, and
// OpenProject requires both. The login fills them; the user can change them in
// OpenProject, and a later ensure never overwrites them.
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
	return `require "json"
d = JSON.parse(<<~'CEFFIO')
` + string(donnees) + `
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
src.onthefly_register = false
src.save!
u = User.find_by(login: d["login"])
if u.nil?
  u = User.new(login: d["login"], mail: d["mail"], firstname: d["login"], lastname: d["login"])
  u.ldap_auth_source = src
  u.admin = d["admin"]
  u.status = User.statuses[:active]
  u.save!
elsif u.ldap_auth_source_id != src.id
  # AN ACCOUNT CREATED BY HAND IN OPENPROJECT is adopted, not duplicated: it
  # becomes reachable through the sign-in and loses nothing it already had.
  u.ldap_auth_source = src
  u.admin = true if d["admin"]
  u.save!
elsif d["admin"] && !u.admin?
  u.update!(admin: true)
end
puts "CEFFIO_OK #{u.id}"
`, nil
}

// scriptSuppression renders the Ruby that deletes one account through
// OpenProject's own service, so its memberships and references are handled the
// way the application handles them. An absent account is the normal case on a
// retry.
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
  r = Users::DeleteService.new(model: u, user: User.system).call
  raise "deletion refused: #{r.errors.full_messages.join(', ')}" unless r.success?
end
puts "CEFFIO_OK"
`, nil
}

// executerRails runs a Ruby script in the web container, with the injected
// secrets sourced (DATABASE_URL lives in /secrets/env, see k8s.AvecSecrets).
//
// THE SCRIPT GOES THROUGH STANDARD INPUT (`rails runner -`): it carries an
// address, and stdin leaves nothing in the process table.
//
// THE MARKER IS CHECKED, not the exit code alone: Rails prints deprecation
// warnings on stderr and a script that raised still prints them — "CEFFIO_OK"
// is the proof the last line ran.
func executerRails(ctx context.Context, cli *k8sapi.Client, script string) error {
	pod, err := cli.PodDuDeploiement(ctx, nsProjets, nomApp, nomApp)
	if err != nil {
		return fmt.Errorf("openproject: no application pod to create the account in: %w", err)
	}
	out, err := cli.ExecuterAvecEntree(ctx, nsProjets, pod, "web", script,
		"bash", "-c", k8s.AvecSecrets("cd /app && bundle exec rails runner -"))
	if err != nil {
		return fmt.Errorf("openproject: rails runner: %w: %.400s", err, out)
	}
	if !strings.Contains(out, "CEFFIO_OK") {
		return fmt.Errorf("openproject: rails runner did not confirm the change: %.400s", out)
	}
	return nil
}

func assurerCompteOpenProject(ctx context.Context, cli *k8sapi.Client, c compteOP) error {
	script, err := scriptCompte(c)
	if err != nil {
		return err
	}
	return executerRails(ctx, cli, script)
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
