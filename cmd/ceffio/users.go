// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

// `ceffio users` manages the users of the platform and the accounts every
// installed module owns for them, from a terminal.
//
// THE CONTRACT IS internal/module/accounts.go (docs/plan-mail.md §4.6): the
// platform account in Keycloak and Nextcloud, then one EnsureAccount per
// module, then each module's result written back. The CLI adds NOTHING to that
// contract — its job is to collect the values, apply the ordering, and say
// clearly what exists when a step fails.
//
// WHY THE ORDERING IS IN THIS FILE AND NOT IN THE MODULES: a module only knows
// its own objects. Only the command knows that the platform account is created
// before provisioning and deleted after it, and that is what keeps a failure
// recoverable by re-running the same command.

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// modulesAll is the registry the commands walk.
//
// WHY A VARIABLE: a test must not depend on what happens to be compiled in
// (internal/console/modules.go has the same seam for the same reason). The
// production value is the registry, and the test replaces it with fakes.
var modulesAll = module.All

// envPourModule builds the Env a module acts on.
//
// WHY A VARIABLE: the production value reads the cluster to build its
// parameters, and a unit test has no cluster. The seam is the module
// environment rather than the modules themselves: it keeps
// modulesComptes in the tested path.
var envPourModule = moduleEnvCLI

// moduleCompte is an installed module that manages platform accounts.
type moduleCompte struct {
	ID  string
	Mod module.Module
	Acc module.Accounts
	Env module.Env
}

// titre is the module's short human name, for messages.
func (c moduleCompte) titre() string {
	return titreModule(c.Mod)
}

// titreModule returns the label a module declares, or its ID.
func titreModule(m module.Module) string {
	if t := strings.TrimSpace(m.Info().Title); t != "" {
		return t
	}
	return m.Info().ID
}

// modulesComptes returns the installed modules that manage accounts, in
// registry order (dependencies first).
//
// ONLY INSTALLED MODULES TAKE PART: provisioning a mailbox for a module that is
// not installed would create an object its own installation then overwrites or
// orphans; and a module that is only "degraded" still counts, because its data
// exists and the user needs their account in it. The registry order matters:
// the modules declare their dependencies, so a module that depends on another
// is provisioned after it.
func modulesComptes(ctx context.Context, domain string) []moduleCompte {
	var comptes []moduleCompte
	for _, m := range modulesAll() {
		acc, ok := module.AccountsOf(m)
		if !ok {
			continue
		}
		info := m.Info()
		env := envPourModule(domain, info.ID)
		etat := m.State(ctx, env)
		if etat.Status != module.Installed && etat.Status != module.Degraded {
			continue
		}
		comptes = append(comptes, moduleCompte{ID: info.ID, Mod: m, Acc: acc, Env: env})
	}
	return comptes
}

// estCompteProtege says whether a name is the platform administration account.
//
// COMPARED WITHOUT CASE, like the console does: Keycloak's usernames are
// case-insensitive, so "AdminCeffio" IS the administration account even though
// it is spelled differently.
func estCompteProtege(nom string) bool {
	return strings.EqualFold(strings.TrimSpace(nom), compteAdmin)
}

// trouverUtilisateur reads one platform account by username.
func trouverUtilisateur(ctx context.Context, nom string) (comptePlateforme, error) {
	compte, existe, err := keycloakParNom(ctx, nom)
	if err != nil {
		return comptePlateforme{}, err
	}
	if !existe {
		return comptePlateforme{}, fmt.Errorf("no platform user named %q", nom)
	}
	return compte, nil
}

// utilisateursModule converts platform accounts to the contract's User.
func utilisateursModule(comptes []comptePlateforme) []module.User {
	out := make([]module.User, 0, len(comptes))
	for _, c := range comptes {
		out = append(out, c.User)
	}
	return out
}

// ---------------------------------------------------------------------------
// command tree

func newUsersCmd() *cobra.Command {
	var domain string

	c := &cobra.Command{
		Use:   "users",
		Short: "Manage the platform users and their module accounts",
		Long: `Lists, creates, deactivates, reactivates and deletes the users of the
platform, and runs the actions a module offers on one user's account.

A user is made of the platform account (Keycloak, the user directory) and the
local account in every installed module that manages accounts — Nextcloud for
the file access, and each module's own objects (a mailbox, for example) for the
rest.

The commands are generic: a module added tomorrow is provisioned, suspended,
resumed and deleted by these commands without editing them, provided it
implements the account contract (internal/module/accounts.go).`,
	}

	// Same production default as `ceffio install` and `ceffio module`.
	c.PersistentFlags().StringVar(&domain, "domain", "ceffio.example.com",
		"Base domain of the installation (e.g. company.fr)")

	c.AddCommand(
		newUsersListCmd(&domain),
		newUsersAddCmd(&domain),
		newUsersDeactivateCmd(&domain),
		newUsersReactivateCmd(&domain),
		newUsersDeleteCmd(&domain),
		newUsersAccountCmd(&domain),
	)
	return c
}

// newUsersListCmd prints the platform users and the accounts they have in the
// modules.
func newUsersListCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the users and the accounts each module owns for them",
		Long: `Prints one line per platform user, with the state of the account in every
installed module that manages accounts.

The module columns are read in ONE batched call per module, not one per user:
a directory with a hundred users would otherwise make a hundred calls into each
module's pod for a single listing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listerUtilisateurs(cmd, *domain)
		},
	}
}

// newUsersAddCmd creates a user and the accounts its modules own.
func newUsersAddCmd(domain *string) *cobra.Command {
	var (
		email    string
		password string
		sets     []string
	)
	c := &cobra.Command{
		Use:   "add USERNAME",
		Short: "Create a user and the accounts the installed modules own for it",
		Long: `Creates the platform account, then lets every installed module provision its
objects, then writes each module's result back to the platform account.

Every module validates BEFORE anything is created: a value it refuses (a name
that is already taken, a quota out of range) fails the whole command while
nothing exists yet.

A module may own the email address (an internal mailbox computes
<username>@<domain>): such a module makes --email meaningless while its
"replaces the address" field is set, and the address it assigns is the one the
platform account ends up with.

The password is generated and printed ONCE when --password is omitted. It can
be provided on standard input with --password -, which keeps it out of the
shell history.

If a step fails after the platform account exists, the same command can be
re-run: it adopts the existing accounts and finishes the provisioning.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ajouterUtilisateur(cmd, *domain, args[0], email, password, sets)
		},
	}
	c.Flags().StringVar(&email, "email", "",
		"Email address of the user (a module may assign it instead)")
	c.Flags().StringVar(&password, "password", "",
		"Password to set; \"-\" reads it from standard input (generated and printed when omitted)")
	c.Flags().StringArrayVar(&sets, "set", nil,
		"Value of a module field, MODULE.KEY=VALUE (repeatable)")
	return c
}

// newUsersDeactivateCmd closes a user's access without deleting anything.
func newUsersDeactivateCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "deactivate USERNAME",
		Short: "Deactivate a user: no session, and its accounts are suspended",
		Long: `Disables the platform account (the user can no longer sign in) and asks
every installed module to suspend its objects — a mailbox that keeps receiving
mail for a deactivated user is a security problem, not a cosmetic one.

Nothing is deleted: "reactivate" gives the user their accounts back.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return changerEtatUtilisateur(cmd, *domain, args[0], false)
		},
	}
}

// newUsersReactivateCmd gives a deactivated user their access back.
func newUsersReactivateCmd(domain *string) *cobra.Command {
	return &cobra.Command{
		Use:   "reactivate USERNAME",
		Short: "Reactivate a deactivated user and its accounts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return changerEtatUtilisateur(cmd, *domain, args[0], true)
		},
	}
}

// newUsersDeleteCmd deletes a user and every account it owns.
func newUsersDeleteCmd(domain *string) *cobra.Command {
	var confirm string
	c := &cobra.Command{
		Use:   "delete USERNAME",
		Short: "Delete a user and every account it owns (irreversible)",
		Long: `Deletes the objects the modules own, then the Nextcloud account, then the
platform account.

THE MODULES GO FIRST: once the platform account is gone, nothing else can reach
their objects — a mailbox whose owner has disappeared is exactly the orphan
this ordering avoids. If a step fails, the platform account is kept so the
command can be run again.

Nothing is deleted without --confirm USERNAME: the confirmation is the username
itself, typed again, because this command has no undo.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return supprimerUtilisateur(cmd, *domain, args[0], confirm)
		},
	}
	c.Flags().StringVar(&confirm, "confirm", "",
		"Type the username again to confirm the deletion")
	return c
}

// newUsersAccountCmd runs one action a module offers on one user's account.
func newUsersAccountCmd(domain *string) *cobra.Command {
	var (
		confirm string
		sets    []string
	)
	c := &cobra.Command{
		Use:   "account USERNAME MODULE ACTION",
		Short: "Run a module's action on one user's account",
		Long: `Runs one of the actions a module declares for a user's account: for
example, emptying a mailbox.

The action and its fields belong to the module, not to the CLI: an action the
module does not offer for this user is refused, and its values are validated by
the module before anything happens. An action that requires a typed
confirmation says so — pass it with --confirm.

The fields of an action are given with --set KEY=VALUE (no module prefix here:
the module is already named by the argument).`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return executerActionCompte(cmd, *domain, args[0], args[1], args[2], confirm, sets)
		},
	}
	c.Flags().StringVar(&confirm, "confirm", "", "Typed confirmation an action may require")
	c.Flags().StringArrayVar(&sets, "set", nil, "Value of an action field, KEY=VALUE (repeatable)")
	return c
}

// ---------------------------------------------------------------------------
// list

// listerUtilisateurs prints the users and their module accounts.
func listerUtilisateurs(cmd *cobra.Command, domain string) error {
	ctx := cmd.Context()
	comptes, err := keycloakLister(ctx)
	if err != nil {
		return fmt.Errorf("listing the users: %w", err)
	}
	sort.Slice(comptes, func(i, j int) bool {
		return strings.ToLower(comptes[i].Username) < strings.ToLower(comptes[j].Username)
	})

	modules := modulesComptes(ctx, domain)
	utilisateurs := utilisateursModule(comptes)
	infos := make(map[string]map[string]module.AccountInfo, len(modules))
	for _, m := range modules {
		// A MODULE THAT FAILS DOES NOT FAIL THE LIST: the platform users are the
		// page's primary data, and hiding them because one module's pod is down
		// would make the command useless for a problem that concerns one column.
		// Its column reports the error instead.
		comptesModule, err := m.Acc.AccountInfos(ctx, m.Env, utilisateurs)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "⚠ %s: accounts unavailable: %v\n", m.titre(), err)
			infos[m.ID] = nil
			continue
		}
		infos[m.ID] = comptesModule
	}

	w := cmd.OutOrStdout()
	if len(comptes) == 0 {
		fmt.Fprintln(w, "No platform user yet. Create one with: ceffio users add <username>")
		return nil
	}

	entetes := []string{"USERNAME", "EMAIL", "STATE"}
	for _, m := range modules {
		entetes = append(entetes, strings.ToUpper(m.ID))
	}
	lignes := make([][]string, 0, len(comptes))
	for _, c := range comptes {
		email := c.Email
		if email == "" {
			email = "—"
		}
		etat := "active"
		if !c.Actif {
			etat = "disabled"
		}
		if estCompteProtege(c.Username) {
			etat += " (protected)"
		}
		ligne := []string{c.Username, email, etat}
		for _, m := range modules {
			ligne = append(ligne, resumeCompte(infos[m.ID][c.ID]))
		}
		lignes = append(lignes, ligne)
	}
	afficherTableau(w, entetes, lignes)
	return nil
}

// resumeCompte renders one module's summary of one account.
//
// ABSENT, SUSPENDED AND PRESENT ARE DISTINCT WORDS rather than symbols: the
// output is read in a terminal and pasted in an issue, and a missing account is
// a different problem from a suspended one.
func resumeCompte(info module.AccountInfo) string {
	if !info.Present {
		return "absent"
	}
	if info.Suspended {
		if info.Summary != "" {
			return "suspended (" + info.Summary + ")"
		}
		return "suspended"
	}
	if info.Summary != "" {
		return info.Summary
	}
	return "present"
}

// afficherTableau prints a left-aligned table.
//
// WHY A PURE FUNCTION TAKING AN io.Writer: the test asserts what the operator
// reads, without capturing the process's stdout. The widths are computed in
// runes, so an accented name or the em dash does not shift a column; they are
// not computed in display cells, which is exact for the ASCII identifiers this
// table holds.
func afficherTableau(w io.Writer, entetes []string, lignes [][]string) {
	largeurs := make([]int, len(entetes))
	for i, e := range entetes {
		largeurs[i] = utf8.RuneCountInString(e)
	}
	for _, l := range lignes {
		for i, c := range l {
			if i < len(largeurs) {
				if n := utf8.RuneCountInString(c); n > largeurs[i] {
					largeurs[i] = n
				}
			}
		}
	}
	ligne := func(cellules []string) {
		var b strings.Builder
		for i, c := range cellules {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(c)
			if i < len(cellules)-1 {
				for n := utf8.RuneCountInString(c); n < largeurs[i]; n++ {
					b.WriteByte(' ')
				}
			}
		}
		fmt.Fprintln(w, b.String())
	}
	ligne(entetes)
	for _, l := range lignes {
		ligne(l)
	}
}

// ---------------------------------------------------------------------------
// add

// participationModule is one installed module and the values its fields take for
// the user being created.
type participationModule struct {
	Compte  moduleCompte
	Champs  []module.AccountField
	Valeurs module.Values
}

// ajouterUtilisateur creates the platform account and provisions every module.
//
// THE ORDER IS THE CONTRACT (docs/plan-mail.md §4.6) and it is the whole point:
// every module validates BEFORE Keycloak is touched, then the platform account
// exists in the systems that authenticate, then each module provisions, then
// each module's result is written back. A refusal that arrives after the
// Keycloak account is created leaves a user with no mailbox and no way to
// retry; a mailbox created before the account exists is an object with no owner.
func ajouterUtilisateur(cmd *cobra.Command, domain, nom, email, motDePasse string, sets []string) error {
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return fmt.Errorf("the username cannot be empty")
	}
	if estCompteProtege(nom) {
		return fmt.Errorf("%q is the platform administration account: it already exists and is not created, deactivated or deleted by this command", nom)
	}
	ctx := cmd.Context()

	// The password is resolved BEFORE any cluster call: reading standard input
	// can fail, and discovering that after the account exists would leave a
	// user with an unknown password.
	mdp, genere, err := motDePasseChoisi(cmd, motDePasse)
	if err != nil {
		return err
	}

	modules := modulesComptes(ctx, domain)
	participations, err := preparerModules(ctx, modules, sets)
	if err != nil {
		return err
	}
	// The VALUES and the effective address are resolved before anything is
	// created, because a module that owns the address changes what the platform
	// account is created with.
	adresse := email
	for _, p := range participations {
		if emailRemplace(p.Champs, p.Valeurs) {
			adresse = ""
		}
	}
	utilisateur := module.User{Username: nom, Email: adresse}

	// 1. VALIDATION, all modules, before Keycloak.
	for _, p := range participations {
		if err := p.Compte.Acc.ValidateAccount(ctx, p.Compte.Env, utilisateur, p.Valeurs); err != nil {
			return fmt.Errorf("user creation: %s: %w", p.Compte.titre(), err)
		}
	}

	// 2. The platform accounts: Keycloak (the directory) then Nextcloud (the
	// fallback door, never allowed to fail the creation — the console applies
	// the same rule, and a Nextcloud outage must not prevent a user from
	// signing in).
	compte, err := keycloakCreer(ctx, utilisateur, mdp)
	if err != nil {
		return fmt.Errorf("user creation: %w", err)
	}
	if err := nextcloudCreer(ctx, nom, mdp); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"⚠ the platform account exists, but its Nextcloud account does not: %v\n", err)
	}

	// 3. Provisioning, 4. write-back.
	type fait struct {
		titre string
		email string
	}
	faits := make([]fait, 0, len(participations))
	for _, p := range participations {
		res, err := p.Compte.Acc.EnsureAccount(ctx, p.Compte.Env, utilisateur, p.Valeurs)
		if err != nil {
			// WHAT EXISTS IS SAID, AND HOW TO FINISH: the platform account is
			// there, so the correct gesture is the same command again — not
			// "delete the user and start over", which is what an operator
			// guesses when the error only says "failed".
			return fmt.Errorf(
				"user %q created; provisioning %s failed: %w — run the same command again to finish the setup (it adopts what already exists)",
				nom, p.Compte.titre(), err)
		}
		if err := ecrireResultatCompte(cmd, ctx, compte.User, p.Compte.titre(), res); err != nil {
			return fmt.Errorf(
				"user %q created and provisioned by %s, but its account could not be updated: %w — run the same command again to finish the setup",
				nom, p.Compte.titre(), err)
		}
		faits = append(faits, fait{titre: p.Compte.titre(), email: res.Email})
		if res.Email != "" {
			adresse = res.Email
		}
	}

	// The summary tells the operator what exists, and shows the generated
	// password exactly once.
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "User %q created (Keycloak id %s).\n", compte.Username, compte.ID)
	if adresse != "" {
		fmt.Fprintf(w, "  Email: %s\n", adresse)
	}
	for _, f := range faits {
		fmt.Fprintf(w, "  %s: account ready\n", f.titre)
	}
	if len(participations) == 0 {
		fmt.Fprintln(w, "  No installed module manages accounts: only the platform account exists.")
	}
	if genere {
		fmt.Fprintf(w, "\nPassword (generated, shown once): %s\n", mdp)
	} else {
		fmt.Fprintln(w, "\nPassword set.")
	}
	return nil
}

// preparerModules reads each module's fields and resolves the values.
//
// THE DEFAULTS COME FIRST, then the --set overrides: a module declares what its
// fields are worth when the operator says nothing, and the operator only writes
// what they want to change.
func preparerModules(ctx context.Context, modules []moduleCompte, sets []string) ([]participationModule, error) {
	surcharges, err := valeursParModule(sets, modules)
	if err != nil {
		return nil, err
	}
	out := make([]participationModule, 0, len(modules))
	for _, m := range modules {
		champs := m.Acc.AccountFields(ctx, m.Env)
		valeurs, err := valeursDe(champs, surcharges[m.ID])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.titre(), err)
		}
		out = append(out, participationModule{Compte: m, Champs: champs, Valeurs: valeurs})
	}
	return out, nil
}

// valeursParModule converts repeated MODULE.KEY=VALUE flags to the contract's
// per-module values, refusing every flag it cannot attribute.
//
// A REFUSED FLAG IS NEVER IGNORED: silently dropping an unknown module or an
// unknown key would create a user whose mailbox quota the operator believes
// they set. The message says which modules take part, so the typo is obvious.
func valeursParModule(sets []string, modules []moduleCompte) (map[string]module.Values, error) {
	participants := make(map[string]bool, len(modules))
	for _, m := range modules {
		participants[m.ID] = true
	}
	surcharges := make(map[string]module.Values, len(modules))
	for _, s := range sets {
		cle, valeur, ok := strings.Cut(s, "=")
		cle = strings.TrimSpace(cle)
		if !ok || cle == "" {
			return nil, fmt.Errorf("--set %q: expected MODULE.KEY=VALUE", s)
		}
		id, nom, ok := strings.Cut(cle, ".")
		id, nom = strings.TrimSpace(id), strings.TrimSpace(nom)
		if !ok || id == "" || nom == "" {
			return nil, fmt.Errorf("--set %q: expected MODULE.KEY=VALUE", s)
		}
		if !participants[id] {
			return nil, fmt.Errorf("--set %q: module %q does not take part in user creation (installed modules that manage accounts: %s)",
				s, id, listerIDs(modules))
		}
		if surcharges[id] == nil {
			surcharges[id] = module.Values{}
		}
		surcharges[id][nom] = valeur
	}
	return surcharges, nil
}

// listerIDs renders the IDs of the participating modules for a message.
func listerIDs(modules []moduleCompte) string {
	if len(modules) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(modules))
	for _, m := range modules {
		ids = append(ids, m.ID)
	}
	return strings.Join(ids, ", ")
}

// valeursDe returns the values of a module's fields, starting from the declared
// defaults and applying the received overrides.
//
// UNKNOWN KEYS ARE REFUSED (and not ignored): the form on the console does the
// same, and a mistyped key that silently did nothing would make the operator
// believe a setting was applied.
func valeursDe(champs []module.AccountField, recus module.Values) (module.Values, error) {
	valeurs := make(module.Values, len(champs))
	connus := make(map[string]bool, len(champs))
	for _, c := range champs {
		valeurs[c.Key] = c.Default
		connus[c.Key] = true
	}
	for k, v := range recus {
		if !connus[k] {
			return nil, fmt.Errorf("unknown field %q", k)
		}
		valeurs[k] = v
	}
	return valeurs, nil
}

// emailRemplace says whether a module makes the email input meaningless.
//
// The field is a checkbox (module.Bool): its value is the string "true" or
// "false" as sent by every frontend, and "true" means the module computes the
// address itself (an internal user's address is <username>@<domain>).
func emailRemplace(champs []module.AccountField, valeurs module.Values) bool {
	for _, c := range champs {
		if c.Type == module.Bool && c.ReplacesEmail && valeurs[c.Key] == "true" {
			return true
		}
	}
	return false
}

// ecrireResultatCompte writes a module's result back to the platform accounts.
//
// KEYCLOAK IS A HARD FAILURE, NEXTCLOUD IS NOT: the directory is what every
// login reads, while the Nextcloud address is a profile detail the operator can
// fix without recreating anything (the console applies the same split).
func ecrireResultatCompte(cmd *cobra.Command, ctx context.Context, u module.User, moduleTitre string, res module.AccountResult) error {
	if err := keycloakEcrire(ctx, u, res); err != nil {
		return err
	}
	if res.Email != "" {
		if err := nextcloudEcrireEmail(ctx, u.Username, res.Email); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"⚠ %s: address written in Keycloak but not in Nextcloud (module %s): %v\n",
				u.Username, moduleTitre, err)
		}
	}
	return nil
}

// motDePasseChoisi returns the password to set and whether it was generated.
//
// "--password -" READS ONE LINE on standard input: a flag is visible in the
// shell history and in ps, and an operator who wants to pick the password needs
// a way that is not. An empty line is refused rather than turned into an empty
// password.
func motDePasseChoisi(cmd *cobra.Command, drapeau string) (string, bool, error) {
	switch {
	case drapeau == "-":
		ligne, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", false, fmt.Errorf("reading the password from standard input: %w", err)
		}
		ligne = strings.TrimRight(ligne, "\r\n")
		if ligne == "" {
			return "", false, fmt.Errorf("the password read from standard input is empty")
		}
		return ligne, false, nil
	case drapeau != "":
		return drapeau, false, nil
	}
	mdp, err := motDePasseGenere(18)
	if err != nil {
		return "", false, fmt.Errorf("generating a password: %w", err)
	}
	return mdp, true, nil
}

// motDePasseGenere produces a password without ambiguous characters.
//
// We drop 0/O, 1/l/I, +/: copying a password by hand from a screen is a classic
// source of error, and the generated password is precisely the one noted down.
// Each character is drawn with crypto/rand and rejection-free selection
// (rand.Int): a modulo over random bytes would make the first letters of the
// alphabet slightly more likely.
func motDePasseGenere(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"
	out := make([]byte, 0, n)
	for len(out) < n {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out = append(out, alphabet[i.Int64()])
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// deactivate / reactivate

// changerEtatUtilisateur deactivates or reactivates a user.
//
// THE ORDER IS THE CONTRACT: the directory first (it decides whether a new
// session is possible at all), then Nextcloud, then the modules. The modules'
// failures are collected and returned together: a mailbox that keeps receiving
// mail for a deactivated user is a security problem, and stopping at the first
// module would hide the others.
func changerEtatUtilisateur(cmd *cobra.Command, domain, nom string, actif bool) error {
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return fmt.Errorf("the username cannot be empty")
	}
	geste, participe := "deactivated", "deactivation"
	if actif {
		geste, participe = "reactivated", "reactivation"
	}
	if estCompteProtege(nom) {
		return fmt.Errorf("%q is the platform administration account: its %s is refused", nom, participe)
	}
	ctx := cmd.Context()
	compte, err := trouverUtilisateur(ctx, nom)
	if err != nil {
		return err
	}

	if err := keycloakActiver(ctx, compte.User, actif); err != nil {
		return fmt.Errorf("user %q was not %s: %w", compte.Username, geste, err)
	}
	if err := nextcloudActiver(ctx, compte.Username, actif); err != nil {
		// NON-BLOCKING: the Nextcloud account is the fallback door when Keycloak
		// is unavailable; its state is reported but the modules' objects are
		// what the gesture is really about.
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Nextcloud account not updated: %v\n", err)
	}

	var errs []string
	for _, m := range modulesComptes(ctx, domain) {
		var err error
		if actif {
			err = m.Acc.ResumeAccount(ctx, m.Env, compte.User)
		} else {
			err = m.Acc.SuspendAccount(ctx, m.Env, compte.User)
		}
		if err != nil {
			errs = append(errs, m.titre()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf(
			"user %q is %s in the directory, but its module accounts are not: %s — run the same command again to finish (it converges)",
			compte.Username, geste, strings.Join(errs, "; "))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "User %q %s.\n", compte.Username, geste)
	return nil
}

// ---------------------------------------------------------------------------
// delete

// supprimerUtilisateur deletes the modules' objects, then Nextcloud, then the
// platform account.
//
// THE MODULES GO FIRST: once the platform account is gone, nothing else can
// reach their objects. The confirmation is checked BEFORE any cluster call: a
// mistyped username must not cost a single destructive request.
func supprimerUtilisateur(cmd *cobra.Command, domain, nom, confirm string) error {
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return fmt.Errorf("the username cannot be empty")
	}
	if estCompteProtege(nom) {
		return fmt.Errorf("%q is the platform administration account: its deletion is refused", nom)
	}
	// THE CONFIRMATION IS THE USERNAME, compared without case: Keycloak's
	// usernames are case-insensitive, and a typed confirmation that refused
	// "Alice" for "alice" would be a rule the platform itself does not apply.
	if strings.TrimSpace(confirm) == "" {
		return fmt.Errorf("deleting is irreversible: add --confirm %s to confirm", nom)
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), nom) {
		return fmt.Errorf("type the username %q to confirm the deletion", nom)
	}
	ctx := cmd.Context()
	compte, err := trouverUtilisateur(ctx, nom)
	if err != nil {
		return err
	}

	for _, m := range modulesComptes(ctx, domain) {
		if err := m.Acc.DeleteAccount(ctx, m.Env, compte.User); err != nil {
			return fmt.Errorf(
				"deletion stopped, the platform account was kept so the command can be run again: %s: %w",
				m.titre(), err)
		}
	}
	if err := nextcloudSupprimer(ctx, compte.Username); err != nil {
		return fmt.Errorf(
			"deletion stopped, the platform account was kept so the command can be run again: %w", err)
	}
	if err := keycloakSupprimer(ctx, compte.User); err != nil {
		return fmt.Errorf("deleting the platform account: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "User %q and all its accounts deleted.\n", compte.Username)
	return nil
}

// ---------------------------------------------------------------------------
// module action on one account

// executerActionCompte runs one action a module declares for one user.
//
// THE ACTION IS LOOKED UP IN THE MODULE'S OWN DECLARATION for this user: an
// action the module does not offer is refused rather than forwarded, because a
// module receiving an action it never declared would have to interpret it, and
// the day it stops offering it the command would keep calling it.
func executerActionCompte(cmd *cobra.Command, domain, nom, moduleID, actionID, confirm string, sets []string) error {
	nom = strings.TrimSpace(nom)
	moduleID = strings.TrimSpace(moduleID)
	actionID = strings.TrimSpace(actionID)
	if nom == "" {
		return fmt.Errorf("the username cannot be empty")
	}
	if estCompteProtege(nom) {
		return fmt.Errorf("%q is the platform administration account: no module action is allowed on it", nom)
	}
	ctx := cmd.Context()

	modules := modulesComptes(ctx, domain)
	var cible *moduleCompte
	for i := range modules {
		if modules[i].ID == moduleID {
			cible = &modules[i]
			break
		}
	}
	if cible == nil {
		return fmt.Errorf("module %q does not manage user accounts here (installed modules that do: %s)",
			moduleID, listerIDs(modules))
	}

	compte, err := trouverUtilisateur(ctx, nom)
	if err != nil {
		return err
	}
	infos, err := cible.Acc.AccountInfos(ctx, cible.Env, []module.User{compte.User})
	if err != nil {
		return fmt.Errorf("%s: %w", cible.titre(), err)
	}
	// The map is keyed by the user's ID (the contract's choice): a username can
	// be changed in the directory, an ID cannot.
	info := infos[compte.ID]
	var action *module.AccountAction
	for i := range info.Actions {
		if info.Actions[i].ID == actionID {
			action = &info.Actions[i]
			break
		}
	}
	if action == nil {
		return fmt.Errorf("module %s offers no action %q for %q (it offers: %s)",
			cible.titre(), actionID, compte.Username, listerActions(info.Actions))
	}
	// A TYPED CONFIRMATION IS COMPARED WITHOUT CASE, then trimmed: the console
	// applies the same rule, and its dialog sends exactly what was typed.
	if action.Confirm != "" && !strings.EqualFold(strings.TrimSpace(confirm), action.Confirm) {
		return fmt.Errorf("type %q to confirm this action", action.Confirm)
	}
	// The action's fields are settings fields (module.Field); the helper works
	// on the account variant, which wraps them — so the conversion is the
	// contract's, not the caller's.
	champs := make([]module.AccountField, 0, len(action.Fields))
	for _, f := range action.Fields {
		champs = append(champs, module.AccountField{Field: f})
	}
	recus, err := valeursSimples(sets)
	if err != nil {
		return err
	}
	valeurs, err := valeursDe(champs, recus)
	if err != nil {
		return fmt.Errorf("%s: %w", cible.titre(), err)
	}
	if err := cible.Acc.AccountAction(ctx, cible.Env, compte.User, actionID, valeurs); err != nil {
		return fmt.Errorf("%s: %w", cible.titre(), err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Action %q done on the %s account of %q.\n", actionID, cible.titre(), compte.Username)
	return nil
}

// valeursSimples converts repeated KEY=VALUE flags to the contract's values.
//
// There is no module prefix here: the module is already an argument of the
// command, and requiring it twice would only invite a mismatch.
func valeursSimples(sets []string) (module.Values, error) {
	valeurs := make(module.Values, len(sets))
	for _, s := range sets {
		cle, valeur, ok := strings.Cut(s, "=")
		cle = strings.TrimSpace(cle)
		if !ok || cle == "" {
			return nil, fmt.Errorf("--set %q: expected KEY=VALUE", s)
		}
		valeurs[cle] = valeur
	}
	return valeurs, nil
}

// listerActions renders the actions a module offers, for an error message.
func listerActions(actions []module.AccountAction) string {
	if len(actions) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(actions))
	for _, a := range actions {
		ids = append(ids, a.ID)
	}
	return strings.Join(ids, ", ")
}
