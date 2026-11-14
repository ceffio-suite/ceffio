// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package module

import "context"

// Accounts is the contract through which a module takes part in the Users
// page: it declares the inputs a user creation needs, provisions what it owns
// once the account exists, and reports and acts on each user's account.
//
// WHY IT EXISTS: before this contract, creating a user meant a Keycloak
// account, a Nextcloud account, and nothing else. A feature that needs a
// per-user object — a mailbox is the first one — had no way to learn that a
// user was created, so the operator had to leave the page and create the
// object by hand in the feature's own interface. That is two systems to keep
// in step, and the second one silently missing for every user created
// afterwards.
//
// WHY THE WHOLE PAGE LOGIC IS HERE AND NOT IN THE CONSOLE: the console must
// not name modules. It asks every INSTALLED module implementing Accounts for
// its fields and its accounts, and renders what it is given — so a new module
// appears on the Users page with no change to the page, the handlers or the
// closed route list. A test forbids the page from naming a module
// (TestLaPageNAppelleAucunModuleEnDur), which is the mechanical guard for
// that rule.
//
// ORDER IS PART OF THE CONTRACT, and the console implements it once for every
// module:
//
//  1. ValidateAccount of every module, BEFORE anything is created — Keycloak
//     included. A refusal that comes after the Keycloak account exists leaves
//     a half-created user to clean up by hand;
//  2. Keycloak user, then Nextcloud account (the two the page has always
//     created);
//  3. EnsureAccount of every module;
//  4. write-back of each AccountResult (email and attributes).
//
// Ensuring the platform account first and the module objects second is what
// makes a retry converge: both steps are idempotent, and the platform account
// is the one the operator can see and delete from the page.
type Accounts interface {
	// AccountFields declares the inputs this module adds to the creation form,
	// NEXT TO the username/email/password the page always asks for.
	//
	// It is called on every render of the page: it must be cheap and side
	// effect free, and it must not depend on a specific user.
	AccountFields(ctx context.Context, env Env) []AccountField

	// ValidateAccount runs before anything is created, Keycloak included.
	//
	// WHY SO EARLY: the console used to create the Keycloak account first and
	// discover the module's refusal afterwards, leaving an account with a
	// mailbox that could never be created. A validation error must be
	// actionable as written: it is shown to the operator as-is, so it names
	// the field and the rule, in the operator's language.
	ValidateAccount(ctx context.Context, env Env, u User, v Values) error

	// EnsureAccount provisions what this module owns for the user, and is
	// IDEMPOTENT: a retry of the same creation (the console's own retry after
	// a failure) must converge, not duplicate.
	//
	// It receives the user as it exists at this point — the Keycloak account,
	// with the email the operator typed. What it wants written back goes into
	// the result, because the module must not write the directory itself: one
	// writer per object, and the console owns the platform account.
	EnsureAccount(ctx context.Context, env Env, u User, v Values) (AccountResult, error)

	// AccountInfos reports each user's account for the whole list, in ONE call.
	//
	// WHY BATCHED: the page lists every user; a per-user call would make a
	// page load cost one round trip per user per module, and the mail server
	// answers that whole question in one JMAP request. `users` is the list the
	// page already loaded, so a module can answer about accounts it did not
	// have to look up again.
	AccountInfos(ctx context.Context, env Env, users []User) (map[string]AccountInfo, error)

	// AccountAction runs one action offered by AccountInfos for one user.
	//
	// The action id is the one declared in AccountInfo.Actions; the values are
	// the fields of that action. An unknown id is an error, not a no-op: the
	// page and the module disagreeing about an action is a bug, and silently
	// doing nothing hides it.
	AccountAction(ctx context.Context, env Env, u User, action string, v Values) error

	// SuspendAccount / ResumeAccount are the whole-user lifecycle, called by
	// the Users page when an account is deactivated or reactivated.
	//
	// WHY SEPARATE FROM AccountAction: deactivating a user is the page's own
	// gesture, and it must reach the module without the page knowing which
	// action id to send. Both are idempotent — the platform account's `enabled`
	// flag is the truth, and replaying it must not fail.
	SuspendAccount(ctx context.Context, env Env, u User) error
	ResumeAccount(ctx context.Context, env Env, u User) error

	// DeleteAccount removes what the module owns for the user.
	//
	// THE PLATFORM ACCOUNT IS NOT DELETED HERE: the console deletes the module
	// objects FIRST, then the Nextcloud and Keycloak accounts, so a failure
	// leaves a user that can still be deleted again from the page — the
	// opposite order would leave objects no page can reach.
	//
	// Irreversible by nature (a mailbox's contents go with it), which is why
	// the page asks the operator to type the username before calling it.
	DeleteAccount(ctx context.Context, env Env, u User) error
}

// User is the platform user as the Users page knows it (Keycloak).
type User struct {
	ID       string
	Username string
	Email    string
	// Attributes are the Keycloak user attributes the page read back, so a
	// module can recognize its own users (the mail module writes
	// ceffio_kind=internal and reads it to tell an internal user from an
	// external one).
	Attributes map[string]string
}

// AccountField is a creation input a module adds to the Users form.
type AccountField struct {
	// Field is the settings field: key, label, help, type, default, options,
	// required. Reusing it means one form renderer for settings and users, and
	// one set of validation rules.
	Field
	// ReplacesEmail: this Bool field, when true, hides and ignores the email
	// input of the form.
	//
	// WHY THE EMAIL CAN DISAPPEAR: an internal user's address is not chosen,
	// it is `<username>@<domain>` — the mail server's own convention, which the
	// mailbox creation depends on. Letting the operator type a different
	// address would create a mailbox under one name and an account under
	// another, and the address the user reads their mail at would not be the
	// one the page shows.
	//
	// The JSON name is snake_case like every other field of Field: the page
	// reads it to hide the email input, and a Go-style name would make the
	// browser check a key the API never sends.
	ReplacesEmail bool `json:"replaces_email,omitempty"`
}

// AccountResult is what a module asks the Users page to write back.
type AccountResult struct {
	// Email: non-empty means this becomes the user's email in Keycloak and
	// Nextcloud. It is how an internal user ends up with `<username>@<domain>`
	// without the page knowing the convention.
	Email string
	// Attributes are written as Keycloak user attributes.
	Attributes map[string]string
}

// AccountAction is an action the console offers on one user's account.
type AccountAction struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Confirm string  `json:"confirm,omitempty"` // non-empty: the user must type this (the username)
	Fields  []Field `json:"fields,omitempty"`  // inputs of the action (e.g. new quota)
}

// AccountInfo is one user's account in one module, for the Users page.
type AccountInfo struct {
	Present   bool            `json:"present"`
	Suspended bool            `json:"suspended"`
	Summary   string          `json:"summary"` // e.g. "312 MiB / 1 GiB"
	Actions   []AccountAction `json:"actions"`
}

// AccountsOf returns the module's Accounts implementation, when it has one.
//
// The type assertion lives here so both frontends agree on the rule "a module
// takes part in the Users page when it implements Accounts" instead of each
// writing its own assertion and drifting.
func AccountsOf(m Module) (Accounts, bool) {
	a, ok := m.(Accounts)
	return a, ok
}
