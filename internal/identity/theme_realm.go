// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// realm à thémer. Le realm `master` n'est JAMAIS touché : sa page de connexion sert
// à l'administration de Keycloak et doit rester reconnaissable — un administrateur
// qui se trompe de porte doit le voir.
const realmCeffio = "ceffio"

// DisplayNameHTML is the header above the sign-in card.
//
// IT IS EXACTLY THIS STRING, and ceffio.css targets these two classes:
// `kc-logo-text` is the block keycloak.v2 turns into the logo area, and
// `ceffio-slogan` is Ceffio's own. Writing the header here rather than in a template
// is what keeps the theme upgrade-safe: keycloak.v2 renders this field itself, so a
// Keycloak release keeps its structure and only the styling changes.
//
// A TEST CHECKS THAT THESE CLASSES EXIST IN ceffio.css — a header whose classes are
// styled by nothing renders as unstyled text inside the card, which looks like a
// broken theme rather than a missing rule.
const DisplayNameHTML = `<div class="kc-logo-text"><span>Ceffio</span></div><p class="ceffio-slogan">La suite collaborative souveraine</p>`

// localesSupportees lists the languages the sign-in page offers.
//
// THE LIST AND THE DEFAULT ARE CHECKED TOGETHER: Keycloak IGNORES SILENTLY a default
// locale that is not in supportedLocales, and serves its own default instead — so an
// installation meant to be French shows English, with no error anywhere.
var localesSupportees = []string{"fr", "en"}

// ReglagesRealm is what the identity layer sets on the ceffio realm.
//
// IT IS A STRUCT because the login page is a SETTING (lot T4): the console writes
// these two fields through the generic settings system, and the deployment writes
// them at install time. One shape, so the two paths cannot disagree.
type ReglagesRealm struct {
	Theme       string
	Locale      string
	DisplayName string
}

// ReglagesParDefaut is what an installation gets: the Ceffio page, in French.
func ReglagesParDefaut() ReglagesRealm {
	return ReglagesRealm{Theme: "ceffio", Locale: "fr", DisplayName: "Ceffio"}
}

// appliquerThemeRealm writes the login page onto the ceffio realm, IDEMPOTENTLY.
//
// IT READS THE REALM, CHANGES ONLY THESE FIELDS, AND WRITES IT BACK. A blind
// `kcadm update realms/ceffio` would not work here: the write replaces what it is
// given, and the realm carries clients, roles, flows and keys that must not be
// touched. Reading first is also what makes a second run a no-op — the installer
// applies the identity layer on every upgrade, and rewriting the realm each time
// would restart nothing visible but would churn its revision in the audit log.
//
// ONLY THE FIELDS LISTED ARE SET. `internationalizationEnabled` is turned on because
// a locale list without it is ignored, silently: the operator picks French, and the
// page stays in English.
func appliquerThemeRealm(ctx context.Context, ns string, r ReglagesRealm) error {
	if r.Theme == "" {
		r.Theme = ReglagesParDefaut().Theme
	}
	if r.Locale == "" {
		r.Locale = ReglagesParDefaut().Locale
	}
	if r.DisplayName == "" {
		r.DisplayName = ReglagesParDefaut().DisplayName
	}

	// kcadm update -s WRITES ONLY THE FIELDS NAMED, which is the idempotence we
	// want: the realm keeps its clients, roles, flows and keys untouched, and a
	// second run rewrites the same five values instead of replacing a document it
	// never read.
	//
	// THE POD HAS NEITHER python3 NOR jq — verified — so a read-modify-write in the
	// shell is not available. `update -s` is the supported path and needs nothing.
	//
	// THE VALUES ARE SINGLE-QUOTED, and the HTML is percent-free so no escaping is
	// needed beyond doubling an apostrophe. displayNameHtml carries no apostrophe;
	// the slogan does not either.
	script := kcadmConnecte() +
		`/opt/keycloak/bin/kcadm.sh update realms/` + realmCeffio +
		` -s loginTheme=` + shellQuote(r.Theme) + " " +
		` -s displayName=` + shellQuote(r.DisplayName) + " " +
		` -s displayNameHtml=` + shellQuote(DisplayNameHTML) + " " +
		` -s internationalizationEnabled=true` +
		` -s defaultLocale=` + shellQuote(r.Locale) + " " +
		` -s 'supportedLocales=["` + strings.Join(localesSupportees, `","`) + `"]'`

	return kcadmExec(ctx, ns, script, r.Theme, r.Locale, r.DisplayName, DisplayNameHTML)
}

// kcadmConnecte authenticates kcadm inside the pod, reading the password on stdin.
//
// THE PASSWORD NEVER TRAVELS ON THE COMMAND LINE, which every process on the node
// can read. `IFS= read -r` keeps it intact: no trimming, no backslash
// interpretation, so a password containing $ or \\ still authenticates.
func kcadmConnecte() string {
	return `IFS= read -r motdepasse; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 ` +
		`--realm master --user "$KC_ADMIN_USER" --password "$motdepasse" >/dev/null && `
}

// kcadmExec runs a kcadm script in the keycloak pod with the admin password on
// stdin and the realm settings as arguments.
//
// THE SETTINGS TRAVEL AS ARGUMENTS, not interpolated into the script: the display
// name is HTML, and building a shell line out of it would need quoting rules that a
// future edit would get wrong. `python3 - "$@"` reads them back safely.
func kcadmExec(ctx context.Context, ns, script string, args ...string) error {
	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return fmt.Errorf("keycloak admin credentials unreadable in the vault: %w", err)
	}
	utilisateur, motdepasse := entree["username"], entree["password"]
	if utilisateur == "" || motdepasse == "" {
		return fmt.Errorf("incomplete keycloak/admin vault entry (username and password required)")
	}

	commande := []string{"exec", "-i", "-n", ns, "deploy/keycloak", "-c", "keycloak",
		"--", "sh", "-c", script, "sh"}
	commande = append(commande, args...)

	cmd := k8s.Command(ctx, "kubectl", commande...)
	cmd.Env = append(k8s.Env(), "KC_ADMIN_USER="+utilisateur)
	cmd.Stdin = strings.NewReader(motdepasse + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("applying the login page to the realm: %w: %s",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// appliquerThemeDepuisDeploiement is the lot T3 entry point: the theme and the
// locale that the installation declares.
//
// IT FAILS LOUDLY. A theme that does not apply leaves every user on Keycloak's
// default page, and nothing in the platform reports it — the realm simply carries
// `loginTheme: keycloak` and nobody notices until someone opens the sign-in page.
func appliquerThemeDepuisDeploiement(ctx context.Context, ns string) error {
	fmt.Println("∙ login page (theme ceffio, fr)")
	if err := appliquerThemeRealm(ctx, ns, ReglagesParDefaut()); err != nil {
		return fmt.Errorf("the login theme could not be applied to the %s realm: %w",
			realmCeffio, err)
	}
	return nil
}

// LireLoginTheme returns the realm's current loginTheme, for the settings system.
//
// AN EMPTY RESULT MEANS "the realm does not say", which Keycloak reads as the
// default theme. Returning an error instead would make the settings form unusable
// on an installation whose realm was created before the theme existed.
func LireLoginTheme(ctx context.Context, ns string) (theme, locale string, err error) {
	script := kcadmConnecte() +
		`/opt/keycloak/bin/kcadm.sh get realms/` + realmCeffio +
		` --fields loginTheme,defaultLocale 2>/dev/null`

	coffre := secrets.DepuisEnvironnement()
	entree, err := secrets.LireEntreeCoffre(ctx, coffre, "keycloak", "admin")
	if err != nil {
		return "", "", err
	}
	cmd := k8s.Command(ctx, "kubectl", "exec", "-i", "-n", ns, "deploy/keycloak", "-c", "keycloak",
		"--", "sh", "-c", script)
	cmd.Env = append(k8s.Env(), "KC_ADMIN_USER="+entree["username"])
	cmd.Stdin = strings.NewReader(entree["password"] + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("reading the realm's login page: %w: %s", err,
			strings.TrimSpace(string(out)))
	}

	var r struct {
		LoginTheme    string `json:"loginTheme"`
		DefaultLocale string `json:"defaultLocale"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return "", "", fmt.Errorf("reading the realm's login page: %w", err)
	}
	return r.LoginTheme, r.DefaultLocale, nil
}
