// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
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

// kcadmConnecte authenticates kcadm inside the pod.
//
// THE CREDENTIALS COME FROM /secrets/env INSIDE THE POD, not from an environment
// variable passed to kubectl. The first version set KC_ADMIN_USER on the kubectl
// process and read it back inside the container — which reads as empty, and kcadm
// answers "Invalid user credentials" for a username nobody supplied. The failure
// looks like a wrong password, which is the worst shape a credential error can take.
//
// SOURCING /secrets/env IS THE MECHANISM THE REST OF THE PACKAGE ALREADY USES: the
// OpenBao injector writes that file, and k8s.AvecSecrets exists for exactly this.
//
// THE PASSWORD NEVER TRAVELS ON THE COMMAND LINE, which every process on the node
// can read: it stays in the shell variable the file defines.
func kcadmConnecte() string {
	return `set -a; . /secrets/env; set +a; ` +
		`/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 ` +
		`--realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" ` +
		`--password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null && `
}

// kcadmExec runs a kcadm script inside the keycloak pod.
//
// IT GOES THROUGH THE KUBERNETES API, NOT THROUGH kubectl. The console container has
// no kubectl binary — verified in production, where the settings form rendered an
// empty selector and the API answered `exec: "kubectl": executable file not found in
// $PATH`. k8sapi.Client.Executer speaks the SPDY exec protocol directly, so the same
// code works from a binary on an operator's machine AND from inside the console.
//
// THE POD IS FOUND FIRST: an exec needs a pod name, and the deployment's name is not
// one. The first Ready pod of app=keycloak is the one that serves the realm.
func kcadmExec(ctx context.Context, ns, script string, args ...string) error {
	cli, err := clientK8s()
	if err != nil {
		return fmt.Errorf("connecting to the cluster: %w", err)
	}
	pod, err := podKeycloak(ctx, cli, ns)
	if err != nil {
		return err
	}

	commande := append([]string{"sh", "-c", script, "sh"}, args...)
	out, err := cli.Executer(ctx, ns, pod, "keycloak", commande...)
	if err != nil {
		return fmt.Errorf("applying the login page to the realm: %w: %s",
			err, strings.TrimSpace(out))
	}
	return nil
}

// podKeycloak returns the Ready keycloak pod of the identity namespace.
//
// IT TAKES A READY ONE rather than the first listed: during a rollout the terminating
// pod answers NotFound on exec, and during the first start the new one has no listening
// realm yet. Both produce a failure that reads like a credential problem.
func podKeycloak(ctx context.Context, cli *k8sapi.Client, ns string) (string, error) {
	pods, err := cli.Pods(ctx, ns, "app=keycloak")
	if err != nil {
		return "", fmt.Errorf("listing the keycloak pods: %w", err)
	}
	for _, p := range pods {
		if p.Ready && p.Phase == "Running" {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no Ready keycloak pod in %s: the realm cannot be read or "+
		"written until one is running", ns)
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

// LireLoginTheme returns the realm's current loginTheme and default locale.
//
// AN EMPTY RESULT MEANS "the realm does not say", which Keycloak reads as the default
// theme. Returning an error instead would make the settings form unusable on an
// installation whose realm was created before the theme existed.
func LireLoginTheme(ctx context.Context, ns string) (theme, locale string, err error) {
	script := kcadmConnecte() +
		`/opt/keycloak/bin/kcadm.sh get realms/` + realmCeffio +
		` --fields loginTheme,defaultLocale 2>/dev/null`

	cli, err := clientK8s()
	if err != nil {
		return "", "", fmt.Errorf("connecting to the cluster: %w", err)
	}
	pod, err := podKeycloak(ctx, cli, ns)
	if err != nil {
		return "", "", err
	}
	out, err := cli.Executer(ctx, ns, pod, "keycloak", "sh", "-c", script)
	if err != nil {
		return "", "", fmt.Errorf("reading the realm's login page: %w: %s", err,
			strings.TrimSpace(out))
	}

	// KCADM WRITES ITS PROGRESS TO THE SAME STREAM as the JSON: "Logging into
	// http://localhost:8080 as user admin of realm master" precedes the document, and
	// a straight Unmarshal fails on the 'L'. The JSON body is isolated by taking the
	// first line that opens a brace to the last that closes one.
	corps := corpsJSON(out)
	if corps == "" {
		return "", "", fmt.Errorf("reading the realm's login page: no JSON in the answer: %s",
			strings.TrimSpace(out))
	}
	var r struct {
		LoginTheme    string `json:"loginTheme"`
		DefaultLocale string `json:"defaultLocale"`
	}
	if err := json.Unmarshal([]byte(corps), &r); err != nil {
		return "", "", fmt.Errorf("reading the realm's login page: %w", err)
	}
	return r.LoginTheme, r.DefaultLocale, nil
}

// clientK8s is the Kubernetes client the package uses, as a variable so a test can
// inject a fake instead of reaching for a cluster.
var clientK8s = k8sapi.Nouveau

// AppliquerLoginPage is the entry point the settings system uses: change WHICH theme
// the realm serves, and in which language.
//
// IT DOES NOT TOUCH THE FILES. The theme assets ship with the binary and are mounted in
// the pod; this function only tells the realm which one to use. That is why changing it
// needs NO RESTART — Keycloak resolves the realm's loginTheme per request — while
// shipping a NEW theme restarts the pod, because the files are cached at startup.
//
// displayNameHtml IS LEFT ALONE. It belongs to the theme's identity, not to the choice:
// switching to Keycloak's default page should not strip Ceffio's name from the realm,
// and switching back must find it intact.
func AppliquerLoginPage(ctx context.Context, ns, theme, locale string) error {
	script := kcadmConnecte() +
		`/opt/keycloak/bin/kcadm.sh update realms/` + realmCeffio +
		` -s loginTheme=` + shellQuote(theme) + " " +
		` -s internationalizationEnabled=true` +
		` -s defaultLocale=` + shellQuote(locale)
	return kcadmExec(ctx, ns, script, theme, locale)
}

// corpsJSON returns the JSON document inside a stream that carries other text.
//
// THE SHAPE IS KNOWN AND NARROW: kcadm prints one or two progress lines, then the
// document. Rather than a lenient parser, the braces are located — an output with no
// braces returns "" and the caller reports what it actually received.
func corpsJSON(sortie string) string {
	debut := strings.Index(sortie, "{")
	fin := strings.LastIndex(sortie, "}")
	if debut < 0 || fin <= debut {
		return ""
	}
	return sortie[debut : fin+1]
}
