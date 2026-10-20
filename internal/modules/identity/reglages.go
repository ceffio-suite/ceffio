// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"fmt"

	coucheIdentity "github.com/ceffio-suite/ceffio/internal/identity"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// groupeLogin is the settings group the console draws for the sign-in page.
const groupeLogin = "login_page"

// Settings declares the login page settings.
//
// THE MODULE IMPLEMENTS Configurable, AND THAT IS ALL IT TAKES: the console draws
// this form from the declaration and the CLI prints it, with no code in either that
// knows the word "identity". That is the whole point of the settings contract — a
// module added tomorrow gets a page for free.
//
// TWO FIELDS, BOTH Choice. A free-text theme name would accept a typo and leave the
// realm pointing at a theme that does not exist, which Keycloak answers by silently
// serving its default: the operator sets "ceffio_", saves, and sees no change.
func (m *identityModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeLogin,
		Title: "Login page",
		Description: "The page users see when they sign in to the suite. " +
			"Changing it applies immediately: no restart, no reinstall.",
		Fields: []module.Field{
			{
				Key:   "theme",
				Label: "Theme",
				Help: "Ceffio is the branded page. Keycloak's default is the stock " +
					"page, useful to tell a themeing problem from a sign-in problem.",
				Type:     module.Choice,
				Required: true,
				Options: []module.Option{
					{Value: "ceffio", Label: "Ceffio"},
					{Value: "keycloak.v2", Label: "Keycloak (default)"},
				},
			},
			{
				Key:   "default_locale",
				Label: "Default language",
				Help: "The language the page opens in. Users can still change it " +
					"with the selector on the page itself.",
				Type:     module.Choice,
				Required: true,
				Options: []module.Option{
					{Value: "fr", Label: "Français"},
					{Value: "en", Label: "English"},
				},
			},
		},
	}}
}

// Current reads the realm's login page.
//
// IT READS FROM THE REALM, NOT FROM A STORED VALUE. The realm is the only truth
// here: someone may have changed the theme from the Keycloak admin console, and a
// form showing a stored setting would then lie about what users see.
//
// A MISSING THEME READS AS "ceffio", the installation default — an empty selector
// would look like a broken form rather than a realm that never had one set.
func (m *identityModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != groupeLogin {
		return nil, fmt.Errorf("identity: unknown settings group %q", groupe)
	}
	theme, locale, err := coucheIdentity.LireLoginTheme(ctx, nsIdentity)
	if err != nil {
		// THE DECLARATION IS STILL USEFUL when the realm cannot be read — a sealed
		// vault, an unreachable cluster — which is exactly when an operator wants to
		// see what the settings ARE.
		return nil, err
	}
	if theme == "" {
		theme = "ceffio"
	}
	if locale == "" {
		locale = "fr"
	}
	return module.Values{"theme": theme, "default_locale": locale}, nil
}

// Apply writes the login page to the realm.
//
// NO RESTART IS NEEDED: Keycloak reads the realm's loginTheme per request. The theme
// FILES, on the other hand, are cached at startup — which is why shipping a new
// theme restarts the pod, and changing WHICH theme is used does not.
func (m *identityModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if groupe != groupeLogin {
		return fmt.Errorf("identity: unknown settings group %q", groupe)
	}

	theme := v["theme"]
	locale := v["default_locale"]

	// VALIDATED AGAINST THE DECLARED OPTIONS, not trusted: the API is reachable by
	// any administrator, and a value outside the list would leave the realm pointing
	// at a theme that does not exist — Keycloak then serves its default silently.
	if err := validerChoix(m.Settings(), groupe, "theme", theme); err != nil {
		return err
	}
	if err := validerChoix(m.Settings(), groupe, "default_locale", locale); err != nil {
		return err
	}

	return coucheIdentity.AppliquerLoginPage(ctx, nsIdentity, theme, locale)
}

// Test has nothing to probe: a theme is a value the realm accepts or does not, and
// there is no session to open.
//
// SAYING SO IS BETTER THAN ABSENCE. The console shows a "test" button only for
// groups that can be tested; a group that returns a bare success would teach the
// operator that the button means nothing.
func (m *identityModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	if groupe != groupeLogin {
		return module.TestResult{OK: false, Detail: "unknown settings group"}
	}
	return module.TestResult{
		OK: true,
		Detail: "Nothing to test here: the theme is applied to the realm as soon as " +
			"you save, and the next sign-in shows it.",
	}
}

// validerChoix refuses a value outside a field's declared Options.
//
// IT READ FROM THE DECLARATION rather than from a second list, so a choice added to
// the form is accepted by the writer without touching this code — and a value that
// never appeared in the form cannot be stored.
func validerChoix(groupes []module.Group, groupe, cle, valeur string) error {
	for _, g := range groupes {
		if g.ID != groupe {
			continue
		}
		for _, f := range g.Fields {
			if f.Key != cle {
				continue
			}
			for _, o := range f.Options {
				if o.Value == valeur {
					return nil
				}
			}
			return fmt.Errorf("identity: %q is not one of the values declared for %s", valeur, cle)
		}
	}
	return fmt.Errorf("identity: %s is not a field of group %s", cle, groupe)
}
