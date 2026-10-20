// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// groupeAcces is the settings group: who may enter.
const groupeAcces = "access"

// emailValide is a deliberately loose pattern.
//
// STRICT ENOUGH TO CATCH A TYPO, LOOSE ENOUGH FOR A REAL DOMAIN: `admin@ceffio` without
// a dot is refused because it is almost always a mistake, while a subdomain, a plus sign
// and a dash all pass. A fully RFC-compliant regex would be longer than this file and
// would reject addresses that work.
var emailValide = regexp.MustCompile(`^[^@\s,]+@[^@\s,]+\.[^@\s,]+$`)

// Settings declares the access group.
//
// THE DEFAULT IS THE ADMINISTRATOR'S OWN ADDRESS, so the module is usable the moment it
// is installed. An empty default would produce a proxy that refuses everyone — including
// the person who just installed it, with an error page that explains nothing.
func (m *longhornUIModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeAcces,
		Title: "Who may enter",
		Description: "Addresses allowed to reach the storage interface. " +
			"Everyone else is refused, even when signed in.",
		Fields: []module.Field{
			{
				Key:   "allowed_emails",
				Label: "Allowed addresses",
				Help: "Keycloak addresses separated by commas. This is the ONLY " +
					"authorization: an account that is not listed here is refused, " +
					"whatever its roles.",
				Type:     module.Text,
				Required: true,
				Pattern:  `^[^@\s,]+@[^@\s,]+\.[^@\s,]+(,\s*[^@\s,]+@[^@\s,]+\.[^@\s,]+)*$`,
			},
		},
	}}
}

// Validate refuses an empty list and a malformed address.
//
// IT IS EXPLICIT RATHER THAN LEFT TO Pattern: a pattern says "this does not match", and
// the operator has to work out which of their addresses is wrong. Naming it is the
// difference between a fixable message and a puzzle.
func (m *longhornUIModule) Validate(groupe string, v module.Values) error {
	if groupe != groupeAcces {
		return fmt.Errorf("longhorn-ui: unknown settings group %q", groupe)
	}
	brut := v["allowed_emails"]
	if strings.TrimSpace(brut) == "" {
		return fmt.Errorf("longhorn-ui: the list of allowed addresses is empty — the " +
			"interface would refuse everyone, including you")
	}
	for _, a := range strings.Split(brut, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !emailValide.MatchString(a) {
			return fmt.Errorf("longhorn-ui: %q is not a valid e-mail address — the "+
				"authorization compares this exact string against the token's claim, so "+
				"a typo refuses the person you meant to allow", a)
		}
	}
	return nil
}

// Current reads the stored list.
func (m *longhornUIModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != groupeAcces {
		return nil, fmt.Errorf("longhorn-ui: unknown settings group %q", groupe)
	}
	valeur := adresseDefaut
	if env.Settings != nil {
		if v, err := env.Settings.Lire(ctx, nsSysteme, nomConfigReglages, "allowed_emails"); err == nil && v != "" {
			valeur = v
		}
	}
	return module.Values{"allowed_emails": valeur}, nil
}

// Apply stores the list and rewrites what the proxy reads.
//
// TWO WRITES, AND BOTH ARE NEEDED: the settings store keeps what the form shows, and the
// ConfigMap is what the proxy actually reads as a file. Writing only the first would make
// the form agree with itself while the proxy keeps the old list — the worst kind of
// change, because it looks saved.
func (m *longhornUIModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if err := m.Validate(groupe, v); err != nil {
		return err
	}
	brut := v["allowed_emails"]

	if env.Settings != nil {
		if err := env.Settings.Ecrire(ctx, nsSysteme, nomConfigReglages,
			map[string]string{"allowed_emails": brut}); err != nil {
			return fmt.Errorf("longhorn-ui: storing the allowed addresses: %w", err)
		}
	}
	// THE CONFIGMAP THE PROXY READS, and the checksum that restarts it: the file is read
	// at startup, so rewriting it alone changes nothing.
	if err := poserAdresses(ctx, brut); err != nil {
		return err
	}
	if env.Domain == "" {
		// No domain means no manifest to re-apply; the ConfigMap alone is already the
		// change, and the next install restarts the pod.
		return nil
	}
	return appliquer(ctx, manifesteProxy(env.Domain, sommeAdresses(brut)))
}

// Test says nothing: there is no session to open.
//
// THE ALTERNATIVE — attempting a login — would need an account, and a settings form that
// asks for a password to test a list of addresses is a form nobody fills in.
func (m *longhornUIModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	if err := m.Validate(groupe, v); err != nil {
		return module.TestResult{OK: false, Detail: err.Error()}
	}
	n := len(strings.Split(strings.TrimSpace(v["allowed_emails"]), ","))
	return module.TestResult{
		OK:     true,
		Detail: fmt.Sprintf("%d address(es) allowed. The list is checked at sign-in: anyone not listed is refused, even with a valid Keycloak account.", n),
	}
}
