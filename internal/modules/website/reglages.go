// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package website

import (
	"context"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/settings"
	"github.com/ceffio-suite/ceffio/internal/website"
)

// groupePage is the settings group the console draws for the landing page.
const groupePage = "landing_page"

// cleContact is the field holding the address published in the footer.
const cleContact = "contact_email"

// Settings declares the landing page settings.
//
// WHY A DECLARED SETTING AND NOT A CONSTANT: the address belongs to the
// OPERATOR of the installation, never to the editor. Committing one would
// publish Mandem's address from every customer's server, and a customer who
// received a report meant for them would have no way to know. The default is
// therefore EMPTY — no address at all — and a domain that does want one sets
// it here.
//
// The module implements Configurable and that is all it takes: the console
// draws this form and the CLI prints it, with no code in either that knows the
// word "website".
func (m *websiteModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupePage,
		Title: "Landing page",
		Description: "The public page published on the installation's root host. " +
			"Changing a value re-renders the page and replaces its pod: no reinstall, " +
			"and the address visitors type does not change.",
		Fields: []module.Field{{
			Key:   cleContact,
			Label: "Contact address",
			Help: "Published in the footer, as a link and as text. Leave empty to publish no " +
				"address: the page then says the reporting channels are the ones in security.txt. " +
				"An address here is the installation's own, not the editor's.",
			Type:    module.Text,
			Pattern: website.MotifAdresse,
		}},
	}}
}

// groupe returns the declaration of one group, and whether it exists. Looking
// it up instead of fabricating a Group means Current and Apply can never be
// given a field list that Settings does not declare.
func (m *websiteModule) groupe(id string) (module.Group, bool) {
	for _, g := range m.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// Current reads the stored contact address.
//
// IT READS THE STORE, NOT THE PUBLISHED PAGE: for this module the store IS the
// truth — a page edited out of band would be overwritten by the next install,
// and there is no other frontend that could change the address behind the
// form's back. A missing entry reads as the empty default, which is what an
// installation that never set one publishes.
func (m *websiteModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	g, ok := m.groupe(groupe)
	if !ok {
		return nil, fmt.Errorf("website: unknown settings group %q (declared: %s)", groupe, groupePage)
	}
	return settings.Load(ctx, env, g)
}

// Apply stores the contact address and republishes the page when it exists.
//
// THE VALUE IS VALIDATED BEFORE IT IS STORED, and validated again by
// website.Files when the page is rendered: the form is one frontend among
// several (console, CLI), and a stored value that the renderer rejects would
// break the next install with an error nobody can trace back to its input.
//
// A SAVE THAT COULD NOT BECOME VISIBLE IS REFUSED BEFORE IT IS WRITTEN.
// "Apply failed" must mean "nothing changed": storing an address the page
// cannot be re-rendered with would leave the store ahead of the public page,
// and the operator would have no way to tell which of the two is current.
func (m *websiteModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	g, ok := m.groupe(groupe)
	if !ok {
		return fmt.Errorf("website: unknown settings group %q (declared: %s)", groupe, groupePage)
	}
	if v == nil {
		v = module.Values{}
	}
	// A text input carries what was typed, including surrounding spaces; they
	// are not part of an address, and the pattern would reject a value the
	// operator sees as correct.
	v[cleContact] = strings.TrimSpace(v[cleContact])
	if err := module.Validate(g, v); err != nil {
		return err
	}
	publiee := m.pagePresente(ctx, env)
	if publiee && env.Domain == "" {
		return fmt.Errorf("website: cannot re-render the page without the installation domain (use --domain)")
	}
	if err := settings.Save(ctx, env, g, v); err != nil {
		return err
	}
	if !publiee {
		return nil
	}
	return m.republierPage(ctx, env, v[cleContact])
}

// pagePresente reports whether there is a page to re-render. False is a normal
// answer: a setting can legitimately be recorded before the module is installed
// (`ceffio module config` has no install gate, and a script may prepare an
// installation), and Install reads the store anyway — storing the value is then
// the whole job.
func (m *websiteModule) pagePresente(ctx context.Context, env module.Env) bool {
	if env.Kube == nil {
		return false
	}
	etat := m.State(ctx, env)
	return etat.Status == module.Installed || etat.Status == module.Degraded
}

// republierPage makes a saved address visible without reinstalling the module.
//
// It does NOT wait for the replacement pod. The caller is an HTTP request or a
// CLI command whose job is to record a decision; a rolling update takes a few
// seconds, and blocking the console's request on it would time it out.
func (m *websiteModule) republierPage(ctx context.Context, env module.Env, contact string) error {
	donnees, empreinte, err := rendre(env.Domain, contact)
	if err != nil {
		return err
	}
	if err := assurerConfigMap(ctx, env.Kube, donnees); err != nil {
		return err
	}
	return assurerDeploiement(ctx, env.Kube, empreinte)
}

// contactPublie reads the address Install must publish. Empty is a normal
// answer: it is what an installation that never configured one publishes.
func (m *websiteModule) contactPublie(ctx context.Context, env module.Env) (string, error) {
	valeurs, err := m.Current(ctx, env, groupePage)
	if err != nil {
		return "", err
	}
	return valeurs[cleContact], nil
}

var (
	_ module.Module       = (*websiteModule)(nil)
	_ module.Configurable = (*websiteModule)(nil)
)
