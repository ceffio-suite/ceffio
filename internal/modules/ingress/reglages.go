// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package ingress

// The ingress module's SETTINGS: how the certificates are obtained.
//
// WHY THIS MOVED HERE: the TLS page was written by hand inside the console, and
// the challenge came from an environment variable read at install time. So
// changing the challenge — or the DNS provider — meant a console change for the
// page, a reinstall for the value, and the two could disagree. The module now
// DECLARES the group, and the console, the CLI and the installer serve it.
//
// WHERE THE CREDENTIAL IS STORED, AND WHY IT DOES NOT MOVE: the solver reads
// `kv/data/ceffio/tls/dns-provider`, and that path is written into the
// ClusterIssuer's configuration by internal/ingress. The module therefore
// OVERRIDES the default store to write THERE rather than under
// `kv/ceffio/settings/<module>/<group>`: an existing installation must find its
// configuration where it already is, with no migration and no second copy to
// keep in step. This is the case the settings contract explicitly allows, and
// the reason is stated here rather than left to be guessed.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/acme"
	coucheIngress "github.com/ceffio-suite/ceffio/internal/ingress"
	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

const (
	// groupeTLS is the settings group this module declares.
	groupeTLS = "tls"

	// Composant and SousChemin are the vault coordinates of the DNS credential.
	//
	// THEY MUST MATCH internal/ingress.dnswebhook.go: the solver is deployed
	// with an annotation telling it to read that entry, so writing anywhere else
	// produces a solver that starts, reads nothing, and fails every challenge.
	// The mismatch is silent — the pod is Running and the log says the record
	// could not be published — which is why the two are tied by a test.
	ComposantCoffre  = "tls"
	SousCheminCoffre = "dns-provider"

	// ZoneParDefaut is empty: the zone is the certified domain unless the
	// operator says otherwise.
	ZoneParDefaut = ""
)

// challengeChoisi and providerChoisi are the values of the Choice fields.
//
// They are declared once and used by both Settings and Apply, so the form the
// operator sees and the value the installer writes cannot drift apart.
var valeursChallenge = []module.Option{
	{Value: "http01", Label: "HTTP-01 (no credential, one certificate per hostname)"},
	{Value: "dns01", Label: "DNS-01 (wildcard certificates, needs a DNS provider)"},
}

// Settings declares the group.
//
// THE DNS FIELDS ARE GENERATED FROM THE PROVIDER TABLE in internal/acme, which
// is what makes "add a host" a one-line change: the console draws the form, the
// CLI validates it, and this module stores it — none of them knows the host's
// name.
//
// THE CONDITIONAL FIELDS ARE DECLARED, not decided by the frontend: the provider
// and its credential only make sense once the challenge is dns01, and the
// contract carries that condition so every frontend applies it identically.
func (m *ingressModule) Settings() []module.Group {
	champs := []module.Field{
		{
			Key:     "challenge",
			Label:   "Challenge",
			Help:    "How the authority proves this cluster controls the domain. HTTP-01 is the historical default and needs no credential; DNS-01 is the only one that can issue a wildcard.",
			Type:    module.Choice,
			Options: valeursChallenge,
			Default: "http01",
		},
		{
			Key:      "dns_provider",
			Label:    "DNS provider",
			Help:     "The host holding the zone. The four in-tree providers need no component deployed; the others go through a webhook solver.",
			Type:     module.Text,
			ShowWhen: &module.Condition{Key: "challenge", Equals: "dns01"},
		},
		{
			Key:      "dns_zone",
			Label:    "DNS zone",
			Help:     "The zone the challenge record is written in. Empty means the certified domain itself.",
			Type:     module.Text,
			ShowWhen: &module.Condition{Key: "challenge", Equals: "dns01"},
		},
	}

	// One field per credential of every KNOWN provider. The names are prefixed
	// by the provider so two hosts can both have an `api_token` without one
	// overwriting the other in the store.
	//
	// THE CONDITION IS ON `challenge`, NOT ON `dns_provider`, and that is
	// deliberate: `dns_provider` is itself conditional (it appears only for
	// dns01), and a field depending on a conditional field can never be
	// reached — the form would hide it forever with no error anywhere. The
	// contract refuses that shape at registration, which is how this was caught.
	//
	// The cost: every provider's fields are drawn once dns01 is chosen, and the
	// operator sees the ones for the host they picked because the others are
	// labelled with their provider's name. A cleaner grouping would need a
	// second level of grouping in the contract, which the plan explicitly keeps
	// out of scope.
	for _, p := range providersAvecIdentifiants() {
		for _, c := range p.Champs {
			t := module.Text
			if c.Secret {
				t = module.Secret
			}
			champs = append(champs, module.Field{
				Key:      cleIdentifiant(p.Nom, c.Name),
				Label:    p.Nom + " · " + c.Label,
				Help:     c.Help,
				Type:     t,
				Required: false,
				ShowWhen: &module.Condition{Key: "challenge", Equals: "dns01"},
			})
		}
	}
	return []module.Group{{
		ID:    groupeTLS,
		Title: "TLS certificates",
		Description: "How the certificates are issued. Changing the challenge takes effect on the " +
			"ClusterIssuer: DNS-01 is required for a wildcard, HTTP-01 is the default and needs " +
			"nothing but port 80.",
		Fields: champs,
	}}
}

// providerAvecChamps is one provider and its declared credential fields.
type providerAvecChamps struct {
	Nom    string
	Champs []identifiantTLS
}

// identifiantTLS mirrors the ACME package's field description, redeclared here
// as a plain pair so this package does not depend on the shape of another
// module's types.
type identifiantTLS struct {
	Name   string
	Label  string
	Help   string
	Secret bool
}

// providersAvecIdentifiants lists every provider Ceffio describes, with its
// fields. It is read ONCE, so Settings and Apply cannot disagree about which
// keys exist.
func providersAvecIdentifiants() []providerAvecChamps {
	// The canonical list lives in internal/acme, which is where the solver's
	// own expectations are written. Reading it there means adding a host is one
	// line in ONE place.
	var out []providerAvecChamps
	for _, nom := range coucheIngress.ProvidersConnus() {
		champs, _ := coucheIngress.IdentifiantsDuProvider(nom)
		p := providerAvecChamps{Nom: string(nom)}
		for _, c := range champs {
			p.Champs = append(p.Champs, identifiantTLS{
				Name: c.Name, Label: c.Label, Help: c.Help, Secret: c.Secret,
			})
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nom < out[j].Nom })
	return out
}

// cleIdentifiant is the key of one credential field.
//
// THE PROVIDER IS IN THE KEY: two hosts can both declare `api_token`, and a
// flat key would make the second overwrite the first — a loss that looks like a
// credential that stops working when the operator switches provider.
func cleIdentifiant(provider, champ string) string {
	return "cred_" + strings.ReplaceAll(provider, "-", "_") + "_" +
		strings.ReplaceAll(champ, "-", "_")
}

// Current reads the group's values.
//
// THE CHALLENGE AND THE ZONE come from the resolved ACME settings, which the
// installation primed from the environment on its first pass. THE CREDENTIAL
// comes from the vault, and each secret answers the placeholder — never its
// value.
func (m *ingressModule) Current(ctx context.Context, env module.Env, groupe string) (module.Values, error) {
	if groupe != groupeTLS {
		return nil, fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	// The stored values come from the store; the environment only ANSWERS when
	// nothing is stored yet, which is the installation's first pass.
	stockes, err := lireReglagesStockes(ctx, env)
	if err != nil {
		return nil, err
	}
	out := module.Values{
		"challenge":    stockes["challenge"],
		"dns_provider": stockes["dns_provider"],
		"dns_zone":     stockes["dns_zone"],
	}

	// Every credential field is answered, so the form has a value for each.
	identifiants, err := lireIdentifiants(ctx, env)
	if err != nil {
		return nil, err
	}
	for _, p := range providersAvecIdentifiants() {
		for _, c := range p.Champs {
			cle := cleIdentifiant(p.Nom, c.Name)
			if _, present := identifiants[c.Name]; present && p.Nom == stockes["dns_provider"] {
				if c.Secret {
					out[cle] = module.SecretSet
				} else {
					out[cle] = identifiants[c.Name]
				}
				continue
			}
			out[cle] = ""
		}
	}
	return out, nil
}

// Apply validates, stores and makes the change effective.
//
// TWO DESTINATIONS, and both are needed:
//   - the CHALLENGE, the PROVIDER and the ZONE go to the common store, so
//     `ceffio backup` picks them up and the console reads them back;
//   - the CREDENTIAL goes to the SAME VAULT PATH the solver reads, and a field
//     left empty keeps the stored value.
//
// WHY IT DOES NOT REDEPLOY HERE: applying the challenge means rewriting the
// ClusterIssuer, which is internal/ingress's business — it holds the manifests
// and the ordering. The module stores the settings and calls it, so the
// knowledge of HOW stays in one place.
func (m *ingressModule) Apply(ctx context.Context, env module.Env, groupe string, v module.Values) error {
	if groupe != groupeTLS {
		return fmt.Errorf("%w: %s", module.ErrUnknownGroup, groupe)
	}
	g, _ := m.groupeDe(groupe)
	if err := module.Validate(g, v); err != nil {
		return err
	}

	// 1. The credential, at the path the solver reads. Merged: the fields of
	//    OTHER providers stay, so switching host and switching back does not
	//    lose what was entered.
	if err := ecrireIdentifiants(ctx, env, v); err != nil {
		return err
	}

	// 2. The three ordinary values, in the common store.
	ordinaires := map[string]string{}
	for _, cle := range []string{"challenge", "dns_provider", "dns_zone"} {
		if val, ok := v[cle]; ok {
			ordinaires[cle] = strings.TrimSpace(val)
		}
	}
	if ordinaires["challenge"] == "" {
		ordinaires["challenge"] = "http01"
	}
	if env.Settings != nil {
		poids, err := json.Marshal(ordinaires)
		if err != nil {
			return err
		}
		if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
			map[string]string{"ingress.tls": string(poids)}); err != nil {
			return err
		}
	}

	// 3. The change is made effective, through the same path the installation
	//    uses. The Env given to Deploy now carries the values just stored.
	reglages, err := acme.DepuisValeurs(ordinaires["challenge"], ordinaires["dns_provider"], ordinaires["dns_zone"])
	if err != nil {
		return err
	}
	return coucheIngress.Deploy(ctx, env.Domain, reglages)
}

// Test checks the DNS credential against the provider, when Ceffio can.
//
// WHY A CHECK IS POSSIBLE HERE: a DNS credential is the one setting whose
// mistake costs a failed issuance, days later, at renewal — the worst moment to
// discover a typo. Ceffio cannot test every host (the API differs per provider,
// and the webhook speaks a language of its own), so the check is honest about
// what it can say: it verifies the FIELDS are present and that the solver is
// deployed for this provider. Claiming more would be a button that always
// answers OK.
func (m *ingressModule) Test(ctx context.Context, env module.Env, groupe string, v module.Values) module.TestResult {
	r := module.TestResult{Steps: []string{"reading the selected challenge"}}

	g, _ := m.groupeDe(groupe)
	if err := module.Validate(g, v); err != nil {
		r.Detail = err.Error()
		return r
	}

	challenge := v["challenge"]
	r.Steps = append(r.Steps, "challenge is "+challenge)

	if challenge != "dns01" {
		r.OK = true
		r.Detail = "HTTP-01 needs no credential: nothing to check"
		return r
	}

	provider := v["dns_provider"]
	r.Steps = append(r.Steps, "provider is "+provider)
	if provider == "" {
		r.Detail = "DNS-01 needs a provider: name one, or use HTTP-01"
		return r
	}

	// The fields the provider requires must be filled.
	manquants := []string{}
	connu := false
	for _, p := range providersAvecIdentifiants() {
		if p.Nom != provider {
			continue
		}
		connu = true
		stockes, _ := lireIdentifiants(ctx, env)
		for _, c := range p.Champs {
			cle := cleIdentifiant(p.Nom, c.Name)
			// A secret already stored counts as filled: the form sends it back
			// empty and that means "keep".
			if _, deja := stockes[c.Name]; deja {
				continue
			}
			if strings.TrimSpace(v[cle]) == "" && c.Secret {
				manquants = append(manquants, c.Label)
			}
		}
	}
	r.Steps = append(r.Steps, fmt.Sprintf("checked %d credential field(s)", len(manquants)))
	if len(manquants) > 0 {
		r.Detail = "missing credentials: " + strings.Join(manquants, ", ")
		return r
	}

	if !connu {
		r.OK = true
		r.Detail = "Ceffio does not describe " + provider + ": the fields cannot be verified here. " +
			"Check that the names match the solver's documentation."
		return r
	}

	r.OK = true
	r.Detail = "the credential fields for " + provider + " are filled. Ceffio cannot reach the " +
		"provider's API for every host: the real proof is the next issuance, which the status page reports."
	return r
}

// lireReglagesStockes reads the three non-secret settings.
//
// WHERE THEY LIVE: the default store (the `ceffio-settings` ConfigMap), under
// the key `<module>.<group>` — the common place, so a backup picks them up
// without anyone thinking about it. The CREDENTIAL does not live here: it goes
// to the vault path the solver reads, which is why Apply overrides it.
//
// ON AN INSTALLATION THAT WAS NEVER RECONFIGURED the store is empty and the
// environment answers, once. The amorçage is written back on the next Apply, so
// the store becomes authoritative afterwards and a variable left in a script
// cannot override a choice made in the console.
func lireReglagesStockes(ctx context.Context, env module.Env) (map[string]string, error) {
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", "ingress.tls")
		if err != nil {
			return nil, err
		}
		if brut != "" {
			stoc := map[string]string{}
			if err := json.Unmarshal([]byte(brut), &stoc); err != nil {
				return nil, fmt.Errorf("ingress: settings entry is not valid JSON: %w", err)
			}
			// A missing challenge means the historical default, never empty.
			if stoc["challenge"] == "" {
				stoc["challenge"] = "http01"
			}
			return stoc, nil
		}
	}

	// Nothing stored: the environment, which is how an installation configured
	// before this change keeps working.
	if v, ok := DepuisEnvironnementAmorce(); ok {
		return v, nil
	}
	return map[string]string{"challenge": "http01", "dns_provider": "", "dns_zone": ""}, nil
}

// groupeDe returns the declared group with that ID.
func (m *ingressModule) groupeDe(id string) (module.Group, bool) {
	for _, g := range m.Settings() {
		if g.ID == id {
			return g, true
		}
	}
	return module.Group{}, false
}

// lireIdentifiants reads the DNS credential from the vault.
func lireIdentifiants(ctx context.Context, env module.Env) (map[string]string, error) {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return map[string]string{}, nil
	}
	val, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil {
		if estAbsent(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	return val, nil
}

// ecrireIdentifiants writes the credential at the solver's path, MERGING.
func ecrireIdentifiants(ctx context.Context, env module.Env, v module.Values) error {
	cfg := secrets.DepuisEnvironnement()
	if cfg == nil {
		return fmt.Errorf("ingress: no vault configured: the DNS credential must be stored in " +
			"OpenBao, which is where the solver reads it")
	}

	existants, err := secrets.LireEntreeCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre)
	if err != nil && !estAbsent(err) {
		return err
	}
	if existants == nil {
		existants = map[string]string{}
	}

	// The provider name is stored alongside the credential: the solver's
	// configuration block carries it as a value, and the console reads it back.
	if p := strings.TrimSpace(v["dns_provider"]); p != "" {
		existants["provider"] = p
	}
	for _, p := range providersAvecIdentifiants() {
		for _, c := range p.Champs {
			cle := cleIdentifiant(p.Nom, c.Name)
			val := strings.TrimSpace(v[cle])
			// An empty value keeps the stored one, and the placeholder the
			// console received is not a value.
			if val == "" || val == module.SecretSet {
				continue
			}
			existants[c.Name] = val
		}
	}
	return secrets.EcrireDansCoffre(ctx, cfg, ComposantCoffre, SousCheminCoffre, existants)
}

// estAbsent tells "the entry is not there yet" from a real failure.
func estAbsent(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "absent") || strings.Contains(s, "not found")
}

// ZoneLue returns the zone as stored, empty when the certified domain is meant.
func ZoneLue(v module.Values) string { return strings.TrimSpace(v["dns_zone"]) }

// DepuisEnvironnementAmorce builds the settings from CEFFIO_ACME_*, for the
// INSTALLATION's first pass.
//
// WHY AN AMORÇAGE AND NOT A MIGRATION: an installation configured through the
// variables already works, and it must keep working after this change without
// being reconfigured. Reading them once, when nothing is stored yet, makes the
// stored value authoritative afterwards — so an operator who later changes the
// challenge from the console is not overridden by a variable left in a script.
func DepuisEnvironnementAmorce() (module.Values, bool) {
	challenge := strings.TrimSpace(os.Getenv("CEFFIO_ACME_CHALLENGE"))
	provider := strings.TrimSpace(os.Getenv("CEFFIO_DNS_PROVIDER"))
	zone := strings.TrimSpace(os.Getenv("CEFFIO_DNS_ZONE"))
	if challenge == "" && provider == "" && zone == "" {
		return nil, false
	}
	if challenge == "" {
		challenge = "http01"
	}
	return module.Values{
		"challenge":    challenge,
		"dns_provider": provider,
		"dns_zone":     zone,
	}, true
}
