// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package settings stores what a module's operator settings hold.
//
// WHY A COMMON PLACE, shared by every module: settings end up in the same spot,
// they are picked up by `ceffio backup` without anyone thinking about it, and
// they stay readable with kubectl during an incident. Four modules each
// inventing their own storage would produce four places to look and four things
// to forget in a backup.
//
// WHY IT IS NOT IN internal/module: that package describes settings and must
// import nothing internal — every module imports it. Storing is a different
// concern from describing, and a module that needs neither can ignore this
// package entirely.
//
// A MODULE MAY STORE ELSEWHERE when it has a reason: a credential already read
// by another component (the DNS solver, for instance) must stay at the path that
// component reads. Such a module overrides Current and Apply and says why in its
// code. The default here is the common case, not an obligation.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/secrets"
)

// Namespace et noms des objets Kubernetes qui portent les réglages.
const (
	// Namespace is where every ordinary setting lives. ceffio-system because
	// that is where the console reads them from and where the rest of the
	// platform's own configuration already sits.
	Namespace = "ceffio-system"
	// ConfigMapNom holds all ordinary settings, one key per `<module>.<group>`.
	//
	// WHY ONE CONFIGMAP AND NOT ONE PER MODULE: the values are small, they are
	// read together by a backup, and a single object is one thing to restore.
	// A ConfigMap per module would multiply the objects to enumerate for no
	// gain.
	ConfigMapNom = "ceffio-settings"
	// prefixeSecret is the prefix of the per-module Kubernetes Secret used when
	// no vault is configured.
	prefixeSecret = "ceffio-settings-"
)

// clientConfigMap abstracts the Kubernetes ConfigMap access, so the package can
// be tested without a cluster.
type clientConfigMap interface {
	Lire(ctx context.Context, ns, nom, cle string) (string, error)
	Ecrire(ctx context.Context, ns, nom string, donnees map[string]string) error
	Supprimer(ctx context.Context, ns, nom, cle string) error
}

// Load reads one group's values.
//
// SECRET FIELDS NEVER COME BACK FROM HERE AS THEIR VALUE: this function is the
// one place that reads a stored secret on behalf of a frontend, so it is where
// the rule "a secret does not travel back to a browser" is enforced — not in
// each frontend, where it would be enforced differently or forgotten. A Set
// secret answers module.SecretSet; an unset one answers "".
//
// Ordinary values answer the stored value, or the field's Default when nothing
// is stored. The default is RETURNED, never written: storing it would freeze it,
// and a module changing its default later would not reach existing
// installations.
func Load(ctx context.Context, env module.Env, groupe module.Group) (module.Values, error) {
	if err := verifierModuleID(env); err != nil {
		return nil, err
	}
	out := make(module.Values, len(groupe.Fields))
	for _, f := range groupe.Fields {
		if f.Default != "" {
			out[f.Key] = f.Default
		} else {
			out[f.Key] = ""
		}
	}

	// 1. Ordinary values, from the ConfigMap.
	brut, err := lireConfigMap(ctx, env, groupe)
	if err != nil {
		return nil, err
	}
	ordinaires := map[string]string{}
	if brut != "" {
		if err := json.Unmarshal([]byte(brut), &ordinaires); err != nil {
			// A corrupted entry must NOT be silently replaced by defaults: the
			// operator would see their settings vanish and believe they were
			// never saved. Naming the problem is what lets them look.
			return nil, fmt.Errorf("settings: entry %q is not valid JSON: %w", cleConfigMap(groupe), err)
		}
	}
	for cle, v := range ordinaires {
		// Only keys the group declares are returned: a key left behind by a
		// removed field must not reappear in a form.
		for _, f := range groupe.Fields {
			if f.Key == cle && f.Type != module.Secret {
				out[cle] = v
			}
		}
	}

	// 2. Secrets, from the vault or from the Kubernetes Secret.
	stockes, err := lireSecrets(ctx, env, groupe)
	if err != nil {
		return nil, err
	}
	for _, f := range groupe.Fields {
		if f.Type != module.Secret {
			continue
		}
		if _, ok := stockes[f.Key]; ok {
			out[f.Key] = module.SecretSet
		} else {
			out[f.Key] = ""
		}
	}
	return out, nil
}

// Save writes one group's values.
//
// THE RULE OF THE EMPTY SECRET IS APPLIED HERE, once: an empty Secret keeps the
// stored value instead of erasing it. A frontend cannot be trusted to remember
// it — the form submits every field it drew, and the password field is empty
// because the value never reached the browser.
func Save(ctx context.Context, env module.Env, groupe module.Group, v module.Values) error {
	if err := verifierModuleID(env); err != nil {
		return err
	}
	if err := module.Validate(groupe, v); err != nil {
		return err
	}

	// Ordinary values replace the whole entry: the group IS the unit, and
	// merging would leave behind the keys of a field that no longer exists.
	ordinaires := map[string]string{}
	for _, f := range groupe.Fields {
		if f.Type == module.Secret {
			continue
		}
		if val, ok := v[f.Key]; ok {
			ordinaires[f.Key] = val
		}
	}
	if err := ecrireConfigMap(ctx, env, groupe, ordinaires); err != nil {
		return err
	}

	// Secrets are MERGED, so a field left empty keeps what is stored.
	nouveaux := map[string]string{}
	for _, f := range groupe.Fields {
		if f.Type != module.Secret {
			continue
		}
		val := strings.TrimSpace(v[f.Key])
		// An empty value is not written; SecretSet is the placeholder the
		// console received, and writing it would store the placeholder itself.
		if val == "" || val == module.SecretSet {
			continue
		}
		nouveaux[f.Key] = val
	}
	if len(nouveaux) == 0 {
		return nil
	}
	return ecrireSecrets(ctx, env, groupe, nouveaux)
}

// Forget removes one group's stored values, secrets included.
//
// Used when a module is uninstalled: leaving a credential behind keeps a live
// credential on an installation that believes the feature is gone.
func Forget(ctx context.Context, env module.Env, groupe module.Group) error {
	if err := supprimerConfigMap(ctx, env, groupe); err != nil {
		return err
	}
	return supprimerSecrets(ctx, env, groupe)
}

// cleConfigMap is the key of a group's entry.
//
// WHY `<module>.<group>` AND NOT ONE KEY PER FIELD: the group is edited and
// saved as a unit, so storing it as one JSON value means a read gets a coherent
// set — never a half-written form, and never two entries disagreeing about the
// same group.
func cleConfigMap(groupe module.Group) string {
	return groupe.ID
}

// --- Accès ConfigMap -------------------------------------------------------

func lireConfigMap(ctx context.Context, env module.Env, groupe module.Group) (string, error) {
	if env.Settings == nil {
		// No access configured: an installation that has not created the
		// ConfigMap yet, or a caller that reads only (the status page). Empty
		// is the honest answer, and defaults were already applied.
		return "", nil
	}
	return env.Settings.Lire(ctx, Namespace, ConfigMapNom, cleConfigMap(groupe))
}

func ecrireConfigMap(ctx context.Context, env module.Env, groupe module.Group, v map[string]string) error {
	donnees, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("settings: encoding %s: %w", cleConfigMap(groupe), err)
	}
	if env.Settings == nil {
		return fmt.Errorf("settings: no store is configured, cannot save %s", cleConfigMap(groupe))
	}
	return env.Settings.Ecrire(ctx, Namespace, ConfigMapNom, map[string]string{
		cleConfigMap(groupe): string(donnees),
	})
}

func supprimerConfigMap(ctx context.Context, env module.Env, groupe module.Group) error {
	if env.Settings == nil {
		return nil
	}
	return env.Settings.Supprimer(ctx, Namespace, ConfigMapNom, cleConfigMap(groupe))
}

// --- Accès secrets ---------------------------------------------------------

// cheminsSecrets returns the vault component and entry of a group.
//
// WHY `<module>/<group>` AND NOT A FLAT NAME: two modules can each have a group
// named "relay", and a flat namespace would make them collide — one module's
// credential silently overwriting the other's.
func cheminsSecrets(groupe module.Group, moduleID string) (composant, nom string) {
	return "settings/" + moduleID, groupe.ID
}

func lireSecrets(ctx context.Context, env module.Env, groupe module.Group) (map[string]string, error) {
	if cfg := secrets.DepuisEnvironnement(); cfg != nil {
		composant, nom := cheminsSecrets(groupe, moduleID(env))
		val, err := secrets.LireEntreeCoffre(ctx, cfg, composant, nom)
		if err == nil {
			return val, nil
		}
		// The vault is reachable but the entry is absent: that is a normal
		// state BEFORE the first save, not a failure. Any other error is
		// returned, because silently falling back would hide a vault that has
		// become unreachable and make the operator believe their secret is
		// gone.
		if !estEntreeAbsente(err) {
			return nil, err
		}
		return map[string]string{}, nil
	}

	// No vault: the Kubernetes Secret, as everywhere else in Ceffio.
	if env.Secrets == nil {
		return map[string]string{}, nil
	}
	return env.Secrets.Lire(ctx, Namespace, prefixeSecret+moduleID(env), groupe.ID)
}

func ecrireSecrets(ctx context.Context, env module.Env, groupe module.Group, v map[string]string) error {
	if cfg := secrets.DepuisEnvironnement(); cfg != nil {
		composant, nom := cheminsSecrets(groupe, moduleID(env))
		// MERGE with what is stored: a save that changes only one secret must
		// not drop the others.
		existants, err := secrets.LireEntreeCoffre(ctx, cfg, composant, nom)
		if err != nil && !estEntreeAbsente(err) {
			return err
		}
		if existants == nil {
			existants = map[string]string{}
		}
		for k, val := range v {
			existants[k] = val
		}
		return secrets.EcrireDansCoffre(ctx, cfg, composant, nom, existants)
	}

	if env.Secrets == nil {
		return fmt.Errorf("settings: no vault and no secret store, cannot save secrets of %s", groupe.ID)
	}
	existants, err := env.Secrets.Lire(ctx, Namespace, prefixeSecret+moduleID(env), groupe.ID)
	if err != nil {
		return err
	}
	if existants == nil {
		existants = map[string]string{}
	}
	for k, val := range v {
		existants[k] = val
	}
	return env.Secrets.Ecrire(ctx, Namespace, prefixeSecret+moduleID(env), existants)
}

func supprimerSecrets(ctx context.Context, env module.Env, groupe module.Group) error {
	if cfg := secrets.DepuisEnvironnement(); cfg != nil {
		composant, nom := cheminsSecrets(groupe, moduleID(env))
		val, err := secrets.LireEntreeCoffre(ctx, cfg, composant, nom)
		if err != nil {
			if estEntreeAbsente(err) {
				return nil
			}
			return err
		}
		for k := range val {
			delete(val, k)
		}
		return secrets.EcrireDansCoffre(ctx, cfg, composant, nom, val)
	}
	if env.Secrets == nil {
		return nil
	}
	existants, err := env.Secrets.Lire(ctx, Namespace, prefixeSecret+moduleID(env), groupe.ID)
	if err != nil {
		return err
	}
	for k := range existants {
		delete(existants, k)
	}
	return env.Secrets.Ecrire(ctx, Namespace, prefixeSecret+moduleID(env), existants)
}

// estEntreeAbsente tells "the entry is not there yet" from a real failure.
//
// The vault answers 404 for an absent entry, which the client reports as an
// error carrying the status. Treating it as a failure would make the FIRST save
// of every module fail, and every module would have to work around it.
func estEntreeAbsente(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "404") || strings.Contains(s, "absent") || strings.Contains(s, "not found")
}

// moduleID recovers the module ID from the Env the module was given.
//
// WHY IT IS PASSED THROUGH Env AND NOT AS AN ARGUMENT: Load/Save are called by
// the module itself, which knows its own ID — threading it through every call
// would carry a value the module cannot get wrong. Env carries it, so there is
// one answer to "which module is this?".
//
// AN EMPTY ID IS REFUSED by Load and Save (verifierModuleID), not papered over
// here: a sentinel value would write every module's settings to the same place,
// silently, and the collision would look like settings that vanish.
func moduleID(env module.Env) string {
	return env.ModuleID
}

// verifierModuleID refuses an Env that does not say which module it is for.
//
// Without this check the settings would be stored under an empty name: two
// modules would share one entry, and saving one group would erase another's
// values — a corruption that looks like a lost setting, with nothing in the log
// to explain it.
func verifierModuleID(env module.Env) error {
	if env.ModuleID == "" {
		return fmt.Errorf("settings: Env.ModuleID is empty: the caller must say which module " +
			"these settings belong to, otherwise two modules share one entry")
	}
	return nil
}

// clesTriees gives a stable order, for logs and tests.
func clesTriees(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
