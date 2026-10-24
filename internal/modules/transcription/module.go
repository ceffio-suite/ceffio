// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package transcription wraps live transcription (Talk ExApp) as a registry
// module.
//
// WHY A WRAPPER AND NOT A REWRITE: the full install (registration +
// activation + verification) and removal already exist in internal/exapps.
// This package plugs them into module.Module; the state logic is MOVED here
// from the console (repondreEtatTranscription,
// internal/console/transcription.go) so that the CLI and the console query
// AppAPI in exactly the same way.
package transcription

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/exapps"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	// The app identifier, as Nextcloud knows it — the same as
	// internal/exapps/transcription.go (appTranscription, unexported).
	appTranscription = "live_transcription"

	// The namespaces involved: the ExApp one (the workload HaRP deploys
	// there) and the Nextcloud one (the occ that drives AppAPI).
	nsExapps    = "ceffio-exapps"
	nsNextcloud = "ceffio-files"
)

// transcriptionModule is the "live-transcription" module.
type transcriptionModule struct{}

func init() { module.Register(&transcriptionModule{}) }

// Info describes the app. Resources and Warning are taken VERBATIM from the
// existing texts: the comment of internal/exapps/transcription.go (weight
// and irreversibility of the environment variables) and
// internal/console/web/index.html (Transcription tab).
func (m *transcriptionModule) Info() module.Info {
	return module.Info{
		ID:          "live-transcription",
		Title:       "Live transcription",
		Description: "Transcribes speech live during a Talk call, on this server, with open source speech models. Nothing is sent to a third party.",
		Kind:        module.Optional,
		Default:     false,

		// The app cannot install without the deployer: it is HaRP that
		// creates its workload. The dependency is declared here, and the
		// registry (module.All, module.Blocked) derives the order and the
		// blocking from it — the console no longer has to recompute.
		Requires:   []string{"exapps-daemon"},
		Namespaces: []string{nsExapps},

		Resources: "~9 GB disk, ~16 GB RAM",
		Warning:   "Its signaling settings are fixed at installation: changing them means removing and reinstalling the app. The speech languages, themselves, can be changed at any time.",

		// Permissions: the app lives in ceffio-exapps (workload, Service,
		// PVC created by HaRP — the console lists them for state and
		// cleanup), and its installation goes through occ in the Nextcloud
		// pod. The rules reproduce the subset of the ClusterRole
		// ceffio-admin-namespaces (internal/console/deploy.go) already
		// granted in these namespaces, and the ceffio-files entry
		// reproduces the Role ceffio-console-occ.
		Permissions: []module.Permission{
			{
				Namespace: nsExapps,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services", "persistentvolumeclaims"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
				},
			},
			{
				Namespace: nsNextcloud,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "list"},
					},
					{
						APIGroups: []string{""},
						Resources: []string{"pods/exec"},
						Verbs:     []string{"create"},
					},
				},
			},
		},
	}
}

// Install delegates to exapps.TranscriptionDeploye, unchanged: registration
// WITHOUT --wait-finish, activation, then a re-read of the state.
func (m *transcriptionModule) Install(ctx context.Context, env module.Env) error {
	langues, err := languesConfigurees(ctx, env)
	if err != nil {
		return err
	}
	return exapps.TranscriptionDeploye(ctx, env.Domain, langues)
}

// languesConfigurees returns the languages stored by the operator, or the
// default when the setting was never touched.
//
// IT GOES THROUGH Current (and not straight to the ConfigMap) so that the
// default exists in ONE place: a module that duplicated it here would drift
// from the one the console shows.
func languesConfigurees(ctx context.Context, env module.Env) ([]string, error) {
	v, err := (&transcriptionModule{}).Current(ctx, env, groupeLangues)
	if err != nil {
		return nil, err
	}
	return exapps.LanguesDepuisListe(v["codes"])
}

// groupeLangues is the settings group holding the speech languages.
const groupeLangues = "languages"

// cleReglages is the shared ConfigMap key, under the module's own prefix.
const cleReglages = "transcription.languages"

// Settings declares the only thing an operator has to choose: which languages
// this installation must be able to transcribe.
//
// WHY IT IS A SETTING AND NOT A CONSTANT: the ExApp downloads its models on
// first use, over the internet, taking minutes and failing outright on a
// machine that has none. What is placed at installation is what works out of
// the box, so the list is the operator's decision — a French-only platform and
// an Arabic-and-French one do not need the same 6 GB.
func (m *transcriptionModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeLangues,
		Title: "Speech languages",
		Description: "The speech models placed on disk. They are what works on the first call: " +
			"a language left out is downloaded by the app when it is first used, which needs " +
			"internet and makes that call wait.",
		Fields: []module.Field{{
			Key:      "codes",
			Label:    "Languages",
			Type:     module.Text,
			Default:  strings.Join(exapps.LanguesParDefaut, ","),
			Required: true,
			Help: "Comma-separated Vosk codes, for example fr,ar. Known codes: " +
				strings.Join(exapps.ModelesConnus(), ", ") +
				". French costs 68 MB, English 2.9 GB, Arabic 700 MB.",
		}},
	}}
}

// Current returns the stored list, or the default.
func (m *transcriptionModule) Current(ctx context.Context, env module.Env, group string) (module.Values, error) {
	if group != groupeLangues {
		return nil, module.ErrUnknownGroup
	}
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", cleReglages)
		if err != nil {
			return nil, err
		}
		if brut != "" {
			var stoc struct {
				Codes string `json:"codes"`
			}
			if err := json.Unmarshal([]byte(brut), &stoc); err != nil {
				return nil, fmt.Errorf("transcription: settings entry is not valid JSON: %w", err)
			}
			if codes := strings.TrimSpace(stoc.Codes); codes != "" {
				return module.Values{"codes": codes}, nil
			}
		}
	}
	return module.Values{"codes": strings.Join(exapps.LanguesParDefaut, ",")}, nil
}

// Apply validates the list, stores it normalised, then PLACES THE MODELS.
//
// The last step is the point: an operator who adds Arabic expects Arabic to
// work when they close the page, not at a hypothetical reinstall. The download
// is idempotent, so re-saving the same list costs nothing.
func (m *transcriptionModule) Apply(ctx context.Context, env module.Env, group string, v module.Values) error {
	if group != groupeLangues {
		return module.ErrUnknownGroup
	}

	langues, err := exapps.LanguesDepuisListe(v["codes"])
	if err != nil {
		return fmt.Errorf("%w: languages: %v", module.ErrInvalidSettings, err)
	}
	normalise := strings.Join(langues, ",")

	if env.Settings == nil {
		return fmt.Errorf("transcription: no settings store to write to")
	}
	donnees, err := json.Marshal(map[string]string{"codes": normalise})
	if err != nil {
		return err
	}
	if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
		map[string]string{cleReglages: string(donnees)}); err != nil {
		return fmt.Errorf("storing the language list: %w", err)
	}

	if env.Out != nil {
		fmt.Fprintf(env.Out, "∙ placing the speech models: %s\n", normalise)
	}
	if err := exapps.PlacerModeles(ctx, langues); err != nil {
		return fmt.Errorf("placing the models for %s: %w", normalise, err)
	}
	if env.Out != nil {
		fmt.Fprintf(env.Out, "  ✓ speech models in place: %s\n", normalise)
	}
	return nil
}

// Test answers the only question worth answering about this setting: are the
// models the list promises actually on disk?
//
// It is what turns "transcription is installed" into "transcription can
// transcribe": the app is enabled and reachable long before its models exist.
func (m *transcriptionModule) Test(ctx context.Context, env module.Env, group string, v module.Values) module.TestResult {
	if group != groupeLangues {
		return module.TestResult{Detail: "unknown settings group"}
	}
	langues, err := exapps.LanguesDepuisListe(v["codes"])
	if err != nil {
		return module.TestResult{Detail: err.Error()}
	}
	absents, err := exapps.ModelesAbsents(ctx, langues)
	if err != nil {
		return module.TestResult{Detail: "cannot read the ExApp volume: " + err.Error()}
	}
	if len(absents) > 0 {
		return module.TestResult{Detail: "no model on disk for " + strings.Join(absents, ", ") +
			": the app downloads it on the first call, which needs internet and fails without it."}
	}
	return module.TestResult{OK: true, Detail: "every configured language has its model on disk."}
}

// State is the logic of repondreEtatTranscription
// (internal/console/transcription.go), MOVED here as-is: AppAPI is queried
// via occ — never a file, never a guess — and a failed query yields Unknown,
// NOT Absent.
//
// The blocking (deployer unavailable) is computed by module.Blocked: it is
// the exact equivalent of the call to exapps.DeployeurPret the console made
// to grey out the button, but expressed through the declared dependency.
func (m *transcriptionModule) State(ctx context.Context, env module.Env) module.State {
	etat := module.State{Blocked: module.Blocked(ctx, env, m)}

	// occ runs through the Kubernetes API (remotecommand): the console
	// container is distroless, with neither shell nor kubectl. k8sapi.Client
	// is the single path already proven in both contexts.
	cli, err := k8sapi.Nouveau()
	if err != nil {
		etat.Status = module.Unknown
		etat.Detail = "Kubernetes injoignable : " + err.Error()
		return etat
	}
	pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", "nextcloud")
	if err != nil {
		etat.Status = module.Unknown
		etat.Detail = "Pod Nextcloud introuvable : " + err.Error()
		return etat
	}
	sortie, err := cli.Executer(ctx, nsNextcloud, pod, "nextcloud",
		"php", "occ", "app_api:app:list")
	if err != nil {
		// We do NOT conclude "absent" on a failure: the app may already
		// be running, and offering an install on top of it would be worse
		// than saying we do not know.
		etat.Status = module.Unknown
		etat.Detail = "AppAPI injoignable : " + strings.TrimSpace(err.Error())
		return etat
	}

	if ligne := ligneAppareillee(sortie, appTranscription); ligne != "" {
		etat.Status = module.Installed
		etat.Detail = ligne
		return etat
	}
	etat.Status = module.Absent
	return etat
}

// Uninstall delegates to exapps.TranscriptionSupprime, unchanged:
// deactivation, deregistration (HaRP then deletes the workload, the Service
// and the volume), wait for the actual disappearance.
func (m *transcriptionModule) Uninstall(ctx context.Context, env module.Env) error {
	return exapps.TranscriptionSupprime(ctx)
}

// ligneAppareillee returns the first line that MENTIONS the app, or "".
//
// Taken from internal/console/transcription.go: we work line by line rather
// than with a global "contains" — the name also appears in the labels, and a
// global contains would declare installed an app that is merely mentioned.
func ligneAppareillee(texte, app string) string {
	for _, l := range strings.Split(texte, "\n") {
		prop := strings.TrimSpace(l)
		if prop == "" || strings.HasPrefix(prop, "Command") {
			continue
		}
		if strings.Contains(prop, app) {
			return prop
		}
	}
	return ""
}
