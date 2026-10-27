// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package capture exposes the per-participant capture service as a registry
// module.
//
// WHY A SEPARATE MODULE AND NOT AN ADDITION TO recording: recording a meeting
// and transcribing it are two needs. An installation may want the recording
// alone (the .webm) without paying a 1.5 GB image and 4 GiB of RAM; and
// transcription alone, without the recorder, has nothing to transcribe here —
// hence a declared dependency rather than a merge.
package capture

import (
	"context"
	"encoding/json"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/capture"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	groupeTranscription = "transcription"
	cleReglages         = "capture.transcription"

	nsVideo = "ceffio-video"
	nsFiles = "ceffio-files"
)

type captureModule struct{}

func init() { module.Register(&captureModule{}) }

func (m *captureModule) Info() module.Info {
	return module.Info{
		ID:          "capture",
		Title:       "Per-participant capture",
		Description: "Captures one audio track per participant during a Talk recording and writes the named transcript next to the recording.",
		Kind:        module.Optional,
		Default:     false,

		// A recording without the recorder has nothing to transcribe. And that
		// is the ONLY dependency: the capture connects to the signaling with
		// the internal secret, exactly as the recorder does — it needs neither
		// HaRP nor AppAPI. Requiring exapps-daemon would impose, on every
		// installation that records and transcribes, a component that lets
		// Nextcloud start containers, for no reason.
		Requires:   []string{"recording"},
		Namespaces: []string{nsVideo},

		// The service reads its own vault entry, and nothing else: the
		// signaling's shared secret is copied into capture/server by
		// internal/capture, so it never holds a right on talk/*.
		Vault: []module.VaultAccess{{
			ServiceAccount: "ceffio-capture",
			Namespace:      nsVideo,
			Paths:          []string{"kv/data/ceffio/capture/*"},
		}},

		Resources: "~1.5 GB image (model included), 4 GB RAM during transcription",
		// THE DATA-PROTECTION OBLIGATION IS THE FIRST SENTENCE, not a footnote: a
		// named transcript is personal data, and the operator learns it where they
		// decide to install the module — not after a participant complains.
		Warning: "Recording a call and transcribing it processes personal data: the voices " +
			"and the names of the participants. Inform them before the meeting, and fix a " +
			"retention period for the transcript (docs/capture-privacy.md). " +
			"Transcription happens after the call, on this server's CPU; it can take a " +
			"third of the meeting length.",

		// Rights: the deployment itself in ceffio-video, and the two execs
		// described in internal/capture (deposit files, read the recording
		// state).
		Permissions: []module.Permission{
			{
				Namespace: nsVideo,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services", "serviceaccounts", "persistentvolumeclaims"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						// Reading /status goes through services/proxy: `get` on the
						// subresource alone, instead of a right to run commands in
						// the pod.
						APIGroups: []string{""},
						Resources: []string{"services/proxy"},
						Verbs:     []string{"get"},
					},
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"roles", "rolebindings"},
						Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
					},
				},
			},
			{
				Namespace: nsFiles,
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
				},
			},
			// NO RIGHT ON ceffio-data, and its absence is the lot's point: the
			// module no longer reads the recruitment state or the room language
			// from the database, so it must not hold the exec that made it
			// possible. The console therefore cannot create that Role any more
			// either — the permission list is what it is allowed to grant.
		},
	}
}

// Settings declares the two things an operator may want to change. Both land
// in the Deployment's environment, so saving restarts the service — the model
// is loaded once at startup, and the thread count decides how much CPU a
// transcription takes from the calls still running.
func (m *captureModule) Settings() []module.Group {
	return []module.Group{{
		ID:    groupeTranscription,
		Title: "Transcription",
		Description: "The model used after the call, and how much CPU it may take. " +
			"Transcription runs once the recording stops; a larger model is more accurate " +
			"and proportionally slower.",
		Fields: []module.Field{
			{
				Key: "model", Label: "Model", Type: module.Choice, Default: "small",
				Help: "small is part of the image and needs nothing else. medium is fetched " +
					"on first use: without outbound access it must be placed on the /models-extra " +
					"volume, and its absence shows as a failed transcription.",
				Options: []module.Option{
					{Value: "small", Label: "small (included, fast)"},
					{Value: "medium", Label: "medium (more accurate, ~3x slower)"},
				},
			},
			{
				Key: "threads", Label: "CPU threads", Type: module.Number, Default: "4",
				Pattern: "^(?:[1-9]|1[0-6])$",
				Help: "Taken from the same CPU as the calls in progress: raise it only if " +
					"transcription feels too slow and no call is running.",
			},
		},
	}}
}

// Current answers the stored values, or the defaults.
func (m *captureModule) Current(ctx context.Context, env module.Env, group string) (module.Values, error) {
	if group != groupeTranscription {
		return nil, module.ErrUnknownGroup
	}
	stockes := module.Values{"model": "small", "threads": "4"}
	if env.Settings != nil {
		brut, err := env.Settings.Lire(ctx, "ceffio-system", "ceffio-settings", cleReglages)
		if err != nil {
			return nil, err
		}
		if brut != "" {
			if err := json.Unmarshal([]byte(brut), &stockes); err != nil {
				return nil, fmt.Errorf("capture: settings entry is not valid JSON: %w", err)
			}
		}
	}
	return stockes, nil
}

// Apply validates, stores, then pushes the values into the Deployment.
//
// THE CHECK ON medium IS AT RUN TIME, NOT HERE, and that is a deviation from
// the plan worth stating: deciding "is this model available offline" from the
// installer means probing the pod's volume and the machine's egress, and a
// wrong answer blocks a legitimate choice. The service reports a missing model
// as a failed transcription instead — visible in the module state, and
// testable — rather than refusing a setting that may well work.
func (m *captureModule) Apply(ctx context.Context, env module.Env, group string, v module.Values) error {
	if group != groupeTranscription {
		return module.ErrUnknownGroup
	}
	valeurs := module.Values{"model": v["model"], "threads": v["threads"]}
	if valeurs["model"] == "" {
		valeurs["model"] = "small"
	}
	if valeurs["threads"] == "" {
		valeurs["threads"] = "4"
	}
	if err := module.Validate(groupeDe(m), valeurs); err != nil {
		return err
	}

	if env.Settings == nil {
		return fmt.Errorf("capture: no settings store to write to")
	}
	donnees, err := json.Marshal(map[string]string{"model": valeurs["model"], "threads": valeurs["threads"]})
	if err != nil {
		return err
	}
	if err := env.Settings.Ecrire(ctx, "ceffio-system", "ceffio-settings",
		map[string]string{cleReglages: string(donnees)}); err != nil {
		return fmt.Errorf("storing the transcription settings: %w", err)
	}

	cli, err := k8sapi.Nouveau()
	if err != nil {
		return fmt.Errorf("Kubernetes client: %w", err)
	}
	if err := cli.MettreAJourEnv(ctx, nsVideo, "ceffio-capture", "capture", map[string]string{
		"CEFFIO_MODEL":   valeurs["model"],
		"CEFFIO_THREADS": valeurs["threads"],
	}); err != nil {
		return err
	}
	return nil
}

// groupeDe is a tiny helper for module.Validate, which works from the
// declaration, not from the module.
func groupeDe(m *captureModule) module.Group {
	for _, g := range m.Settings() {
		if g.ID == groupeTranscription {
			return g
		}
	}
	return module.Group{}
}

// Install delegates to capture.Deploy.
func (m *captureModule) Install(ctx context.Context, env module.Env) error {
	return capture.Deploy(ctx, env.Domain)
}

// State reads the cluster AND the service, because they answer different
// questions: the Deployment says whether the pod runs, /status says what the
// last recording became. A pod that runs and fails every transcription is not
// "installed" in any useful sense — the plan calls that a silent failure, and
// this is where it stops being silent.
func (m *captureModule) State(ctx context.Context, env module.Env) module.State {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes unreachable: " + err.Error()}
	}
	// ABSENT MEANS NEVER INSTALLED. A crash-looping pod is degraded: telling an
	// operator it is absent sends them looking for an installation that exists.
	if !cli.DeploiementExiste(ctx, nsVideo, "ceffio-capture") {
		return module.State{Status: module.Absent}
	}
	etat := capture.LireEtat(ctx)
	if !etat.Ready {
		return module.State{Status: module.Degraded, Detail: etat.Reason}
	}
	// THE MODEL IS CHECKED BEFORE ANY MEETING. A chosen model that cannot load
	// makes every transcription fail after the fact; saying so while the
	// service is idle is the only moment the operator can still act.
	if pret, ok := etat.Last["model_ready"].(bool); ok && !pret {
		erreur, _ := etat.Last["model_error"].(string)
		if erreur == "" {
			erreur = "the configured model cannot be loaded"
		}
		return module.State{Status: module.Degraded, Detail: "model unusable: " + erreur}
	}
	detail := resumeDernierTravail(etat.Last)
	if etat.Last["result"] == "failed" {
		return module.State{Status: module.Degraded, Detail: detail}
	}
	return module.State{Status: module.Installed, Detail: detail}
}

// resumeDernierTravail turns /status into one line an operator can read.
func resumeDernierTravail(dernier map[string]any) string {
	switch dernier["result"] {
	case "transcribed":
		return "last recording transcribed"
	case "running":
		return "transcribing a recording now"
	case "failed":
		if erreur, ok := dernier["error"].(string); ok && erreur != "" {
			return "last recording failed: " + erreur
		}
		return "last recording failed"
	default:
		return "no recording since the service started"
	}
}

// Uninstall delegates to capture.Supprime.
func (m *captureModule) Uninstall(ctx context.Context, env module.Env) error {
	return capture.Supprime(ctx)
}
