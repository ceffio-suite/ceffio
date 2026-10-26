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

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/capture"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	nsVideo = "ceffio-video"
	nsFiles = "ceffio-files"
	nsData  = "ceffio-data"
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

		Resources: "~1.5 GB image (model included), 4 GB RAM during transcription",
		Warning:   "Transcription happens after the call, on this server's CPU; it can take a third of the meeting length.",

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
			{
				Namespace: nsData,
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
				},
			},
		},
	}
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
