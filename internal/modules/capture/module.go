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

		// A recording without the recorder has nothing to transcribe, and the
		// capture joins the call through the same signaling as live
		// transcription: exapps-daemon must be there.
		Requires:   []string{"recording", "exapps-daemon"},
		Namespaces: []string{nsVideo},

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

// State reads the cluster: is the Deployment ready?
func (m *captureModule) State(ctx context.Context, env module.Env) module.State {
	if _, err := k8sapi.Nouveau(); err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes unreachable: " + err.Error()}
	}
	if capture.Etat(ctx) {
		return module.State{Status: module.Installed}
	}
	return module.State{Status: module.Absent}
}

// Uninstall delegates to capture.Supprime.
func (m *captureModule) Uninstall(ctx context.Context, env module.Env) error {
	return capture.Supprime(ctx)
}
