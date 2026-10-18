// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package recording wraps the Talk call recording server as a registry
// module.
//
// WHY A WRAPPER AND NOT A REWRITE: the install already exists in
// internal/recording (secrets, Deployment/Service, Talk wiring). The only
// feature ADDED by this batch is the uninstall — it existed nowhere; it is
// written in internal/recording, as close as possible to the install it
// mirrors exactly.
package recording

import (
	"context"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
	recording "github.com/ceffio-suite/ceffio/internal/recording"
)

const (
	// The recording server namespace — the same as the
	// Talk/signaling/Janus layer (internal/recording/recording.go, ns).
	nsVideo = "ceffio-video"

	// The Nextcloud namespace: the Talk setting is written there via occ.
	nsNextcloud = "ceffio-files"
)

// recordingModule is the "recording" module.
type recordingModule struct{}

func init() { module.Register(&recordingModule{}) }

// Info describes the recording server. Resources is empty: the workload is
// limited to 2 Gi of RAM (deployRecorder manifest) and downloads no model —
// negligible next to the neighbouring components.
func (m *recordingModule) Info() module.Info {
	return module.Info{
		ID:          "recording",
		Title:       "Recording",
		Description: "Records Talk calls: a hidden participant joins the room, renders it and uploads the result to Nextcloud.",
		Kind:        module.Optional,
		Default:     true,
		Namespaces:  []string{nsVideo},

		// Permissions: a subset of the ClusterRole ceffio-admin-namespaces
		// (internal/console/deploy.go) already bound in ceffio-video,
		// limited to what the deployment touches: the ServiceAccount, the
		// Deployment and the Service of the recorder. The ceffio-files
		// entry reproduces the Role ceffio-console-occ: the Talk wiring
		// (config:app:set spreed recording_servers) goes through occ in
		// the Nextcloud pod.
		Permissions: []module.Permission{
			{
				Namespace: nsVideo,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services", "serviceaccounts"},
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

// Install delegates to recording.Deploy, unchanged.
func (m *recordingModule) Install(ctx context.Context, env module.Env) error {
	return recording.Deploy(ctx, env.Domain)
}

// State reads the cluster: the Deployment ready, and the wiring in Talk.
//
// WHY TWO READS: a recorder that runs but that Talk does not know leaves the
// recording button greyed out — exactly the symptom the existing install
// fixes, and that the state must be able to name.
// (The signaling configuration is NOT read: there is no [recording] block in
// its configuration — see the detailed note in internal/talk/talk.go,
// verified against the signaling sources. Talk calls the recorder directly
// over HTTP.)
func (m *recordingModule) State(ctx context.Context, env module.Env) module.State {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes injoignable : " + err.Error()}
	}
	pret := cli.DeploiementPret(ctx, nsVideo, "talk-recording")

	// The Talk setting is read via occ in the Nextcloud pod. An impossible
	// exec leaves branche at false, like for the deployer: we never
	// conclude "wired" on a failure.
	branche := false
	if pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", "nextcloud"); err == nil {
		if sortie, err := cli.Executer(ctx, nsNextcloud, pod, "nextcloud",
			"php", "occ", "config:app:get", "spreed", "recording_servers"); err == nil {
			// config:app:get returns an empty string or "null" when the
			// setting has never been set: neither one means "wired".
			valeur := strings.TrimSpace(sortie)
			branche = valeur != "" && valeur != "null"
		}
	}

	switch {
	case pret && branche:
		return module.State{Status: module.Installed}
	case pret && !branche:
		return module.State{
			Status: module.Degraded,
			Detail: "Le serveur tourne mais n'est pas declare dans Talk : le bouton d'enregistrement resterait grise.",
		}
	case !pret && branche:
		return module.State{
			Status: module.Degraded,
			Detail: "Declare dans Talk, mais le pod du serveur d'enregistrement est absent.",
		}
	default:
		return module.State{Status: module.Absent}
	}
}

// Uninstall delegates to recording.Remove — the function WRITTEN for this
// batch, the exact mirror of Deploy: it removes the Talk setting, the
// Deployment, the Service and the ServiceAccount.
func (m *recordingModule) Uninstall(ctx context.Context, env module.Env) error {
	return recording.Remove(ctx)
}
