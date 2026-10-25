// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package capture expose le service de capture par participant comme module
// du registre.
//
// POURQUOI UN MODULE SÉPARÉ ET PAS UN AJOUT AU MODULE RECORDING : enregistrer
// une réunion et la transcrire sont deux besoins distincts. Une installation
// peut vouloir l'enregistrement seul (le .webm) sans payer 1,5 Go d'image et
// 4 Gi de RAM ; et la transcription seule, sans le recorder, n'a pas de sens
// ici — d'où la dépendance déclarée, pas la fusion.
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
	nomWork = "ceffio-capture"
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

		// Un enregistrement sans recorder n'aurait rien à transcrire, et la
		// capture rejoint l'appel par le même signaling que la transcription
		// en direct : exapps-daemon doit être là.
		Requires:   []string{"recording", "exapps-daemon"},
		Namespaces: []string{nsVideo},

		Resources: "~1,5 GB image, 4 GB RAM during transcription",
		Warning:   "Transcription happens after the call, on the CPU of this server; it can take a third of the meeting length.",

		// Droits : le déploiement lui-même dans ceffio-video, et les deux
		// execs décrits dans internal/capture (dépôt des fichiers, lecture de
		// l'état d'enregistrement).
		Permissions: []module.Permission{
			{
				Namespace: nsVideo,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services", "serviceaccounts", "persistentvolumeclaims", "secrets"},
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

// Install délègue à capture.Deploy.
func (m *captureModule) Install(ctx context.Context, env module.Env) error {
	return capture.Deploy(ctx, env.Domain)
}

// State lit le cluster : le Deployment est-il prêt ?
func (m *captureModule) State(ctx context.Context, env module.Env) module.State {
	if _, err := k8sapi.Nouveau(); err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes injoignable : " + err.Error()}
	}
	if capture.Etat(ctx) {
		return module.State{Status: module.Installed}
	}
	return module.State{Status: module.Absent}
}

// Uninstall délègue à capture.Supprime.
func (m *captureModule) Uninstall(ctx context.Context, env module.Env) error {
	return capture.Supprime(ctx)
}
