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
		Warning:   "Its settings cannot be changed once installed — the app has to be removed and installed again.",

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
	return exapps.TranscriptionDeploye(ctx, env.Domain)
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
