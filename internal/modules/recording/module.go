// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package recording enveloppe le serveur d'enregistrement des appels Talk en
// module du registre.
//
// POURQUOI UN ENVELOPPEMENT ET NON UNE RÉÉCRITURE : l'installation existe
// déjà dans internal/recording (secrets, Deployment/Service, branchement de
// Talk). La seule fonctionnalité AJOUTÉE par ce lot est la désinstallation —
// elle n'existait nulle part ; elle est écrite dans internal/recording, au
// plus près de l'installation dont elle est le miroir exact.
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
	// Le namespace du serveur d'enregistrement — le même que la couche
	// Talk/signaling/Janus (internal/recording/recording.go, ns).
	nsVideo = "ceffio-video"

	// Le namespace de Nextcloud : le réglage Talk s'y écrit via occ.
	nsNextcloud = "ceffio-files"
)

// recordingModule est le module « recording ».
type recordingModule struct{}

func init() { module.Register(&recordingModule{}) }

// Info décrit le serveur d'enregistrement. Resources est vide : la charge est
// limitée à 2 Gi de RAM (manifeste de deployRecorder) et ne télécharge aucun
// modèle — négligeable devant les composants voisins.
func (m *recordingModule) Info() module.Info {
	return module.Info{
		ID:          "recording",
		Title:       "Recording",
		Description: "Records Talk calls: a hidden participant joins the room, renders it and uploads the result to Nextcloud.",
		Kind:        module.Optional,
		Default:     true,
		Namespaces:  []string{nsVideo},

		// Permissions : sous-ensemble du ClusterRole ceffio-admin-namespaces
		// (internal/console/deploy.go) déjà lié dans ceffio-video, limité à
		// ce que le déploiement touche : le ServiceAccount, le Deployment et
		// le Service du recorder. L'entrée ceffio-files reproduit le Role
		// ceffio-console-occ : le branchement de Talk (config:app:set
		// spreed recording_servers) passe par occ dans le pod Nextcloud.
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

// Install délègue à recording.Deploy, inchangé.
func (m *recordingModule) Install(ctx context.Context, env module.Env) error {
	return recording.Deploy(ctx, env.Domain)
}

// State lit le cluster : le Deployment prêt, et le branchement dans Talk.
//
// POURQUOI DEUX LECTURES : un recorder qui tourne mais que Talk ne connaît
// pas laisse le bouton d'enregistrement grisé — exactement le symptôme que
// l'installation existante corrige, et que l'état doit savoir nommer.
// (La configuration du signaling n'est PAS lue : il n'existe aucun bloc
// [recording] dans sa configuration — voir la note détaillée de
// internal/talk/talk.go, vérifiée contre les sources du signaling. Talk
// appelle le recorder directement en HTTP.)
func (m *recordingModule) State(ctx context.Context, env module.Env) module.State {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes injoignable : " + err.Error()}
	}
	pret := cli.DeploiementPret(ctx, nsVideo, "talk-recording")

	// Le réglage Talk se lit via occ dans le pod Nextcloud. Un exec
	// impossible laisse branche à false, comme pour le déployeur : on ne
	// conclut jamais « branché » sur un échec.
	branche := false
	if pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", "nextcloud"); err == nil {
		if sortie, err := cli.Executer(ctx, nsNextcloud, pod, "nextcloud",
			"php", "occ", "config:app:get", "spreed", "recording_servers"); err == nil {
			// config:app:get renvoie une chaîne vide ou « null » quand le
			// réglage n'a jamais été posé : ni l'une ni l'autre ne veut
			// dire « branché ».
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

// Uninstall délègue à recording.Remove — la fonction ÉCRITE pour ce lot,
// miroir exact de Deploy : elle retire le réglage Talk, le Deployment, le
// Service et le ServiceAccount.
func (m *recordingModule) Uninstall(ctx context.Context, env module.Env) error {
	return recording.Remove(ctx)
}
