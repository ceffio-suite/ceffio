// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package transcription enveloppe la transcription en direct (ExApp Talk) en
// module du registre.
//
// POURQUOI UN ENVELOPPEMENT ET NON UNE RÉÉCRITURE : l'installation
// (enregistrement + activation + vérification) et la suppression complètes
// existent déjà dans internal/exapps. Ce package les branche sur
// module.Module ; la logique d'état est DÉPLACÉE ici depuis la console
// (repondreEtatTranscription, internal/console/transcription.go) pour que le
// CLI et la console interrogent AppAPI exactement de la même façon.
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
	// L'identifiant de l'app, tel que Nextcloud la connaît — le même que
	// internal/exapps/transcription.go (appTranscription, non exporté).
	appTranscription = "live_transcription"

	// Les namespaces concernés : celui des ExApp (la charge de travail que
	// HaRP y déploie) et celui de Nextcloud (l'occ qui pilote AppAPI).
	nsExapps    = "ceffio-exapps"
	nsNextcloud = "ceffio-files"
)

// transcriptionModule est le module « live-transcription ».
type transcriptionModule struct{}

func init() { module.Register(&transcriptionModule{}) }

// Info décrit l'app. Resources et Warning sont repris TELS QUELS des textes
// existants : le commentaire de internal/exapps/transcription.go (poids et
// irréversibilité des variables d'environnement) et
// internal/console/web/index.html (onglet Transcription).
func (m *transcriptionModule) Info() module.Info {
	return module.Info{
		ID:          "live-transcription",
		Title:       "Live transcription",
		Description: "Transcribes speech live during a Talk call, on this server, with open source speech models. Nothing is sent to a third party.",
		Kind:        module.Optional,
		Default:     false,

		// L'app ne peut pas s'installer sans le déployeur : c'est HaRP qui
		// crée sa charge de travail. La dépendance est déclarée ici, et le
		// registre (module.All, module.Blocked) en tire l'ordre et le
		// blocage — la console n'a plus à recalculer.
		Requires:   []string{"exapps-daemon"},
		Namespaces: []string{nsExapps},

		Resources: "~9 GB disk, ~16 GB RAM",
		Warning:   "Its settings cannot be changed once installed — the app has to be removed and installed again.",

		// Permissions : l'app vit dans ceffio-exapps (charge, Service, PVC
		// créés par HaRP — la console les liste pour l'état et le nettoyage),
		// et son installation passe par occ dans le pod Nextcloud. Les règles
		// reprennent le sous-ensemble du ClusterRole ceffio-admin-namespaces
		// (internal/console/deploy.go) déjà accordé dans ces namespaces, et
		// l'entrée ceffio-files reproduit le Role ceffio-console-occ.
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

// Install délègue à exapps.TranscriptionDeploye, inchangé : enregistrement
// SANS --wait-finish, activation, puis relecture de l'état.
func (m *transcriptionModule) Install(ctx context.Context, env module.Env) error {
	return exapps.TranscriptionDeploye(ctx, env.Domain)
}

// State est la logique de repondreEtatTranscription
// (internal/console/transcription.go), DÉPLACÉE ici telle quelle : on
// interroge AppAPI via occ — jamais un fichier ni une supposition — et un
// échec d'interrogation donne Unknown, PAS Absent.
//
// Le blocage (déployeur indisponible) est calculé par module.Blocked : c'est
// l'équivalent exact de l'appel à exapps.DeployeurPret que faisait la console
// pour griser le bouton, mais exprimé à travers la dépendance déclarée.
func (m *transcriptionModule) State(ctx context.Context, env module.Env) module.State {
	etat := module.State{Blocked: module.Blocked(ctx, env, m)}

	// occ s'exécute via l'API Kubernetes (remotecommand) : le conteneur de
	// la console est distroless, sans shell ni kubectl. k8sapi.Client est le
	// chemin unique déjà éprouvé dans les deux contextes.
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
		// On ne conclut PAS « absente » sur un échec : l'app tourne peut-être
		// déjà, et proposer une installation par-dessus serait pire que de
		// dire qu'on ne sait pas.
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

// Uninstall délègue à exapps.TranscriptionSupprime, inchangé : désactivation,
// désenregistrement (HaRP supprime alors charge, Service et volume), attente
// de disparition effective.
func (m *transcriptionModule) Uninstall(ctx context.Context, env module.Env) error {
	return exapps.TranscriptionSupprime(ctx)
}

// ligneAppareillee renvoie la première ligne qui MENTIONNE l'app, ou "".
//
// Reprise de internal/console/transcription.go : on travaille ligne par ligne
// plutôt que par un « contains » global — le nom apparaît aussi dans les
// libellés, et un contains global déclarerait installée une app seulement
// citée.
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
