// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package exappsdaemon enveloppe HaRP, le déployeur d'applications externes,
// en module du registre.
//
// POURQUOI UN ENVELOPPEMENT ET NON UNE RÉÉCRITURE : l'installation et le
// retrait existent déjà dans internal/exapps et ont été éprouvés en production
// (RBAC, coffre, enregistrement AppAPI, ordre des suppressions). Ce package se
// contente de les brancher sur le contrat module.Module ; la seule logique qui
// lui est propre est l'état, DÉPLACÉE ici depuis la console
// (repondreEtatDeployeur, internal/console/exapps.go) pour que le CLI et la
// console lisent exactement la même vérité.
package exappsdaemon

import (
	"context"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/exapps"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

const (
	// Le namespace où vivent les charges des ExApp. Repris de deploy.go
	// (namespacesPlateforme) et du commentaire de exapps.NomsHarp.
	nsExapps = "ceffio-exapps"

	// Le namespace de Nextcloud : c'est LÀ que tourne l'occ qui enregistre le
	// déployeur dans AppAPI, et la lecture d'état doit passer par lui.
	nsNextcloud = "ceffio-files"
)

// harpModule est le module « exapps-daemon ».
type harpModule struct{}

func init() { module.Register(&harpModule{}) }

// Info décrit le déployeur. Les textes Description et Warning sont repris
// TELS QUELS de l'interface existante (internal/console/web/index.html,
// onglet ExApps) : ce sont ceux que l'exploitant lit déjà.
func (m *harpModule) Info() module.Info {
	return module.Info{
		ID:          "exapps-daemon",
		Title:       "ExApp deploy daemon (HaRP)",
		Description: "HaRP runs the containers Nextcloud asks for, speaking the Kubernetes API directly.",
		Kind:        module.Optional,
		Default:     false,
		Namespaces:  []string{nsExapps},

		// Permissions : sous-ensemble des règles que le ClusterRole
		// ceffio-admin-namespaces accorde déjà dans chaque namespace de la
		// plateforme (internal/console/deploy.go), limité à ce que le
		// déploiement de HaRP touche réellement dans ceffio-exapps :
		//   - ServiceAccount/Role/RoleBinding (creerRBAC),
		//   - Deployment/Service/Ingress (deployerHarp),
		//   - PVC (supprimerPVC au retrait), pods (lecture d'état).
		// L'entrée ceffio-files reproduit EXACTEMENT le Role
		// ceffio-console-occ de deploy.go : c'est le droit d'exécuter occ
		// dans le pod Nextcloud, nécessaire pour enregistrer le déployeur
		// dans AppAPI et pour lire son état.
		Permissions: []module.Permission{
			{
				Namespace: nsExapps,
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods", "services", "persistentvolumeclaims", "serviceaccounts"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"apps"},
						Resources: []string{"deployments"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"networking.k8s.io"},
						Resources: []string{"ingresses"},
						Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
					},
					{
						APIGroups: []string{"rbac.authorization.k8s.io"},
						Resources: []string{"roles", "rolebindings"},
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

		Warning: "Nothing that relies on an external application can be installed before this one.",
	}
}

// Install délègue à exapps.Deploy, inchangé : il crée le namespace, le RBAC
// du déployeur, la clé partagée dans le coffre, le pod HaRP, puis
// l'enregistrement dans AppAPI.
//
// La progression est écrite sur stdout par exapps.Deploy lui-même ; la
// réaiguiller vers env.Out demanderait de modifier ses signatures, ce que ce
// lot s'interdit.
func (m *harpModule) Install(ctx context.Context, env module.Env) error {
	return exapps.Deploy(ctx, env.Domain)
}

// State est la logique de repondreEtatDeployeur (internal/console/exapps.go),
// DÉPLACÉE ici telle quelle : les deux lectures — le pod HaRP prêt, et
// l'enregistrement dans AppAPI — et les quatre cas qui en découlent.
//
// POURQUOI k8sapi ET PAS env.Kube : la vérification de l'enregistrement passe
// par un exec SPDY dans le pod Nextcloud, qui exige un *rest.Config — pas
// seulement un kubernetes.Interface. k8sapi.Client exporte déjà exactement les
// trois briques nécessaires (DeploiementPret, PodDuDeploiement, Executer) et
// résout la configuration dans les deux contextes (in-cluster pour la console,
// kubeconfig pour le CLI). Rien à exporter de plus.
func (m *harpModule) State(ctx context.Context, env module.Env) module.State {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes injoignable : " + err.Error()}
	}
	nomHarp, nsHarp := exapps.NomsHarp()
	installe := cli.DeploiementPret(ctx, nsHarp, nomHarp)

	// L'enregistrement dans AppAPI se lit via occ dans le pod Nextcloud. Un
	// exec impossible (pod absent) laisse enregistre à false, comme la
	// console : on ne conclut jamais « enregistré » sur un échec.
	enregistre := false
	if pod, err := cli.PodDuDeploiement(ctx, nsNextcloud, "nextcloud", "nextcloud"); err == nil {
		if sortie, err := cli.Executer(ctx, nsNextcloud, pod, "nextcloud",
			"php", "occ", "app_api:daemon:list"); err == nil {
			enregistre = strings.Contains(strings.ToLower(sortie), strings.ToLower(nomHarp))
		}
	}

	switch {
	case installe && enregistre:
		return module.State{Status: module.Installed}
	case installe && !enregistre:
		// Le plus sournois des quatre cas : HaRP tourne, mais Nextcloud ne
		// le connaît pas. Les ExApp s'installent alors sans jamais
		// s'activer, et rien dans les journaux ne pointe vers
		// l'enregistrement. Le détail nommé ici évite la chasse.
		return module.State{
			Status: module.Degraded,
			Detail: "HaRP tourne mais n'est pas enregistre dans Nextcloud : les applications s'installeraient sans jamais s'activer.",
		}
	case !installe && enregistre:
		return module.State{
			Status: module.Degraded,
			Detail: "Enregistre dans Nextcloud, mais le pod HaRP est absent.",
		}
	default:
		return module.State{Status: module.Absent}
	}
}

// Uninstall délègue à exapps.Remove, inchangé : il retire d'abord les ExApp
// attachées (AppAPI refuse de retirer un déployeur qui en porte encore), puis
// l'enregistrement, puis les ressources Kubernetes et les volumes.
//
// VÉRIFIÉ : exapps.Remove NE supprime PAS le namespace ceffio-exapps — le
// commentaire du code (« LE NAMESPACE N'EST PAS SUPPRIMÉ, et c'est
// délibéré ») et la liste des suppressions le confirment. C'est cohérent
// avec Preparer, qui le crée pour l'installation : le namespace appartient à
// la plateforme, pas au déployeur.
func (m *harpModule) Uninstall(ctx context.Context, env module.Env) error {
	return exapps.Remove(ctx)
}
