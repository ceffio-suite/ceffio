// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package exappsdaemon wraps HaRP, the external application deployer, as a
// registry module.
//
// WHY A WRAPPER AND NOT A REWRITE: install and removal already exist in
// internal/exapps and have been proven in production (RBAC, vault, AppAPI
// registration, deletion order). This package only plugs them into the
// module.Module contract; the only logic that is its own is the state, MOVED
// here from the console (repondreEtatDeployeur, internal/console/exapps.go)
// so that the CLI and the console read exactly the same truth.
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
	// The namespace where the ExApp workloads live. Taken from deploy.go
	// (namespacesPlateforme) and from the comment of exapps.NomsHarp.
	nsExapps = "ceffio-exapps"

	// The Nextcloud namespace: THAT is where the occ that registers the
	// deployer in AppAPI runs, and the state read must go through it.
	nsNextcloud = "ceffio-files"
)

// harpModule is the "exapps-daemon" module.
type harpModule struct{}

func init() { module.Register(&harpModule{}) }

// Info describes the deployer. The Description and Warning texts are taken
// VERBATIM from the existing interface (internal/console/web/index.html,
// ExApps tab): they are the ones the operator already reads.
func (m *harpModule) Info() module.Info {
	return module.Info{
		ID:          "exapps-daemon",
		Title:       "ExApp deploy daemon (HaRP)",
		Description: "HaRP runs the containers Nextcloud asks for, speaking the Kubernetes API directly.",
		Kind:        module.Optional,
		Default:     false,
		Namespaces:  []string{nsExapps},

		// Permissions: a subset of the rules the ClusterRole
		// ceffio-admin-namespaces already grants in every platform
		// namespace (internal/console/deploy.go), limited to what the HaRP
		// deployment actually touches in ceffio-exapps:
		//   - ServiceAccount/Role/RoleBinding (creerRBAC),
		//   - Deployment/Service/Ingress (deployerHarp),
		//   - PVC (supprimerPVC on removal), pods (state read).
		// The ceffio-files entry reproduces EXACTLY the Role
		// ceffio-console-occ of deploy.go: it is the right to run occ in
		// the Nextcloud pod, needed to register the deployer in AppAPI and
		// to read its state.
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

// Install delegates to exapps.Deploy, unchanged: it creates the namespace,
// the deployer RBAC, the shared key in the vault, the HaRP pod, then the
// registration in AppAPI.
//
// Progress is written to stdout by exapps.Deploy itself; rerouting it to
// env.Out would require changing its signatures, which this batch forbids
// itself.
func (m *harpModule) Install(ctx context.Context, env module.Env) error {
	return exapps.Deploy(ctx, env.Domain)
}

// State is the logic of repondreEtatDeployeur (internal/console/exapps.go),
// MOVED here as-is: the two reads — the HaRP pod ready, and the registration
// in AppAPI — and the four cases that follow from them.
//
// WHY k8sapi AND NOT env.Kube: the registration check goes through a SPDY
// exec in the Nextcloud pod, which requires a *rest.Config — not just a
// kubernetes.Interface. k8sapi.Client already exports exactly the three
// building blocks needed (DeploiementPret, PodDuDeploiement, Executer) and
// resolves the configuration in both contexts (in-cluster for the console,
// kubeconfig for the CLI). Nothing more to export.
func (m *harpModule) State(ctx context.Context, env module.Env) module.State {
	cli, err := k8sapi.Nouveau()
	if err != nil {
		return module.State{Status: module.Unknown, Detail: "Kubernetes injoignable : " + err.Error()}
	}
	nomHarp, nsHarp := exapps.NomsHarp()
	installe := cli.DeploiementPret(ctx, nsHarp, nomHarp)

	// The registration in AppAPI is read via occ in the Nextcloud pod. An
	// impossible exec (pod absent) leaves enregistre at false, like the
	// console: we never conclude "registered" on a failure.
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
		// The sneakiest of the four cases: HaRP runs, but Nextcloud does
		// not know it. ExApps then install without ever activating, and
		// nothing in the logs points at the registration. Naming the
		// detail here avoids the hunt.
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

// Uninstall delegates to exapps.Remove, unchanged: it first removes the
// attached ExApps (AppAPI refuses to remove a deployer that still carries
// some), then the registration, then the Kubernetes resources and the
// volumes.
//
// VERIFIED: exapps.Remove does NOT delete the ceffio-exapps namespace — the
// code comment ("LE NAMESPACE N'EST PAS SUPPRIMÉ, et c'est délibéré") and
// the list of deletions confirm it. This is consistent with Preparer, which
// creates it for the install: the namespace belongs to the platform, not to
// the deployer.
func (m *harpModule) Uninstall(ctx context.Context, env module.Env) error {
	return exapps.Remove(ctx)
}
