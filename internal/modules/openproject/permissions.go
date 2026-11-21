// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// toutVerbe is the full write set on an object the module owns.
var toutVerbe = []string{"get", "list", "watch", "create", "update", "patch", "delete"}

// permissionsSysteme lists what the CONSOLE needs in ceffio-system to manage
// this module.
//
// SPELLED OUT RATHER THAN socle.StandardPermission, for the reason longhorn-ui
// gives: a grant nobody asked for is a grant nobody removes. Every tuple below
// but one is already part of the console's legacy grant in ceffio-system.
//
// THE ONE NEW RIGHT is networking.k8s.io/networkpolicies: the policy that lets
// ONLY the proxy reach OpenProject is what makes the trusted header
// trustworthy (manifestePolitique), and the console must be able to lay it
// down and remove it with the rest. It is recorded as a decided addition in
// internal/console/rbac_nonregression_test.go.
//
// NO Secret RIGHT: the credentials come from the OpenBao injector, and the only
// Secret the module leaves behind — the certificate cert-manager issues — is
// removed through its Certificate.
func permissionsSysteme() module.Permission {
	return module.Permission{
		Namespace: nsProjets,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"services", "configmaps", "persistentvolumeclaims", "serviceaccounts"},
				Verbs:     toutVerbe,
			},
			{
				// THE PODS ARE READ, NEVER WRITTEN: the Deployments own them.
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// EXEC: the Users page creates, deletes and lists OpenProject
				// accounts by running Rails in the application pod (comptes.go).
				// LOGS: a failed migration is diagnosed there and nowhere else.
				APIGroups: []string{""},
				Resources: []string{"pods/exec", "pods/log"},
				Verbs:     []string{"get", "create"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets"},
				Verbs:     toutVerbe,
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"ingresses", "networkpolicies"},
				Verbs:     toutVerbe,
			},
			{
				// The certificate cert-manager issues from the Ingress annotation.
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificates", "certificaterequests"},
				Verbs:     toutVerbe,
			},
		},
	}
}

// permissionsDonnees lists what the console needs in the DATA namespace.
//
// ONLY exec into the PostgreSQL pod, and only to create (then, on uninstall,
// drop) this module's database and role — the same psql-in-the-pod path
// internal/files uses. Every tuple here already belongs to the grant the data
// layer gives the console; declaring it keeps this module honest about what it
// touches outside its own namespace.
func permissionsDonnees() module.Permission {
	return module.Permission{
		Namespace: pgNS,
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
	}
}
