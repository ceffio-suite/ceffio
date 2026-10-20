// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// permissionsLonghornUI lists EXACTLY what this module needs in ceffio-system.
//
// IT IS SPELLED OUT RATHER THAN TAKING socle.StandardPermission, and the reason is not
// aesthetic: the proxy is a workload, a route and a small file of addresses. It has no
// business reading secrets, exec'ing into pods or touching volumes. A standard grant
// would give all three, and nobody would ever narrow it — a right nobody asked for is a
// right nobody removes.
//
// WHAT IT DOES NOT NEED, and this is the important half:
//
//   - NO longhorn-system ACCESS AT ALL. The proxy reaches the interface through a
//     ClusterIP Service, which is name resolution, not an API call. Giving it RBAC on
//     the storage namespace for a proxy that deletes nothing would be the first step
//     towards letting it do so.
//   - NO Secret RIGHTS: its credentials come from the OpenBao agent, which writes them
//     into a file inside the pod.
func permissionsLonghornUI() module.Permission {
	return module.Permission{
		Namespace: nsSysteme,
		Rules: []rbacv1.PolicyRule{
			{
				// THE WORKLOAD ITSELF.
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// THE SERVICE AND THE ROUTE.
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// THE LIST OF ALLOWED ADDRESSES, which the access setting rewrites.
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// THE LOGS, because a refused login is diagnosed there and nowhere else:
				// oauth2-proxy answers 403 without explaining which claim failed.
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/log"},
				Verbs:     []string{"get"},
			},
			{
				// THE SERVICE ACCOUNT THE VAULT ROLE IS BOUND TO. Creating it is part of
				// installing the module; without the binding, the agent never injects and
				// the pod starts with no client secret.
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "create", "update", "patch"},
			},
		},
	}
}
