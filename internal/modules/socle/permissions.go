// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package socle

import (
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/ceffio-suite/ceffio/internal/module"
)

// StandardPermission returns the namespace-scoped rights the console holds in
// ONE platform namespace, as a module.Permission the owning module declares in
// its Info().
//
// WHERE THESE RULES COME FROM: they are the VERBATIM reproduction of the
// rules of the former hand-written ClusterRole ceffio-admin-namespaces
// (internal/console/deploy.go, before batch B6), which RoleBindings applied
// uniformly in every platform namespace. Batch B6 turned that grant into the
// SUM of the module registry; for the sum to be identical — no right lost,
// none added — every platform namespace must still carry exactly these rules,
// declared by the module that owns it. The non-regression test
// (internal/console/rbac_nonregression_test.go) pins the equality tuple by
// tuple, and this function is the single place the rules are written.
//
// WHY SHARED AND NOT COPIED INTO EACH MODULE: nine copies of the same seven
// rules are nine places where a future edit can drift, and drift between two
// namespaces is exactly the silent asymmetry the sum is meant to prevent.
// A module MAY declare less than this set when its namespace genuinely needs
// less — but narrowing one namespace is a privilege decision, made on
// purpose, never by copy-paste accident.
//
// WHY socle: this package already holds what the ten core-layer modules share
// (state reads). It registers no module, so all.go and its guardrail test are
// unaffected.
func StandardPermission(namespace string) module.Permission {
	return module.Permission{
		Namespace: namespace,
		Rules: []rbacv1.PolicyRule{
			{
				// The heart of the platform: workloads, configuration,
				// application secrets, services, volumes.
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "serviceaccounts"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// Exec and logs: the console drives occ in the pods and
				// shows their output.
				APIGroups: []string{""},
				Resources: []string{"pods/exec", "pods/log"},
				Verbs:     []string{"get", "create"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "statefulsets", "replicasets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"ingresses"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificates", "certificaterequests"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// The console creates the namespace-scoped RBAC of the
				// components it deploys (e.g. the HaRP deployer's Role).
				// Cluster-scoped RBAC stays out of reach, by design —
				// see deploy.go.
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// The PostgreSQL clusters (CNPG custom resources) live in
				// the application namespaces, not in the operator's.
				APIGroups: []string{"postgresql.cnpg.io"},
				Resources: []string{"*"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}
}
