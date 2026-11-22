// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// AssurerRoleModule makes the vault grant one module's pods what the module
// declared: a read-only policy confined to its own kv/ prefix, and the
// Kubernetes authentication role that binds the module's ServiceAccount to it.
//
// WHY A MODULE INSTALL CANNOT LEAVE THIS TO `ceffio vault`: the policies and the
// roles are built from the module registry AT VAULT DEPLOYMENT TIME
// (poserPolitiquesEtJetons and configurerAuthKubernetes, in this package). An
// installation whose vault was deployed by an earlier binary therefore has no
// role for a module added since — the registry it read did not contain it.
//
// MEASURED during the OpenProject acceptance run (2026-11-21): the pod stayed
// in Init with
//
//	vault-agent-init: Code: 400. Errors: * invalid role name "openproject"
//
// and the only remedy was to re-run `ceffio vault`, a command the operator has
// no reason to suspect. The failure costs the whole 15-minute wait and names
// neither the cause nor the fix. The module now asserts its own access before
// deploying a single pod that could not fetch its secrets.
//
// IDEMPOTENT: policy and role are written with the same content, so a re-run
// changes nothing and costs one write each.
func AssurerRoleModule(ctx context.Context, cli *k8sapi.Client, id, serviceAccount, namespace string, chemins []string) error {
	// THE REFUSAL COMES FIRST, BEFORE ANY CLUSTER CALL: a path that escapes the
	// module's own prefix must fail here, not become a policy and a live role.
	regle, err := PolitiqueModule(id, chemins)
	if err != nil {
		return err
	}
	if cli == nil {
		return fmt.Errorf("vault role %q: no Kubernetes client", id)
	}
	adm, err := jetonAdministration(ctx, cli)
	if err != nil {
		return fmt.Errorf("vault role %q: %w", id, err)
	}
	if err := poserPolitiqueModule(ctx, cli, adm, nomPolitiqueModule(id), regle); err != nil {
		return err
	}
	if err := poserRoleKubernetes(ctx, cli, adm, id, serviceAccount, namespace, nomPolitiqueModule(id)); err != nil {
		return erreurRoleKubernetes(err)
	}
	return nil
}

// aideRoleKubernetes is the sentence the operator needs when the role write
// fails for the reason this mechanism exists to uncover: a vault deployed
// before the module, with no Kubernetes authentication method, or a token
// without the right to write one. A 400 alone says neither what to do nor that
// a single command fixes it.
const aideRoleKubernetes = "if this vault was deployed by an earlier release, run `ceffio vault` " +
	"once (it builds the roles from the module registry), then retry"

// erreurRoleKubernetes wraps a failed role write WITH the remedy.
func erreurRoleKubernetes(err error) error {
	return fmt.Errorf("%w — %s", err, aideRoleKubernetes)
}

// nomPolitiqueModule is the policy name of a module, and it MUST be the one the
// provisioning loop builds: a role pointing at a policy under another name
// authenticates the pod and then refuses every read, so the pod starts WITHOUT
// its secrets instead of failing to start.
func nomPolitiqueModule(id string) string { return "ceffio-" + id }

// poserPolitiqueModule writes one policy into the vault pod, then into the
// vault. Shared with the `ceffio vault` provisioning loop: two copies of the
// heredoc would drift, and the drift would only show as a rejected policy.
//
// THE FILE IS WRITTEN BEFORE THE WRITE, for the same reason as there: the
// command line can only carry text, and a multi-line HCL document read from
// standard input is not something the write endpoint offers.
func poserPolitiqueModule(ctx context.Context, cli *k8sapi.Client, jeton, nom, regle string) error {
	script := fmt.Sprintf("cat > /tmp/p.hcl <<'FIN_POLITIQUE'\n%s\nFIN_POLITIQUE\n", regle)
	if _, err := cli.Executer(ctx, ns, pod, "openbao", "sh", "-c", script); err != nil {
		return fmt.Errorf("writing policy %s: %w", nom, err)
	}
	return ecrirePolitique(ctx, cli, jeton, struct{ nom, regle string }{nom, regle})
}

// poserRoleKubernetes creates or updates one Kubernetes authentication role.
//
// BOTH THE NAME AND THE NAMESPACE ARE BOUND on purpose: an identical
// ServiceAccount created elsewhere in the cluster would otherwise obtain the
// same rights, which is exactly what the header-SSO design must not allow.
func poserRoleKubernetes(ctx context.Context, cli *k8sapi.Client, jeton, nom, serviceAccount, namespace, politique string) error {
	if _, err := baoAvecJeton(ctx, cli, jeton,
		"write", "auth/kubernetes/role/"+nom,
		"bound_service_account_names="+serviceAccount,
		"bound_service_account_namespaces="+namespace,
		"policies="+politique,
		"ttl=1h"); err != nil {
		return fmt.Errorf("role %q: %w", nom, err)
	}
	return nil
}
