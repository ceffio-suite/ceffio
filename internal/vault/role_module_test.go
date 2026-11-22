// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAssurerRoleModuleRefuseUnCheminHorsPrefixe: the policy rule is checked
// BEFORE any cluster call. A module that declares a path outside its own
// prefix must get a refusal, never a policy — and the nil client is the proof
// that nothing touched Kubernetes on the way: any call would panic.
func TestAssurerRoleModuleRefuseUnCheminHorsPrefixe(t *testing.T) {
	for _, mauvais := range []string{
		"kv/data/ceffio/talk/*",       // another component's secrets
		"kv/data/ceffio/capture/../x", // escaping its own prefix
	} {
		err := AssurerRoleModule(context.Background(), nil, "capture", "capture", "ceffio-system",
			[]string{mauvais})
		if err == nil {
			t.Fatalf("AssurerRoleModule accepted %q", mauvais)
		}
		if !strings.Contains(err.Error(), "may only read under") &&
			!strings.Contains(err.Error(), `".."`) {
			t.Errorf("refusal does not name the rule for %q: %v", mauvais, err)
		}
	}
}

// TestAssurerRoleModuleSansClient: valid paths but no Kubernetes client is an
// error, not a panic. The install path must say what is missing rather than
// crash in the middle of a deployment.
func TestAssurerRoleModuleSansClient(t *testing.T) {
	err := AssurerRoleModule(context.Background(), nil, "capture", "capture", "ceffio-system",
		[]string{"kv/data/ceffio/capture/*"})
	if err == nil {
		t.Fatal("AssurerRoleModule accepted a nil client")
	}
	if !strings.Contains(err.Error(), "no Kubernetes client") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestErreurRoleKubernetesDonneLaRemede: a failed role write is where the
// operator learns that one command fixes it. The remedy is part of the message
// on purpose — a bare "invalid role name" sent the acceptance run looking for a
// bug in the module instead of a command in the suite.
func TestErreurRoleKubernetesDonneLaRemede(t *testing.T) {
	erreur := erreurRoleKubernetes(errors.New("no handler for route \"auth/kubernetes/role/capture\""))
	for _, attendu := range []string{
		"no handler for route",
		"ceffio vault",
		"then retry",
	} {
		if !strings.Contains(erreur.Error(), attendu) {
			t.Errorf("the message does not contain %q: %v", attendu, erreur)
		}
	}
}

// TestNomPolitiqueModuleSuitLeProvisionnement: the role must point at the policy
// the provisioning loop actually writes. Two names would authenticate the pod
// and then refuse every read — the pod starts WITHOUT its secrets instead of
// failing to start.
func TestNomPolitiqueModuleSuitLeProvisionnement(t *testing.T) {
	if got := nomPolitiqueModule("openproject"); got != "ceffio-openproject" {
		t.Errorf("nomPolitiqueModule = %q, want ceffio-openproject", got)
	}
}