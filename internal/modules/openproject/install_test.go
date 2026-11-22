// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/k8sapi"
	"github.com/ceffio-suite/ceffio/internal/module"
)

// TestLInstallationAssureLeRoleVaultEnPremier pins the ORDER, which is the whole
// point of step 0: the vault policy and the Kubernetes role are asserted BEFORE
// the first secret is read and before a single pod is applied. A pod that
// cannot authenticate to the vault stays in Init for the whole 15-minute wait
// and says nothing useful — measured on the acceptance run of 2026-11-21
// ("invalid role name \"openproject\"").
func TestLInstallationAssureLeRoleVaultEnPremier(t *testing.T) {
	ancienClient, ancienRole, ancienLire := nouveauClient, assurerRoleVault, lireCoffre
	t.Cleanup(func() { nouveauClient, assurerRoleVault, lireCoffre = ancienClient, ancienRole, ancienLire })

	nouveauClient = func() (*k8sapi.Client, error) {
		return k8sapi.PourTest(nil, nil), nil
	}

	var appels int
	var vu struct {
		id, sa, ns string
		chemins    []string
	}
	assurerRoleVault = func(ctx context.Context, cli *k8sapi.Client, id, sa, ns string, chemins []string) error {
		appels++
		vu.id, vu.sa, vu.ns, vu.chemins = id, sa, ns, chemins
		return errors.New(`role "openproject": no handler for route "auth/kubernetes/role/openproject"`)
	}
	coffreLu := false
	lireCoffre = func(ctx context.Context, composant, nom string) (map[string]string, error) {
		coffreLu = true
		return nil, errors.New("the vault must not be read before the access is asserted")
	}

	err := installer(context.Background(), module.Env{Domain: "example.com", Out: io.Discard})
	if err == nil {
		t.Fatal("the installation succeeded although the vault role could not be written")
	}

	// THE FAILURE COMES FROM STEP 0, AND IT IS THE VAULT THAT FAILED: the
	// message names the access, so an operator reads "vault", not "Kubernetes
	// objects" or "the database".
	if !strings.Contains(err.Error(), "vault access") {
		t.Errorf("the error does not name the vault access: %v", err)
	}
	if appels != 1 {
		t.Errorf("assurerRoleVault called %d times, want 1", appels)
	}
	if coffreLu {
		t.Error("the vault was read before the access was asserted: the order is the fix")
	}

	// THE ACCESS ASSERTED IS THE ONE THE REGISTRY DECLARES, not a copy.
	acces := (&openprojectModule{}).Info().Vault[0]
	if vu.id != idModule || vu.sa != acces.ServiceAccount || vu.ns != acces.Namespace {
		t.Errorf("wrong identity asserted: %+v, want id=%q sa=%q ns=%q",
			vu, idModule, acces.ServiceAccount, acces.Namespace)
	}
	if len(vu.chemins) != len(acces.Paths) || vu.chemins[0] != acces.Paths[0] {
		t.Errorf("paths asserted = %v, want %v", vu.chemins, acces.Paths)
	}
}
