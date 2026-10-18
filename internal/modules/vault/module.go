// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package vault declares the "vault" layer (OpenBao, the secrets vault) as
// a Core module of the registry.
//
// WHY A WRAPPER: the install already exists in internal/vault and remains
// driven by cmd/ceffio/install.go. This package DESCRIBES the layer so that
// the state and the diagnostic read it in the registry.
package vault

import (
	"context"
	"fmt"
	"os"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
	coucheVault "github.com/ceffio-suite/ceffio/internal/vault"
)

const (
	// The namespace of the vault (internal/vault/vault.go, ns).
	nsVault = "ceffio-vault"
)

// vaultModule is the "vault" module.
type vaultModule struct{}

func init() { module.Register(&vaultModule{}) }

// Info describes the layer. Requires deliberately empty: the order of the
// core belongs to the explicit sequence of cmd/ceffio/install.go (which
// lays down the vault AFTER platform but BEFORE any application, so that
// each one can read its secrets instead of inventing them).
func (m *vaultModule) Info() module.Info {
	return module.Info{
		ID:          "vault",
		Title:       "Secrets vault",
		Description: "OpenBao: the single place application secrets live, instead of being invented per component.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsVault},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsVault)},

		// NO Services declared, and it is a verified choice: the Ingress
		// bao.<domain> does exist (internal/ingress, ingressesManifest —
		// the OIDC sends the browser there), but it is NOT in
		// catalogueServices (internal/console/status.go). The registry must
		// be able to reproduce the current answer of /api/status exactly;
		// inventing an exposure the console never published would make it
		// lie in the other direction.
	}
}

// Install delegates to vault.Deploy, unchanged — with ONE adaptation that
// is not cosmetic: Deploy never returns an error, but a *Resultat whose
// Pret says whether the vault is usable.
//
// WHY PUBLISH BAO_* HERE: this is exactly what the install sequence
// (cmd/ceffio/install.go) does right after vault.Deploy — without this
// publication, the vault would be deployed but the following layers would
// read secrets.DepuisEnvironnement() = nil and fall back to Kubernetes
// Secrets. An Install that lays down the vault without publishing it would
// install a vault nobody uses.
//
// WHY NOT FAIL WHEN Pret=false: the documented rule of the layer is "an
// unavailable vault never fails the deployment" — the suite continues with
// Kubernetes Secrets. The module honors this contract: warning written to
// env.Out, nil returned. It is State, not Install, that will then tell the
// truth about the vault.
func (m *vaultModule) Install(ctx context.Context, env module.Env) error {
	resultat := coucheVault.Deploy(ctx, env.Domain)
	if resultat != nil && resultat.Pret {
		os.Setenv("BAO_ADDR", resultat.Adresse)
		os.Setenv("BAO_TOKEN", resultat.Jeton)
		os.Setenv("BAO_MOTEUR", "kv")
		if env.Out != nil {
			fmt.Fprintf(env.Out, "vault published for the following steps: %s (token not shown)\n", resultat.Adresse)
		}
		return nil
	}
	if env.Out != nil {
		fmt.Fprintln(env.Out, "vault unavailable — the identity layer will fail without it")
		fmt.Fprintln(env.Out, "  check `kubectl -n ceffio-vault get pods` and the openbao logs")
	}
	return nil
}

// State reads the cluster: the pod of the OpenBao StatefulSet (openbao-0)
// ready. We do NOT ask `bao status`: a sealed or uninitialized vault is a
// normal transient state of the installation, and the layer itself
// initializes and unseals — the observed state of the pod is the honest
// signal here.
func (m *vaultModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDesPods(ctx, env, []string{nsVault}, []string{"openbao"})
}

// Uninstall refuses: the vault carries the secrets of the WHOLE suite —
// removing it would erase the credentials of the databases and the apps.
// The core is removed with the cluster (ceffio uninstall).
func (m *vaultModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
