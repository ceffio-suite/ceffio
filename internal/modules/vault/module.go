// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package vault déclare la couche « vault » (OpenBao, le coffre des secrets)
// comme module Core du registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/vault
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
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
	// Le namespace du coffre (internal/vault/vault.go, ns).
	nsVault = "ceffio-vault"
)

// vaultModule est le module « vault ».
type vaultModule struct{}

func init() { module.Register(&vaultModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// appartient à la séquence explicite de cmd/ceffio/install.go (qui pose le
// coffre APRÈS platform mais AVANT toute application, pour que chacune
// puisse lire ses secrets au lieu d'en inventer).
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

		// PAS de Services déclarés, et c'est un choix vérifié : l'Ingress
		// bao.<domain> existe bien (internal/ingress, ingressesManifest —
		// l'OIDC y renvoie le navigateur), mais il n'est PAS dans
		// catalogueServices (internal/console/status.go). Le registre doit
		// permettre de reproduire la réponse actuelle de /api/status à
		// l'identique ; inventer une exposition que la console n'a jamais
		// publiée la ferait mentir dans l'autre sens.
	}
}

// Install délègue à vault.Deploy, inchangé — avec UNE adaptation qui n'est
// pas cosmétique : Deploy ne retourne jamais d'erreur, mais un *Resultat
// dont Pret dit si le coffre est utilisable.
//
// POURQUOI PUBLIER BAO_* ICI : c'est exactement ce que fait la séquence
// d'installation (cmd/ceffio/install.go) juste après vault.Deploy — sans
// cette publication, le coffre serait déployé mais les couches suivantes
// liraient secrets.DepuisEnvironnement() = nil et retomberaient sur les
// Secrets Kubernetes. Un Install qui poserait le coffre sans le publier
// installerait un coffre que personne n'utilise.
//
// POURQUOI NE PAS ÉCHOUER QUAND Pret=false : la règle documentée de la
// couche est « un coffre indisponible ne fait jamais échouer le
// déploiement » — la suite continue avec les Secrets Kubernetes. Le
// module honore ce contrat : avertissement écrit dans env.Out, retour nil.
// C'est State, pas Install, qui dira ensuite la vérité sur le coffre.
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

// State lit le cluster : le pod du StatefulSet OpenBao (openbao-0) prêt. On
// ne demande PAS `bao status` : un coffre scellé ou non initialisé est un
// état transitoire normal de l'installation, et c'est la couche elle-même
// qui initialise et descelle — l'état observé du pod est le signal honnête
// ici.
func (m *vaultModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDesPods(ctx, env, []string{nsVault}, []string{"openbao"})
}

// Uninstall refuse : le coffre porte les secrets de TOUTE la suite — le
// retirer effacerait les identités des bases et des apps. Le socle se
// retire avec le cluster (ceffio uninstall).
func (m *vaultModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
