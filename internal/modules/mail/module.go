// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package mail déclare la couche « mail » (Stalwart) comme module Core du
// registre.
//
// POURQUOI UN ENVELOPPEMENT : l'installation existe déjà dans internal/mail
// et reste pilotée par cmd/ceffio/install.go. Ce package DÉCRIT la couche
// pour que l'état et le diagnostic la lisent dans le registre.
//
// LE CAS PARTICULIER DE CE MODULE — Install NE DÉLÈGUE PAS :
// mail.Deploy exige les réglages du relais SMTP sortant (hôte, port,
// utilisateur, mot de passe) que module.Env ne porte pas, et pour cause :
// ce sont des données de l'opérateur saisies par la commande install
// (--smtp-relais, …). Le port 25 sortant est bloqué par les FAI (vérifié),
// donc un Stalwart déployé SANS relais recevrait mais n'enverrait jamais —
// une installation silencieusement cassée. Plutôt que de déléguer avec un
// relais vide et faire semblant, Install retourne une erreur explicite :
// la séquence d'installation, qui détient les réglages, reste la seule à
// installer cette couche.
package mail

import (
	"context"
	"fmt"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/modules/socle"
)

// PAS D'IMPORT DE internal/mail ICI, et c'est voulu : ce module n'appelle
// JAMAIS mail.Deploy (voir Install). Conserver un import inutilisable sous
// prétexte de lien symbolique ferait croire à une délégation qui n'existe
// pas. La couche est décrite, pas pilotée.

// Le namespace de Stalwart (internal/mail/mail.go, ns).
const nsMail = "ceffio-mail"

// mailModule est le module « mail ».
type mailModule struct{}

func init() { module.Register(&mailModule{}) }

// Info décrit la couche. Requires volontairement vide : l'ordre du socle
// (mail après ingress, car le SSO de Stalwart vérifie son discovery OIDC
// sur https://keycloak.<domain>) appartient à la séquence explicite de
// cmd/ceffio/install.go.
func (m *mailModule) Info() module.Info {
	return module.Info{
		ID:          "mail",
		Title:       "Mail server (Stalwart)",
		Description: "Stalwart: the mail server behind Nextcloud Mail, with SMTP relay settings held by the install sequence.",
		Kind:        module.Core,
		Default:     true,
		Namespaces:  []string{nsMail},

		// Permissions (batch B6): the console administers this namespace —
		// the standard set reproduces what the former ClusterRole
		// ceffio-admin-namespaces granted via its RoleBinding (see
		// socle.StandardPermission).
		Permissions: []module.Permission{socle.StandardPermission(nsMail)},

		Warning: "Installed by the install sequence only: it needs the outbound SMTP relay settings, which the registry does not carry.",
	}
}

// Install refuse, EXPLICITEMENT.
//
// POURQUOI UNE ERREUR PLUTÔT QU'UNE DÉLÉGATION APPROXIMATIVE : appeler
// mail.Deploy avec un relais vide produirait un Stalwart qui tourne, qui
// reçoit, et qui n'envoie RIEN — le pire état possible, parce que tout
// paraîtrait installé. Env n'a pas les réglages du relais et ne doit pas
// les avoir (un mot de passe SMTP n'est pas une donnée de cluster). La
// seule réponse honnête est de dire qui, et pourquoi, installe cette
// couche.
func (m *mailModule) Install(ctx context.Context, env module.Env) error {
	return fmt.Errorf("mail is installed by the install sequence, which holds the SMTP relay settings; " +
		"the registry describes it but does not install it")
}

// State lit le cluster : le Deployment stalwart prêt dans ceffio-mail.
func (m *mailModule) State(ctx context.Context, env module.Env) module.State {
	return socle.EtatDuDeploiement(ctx, env, nsMail, "stalwart")
}

// Uninstall refuse : la couche fait partie du produit (Kind Core) ; les
// boîtes mail des utilisateurs vivent dans son volume. Le socle se retire
// avec le cluster (ceffio uninstall).
func (m *mailModule) Uninstall(ctx context.Context, env module.Env) error {
	return socle.ErreurSocleIndemontable(m.Info().ID)
}
