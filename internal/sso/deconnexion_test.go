// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package sso

import (
	"strings"
	"testing"
)

// TestChaqueClientPublicARetourApresDeconnexion : le 400 que l'utilisateur a vu.
//
// KEYCLOAK GARDE DEUX LISTES SÉPARÉES, et les remplir est deux gestes distincts : les
// URI de retour après CONNEXION (redirectUris), et celles après DÉCONNEXION
// (l'attribut post.logout.redirect.uris). Le client nextcloud n'avait que la première,
// donc la déconnexion depuis Nextcloud finissait sur
//
//	Nous sommes désolés... L'URI de redirection est invalide
//
// pendant que la connexion fonctionnait parfaitement — d'où le silence.
//
// CE TEST BOUCLE SUR TOUS LES CLIENTS, pas seulement nextcloud : le défaut est
// l'absence d'un champ, et une liste écrite à la main oublierait le prochain client
// ajouté.
func TestChaqueClientPublicARetourApresDeconnexion(t *testing.T) {
	for _, c := range clientsOIDC("exemple.org") {
		if c.postLogout == "" {
			t.Errorf("le client %q ne déclare aucun retour après déconnexion.\n"+
				"Keycloak refusera chaque sign-out avec « L'URI de redirection est "+
				"invalide » (400), alors que la connexion, elle, fonctionne.",
				c.id)
			continue
		}
		// UNE URI DE RETOUR DOIT ÊTRE ABSOLUE : un chemin relatif est refusé par
		// Keycloak avec le même message, et ne dit pas pourquoi.
		for _, uri := range strings.Split(c.postLogout, ",") {
			uri = strings.TrimSpace(uri)
			if !strings.HasPrefix(uri, "https://") {
				t.Errorf("client %q : le retour %q n'est pas une URI absolue en https. "+
					"Keycloak refuse une URI relative avec le même message qu'une URI "+
					"absente.", c.id, uri)
			}
		}
	}
}

// TestNextcloudRevientSurSonHote : le retour après déconnexion est le domaine de
// l'application, pas une page interne.
//
// NEXTCLOUD DEMANDE À REVENIR SUR SA RACINE après avoir quitté la session, et l'adresse
// envoyée porte la barre finale. Déclarer une page interne ne correspondrait à rien.
func TestNextcloudRevientSurSonHote(t *testing.T) {
	for _, c := range clientsOIDC("exemple.org") {
		if c.id != "nextcloud" {
			continue
		}
		attendu := "https://cloud.exemple.org/"
		if c.postLogout != attendu {
			t.Errorf("le retour de nextcloud est %q, attendu %q : c'est l'adresse que "+
				"le client envoie réellement", c.postLogout, attendu)
		}
		return
	}
	t.Fatal("aucun client nextcloud dans la liste")
}

// TestLesRetoursSontConstruitsSurLeDomaine : un domaine codé en dur enverrait une
// installation vers celui d'une autre.
func TestLesRetoursSontConstruitsSurLeDomaine(t *testing.T) {
	const domaine = "client.exemple.net"
	for _, c := range clientsOIDC(domaine) {
		if c.postLogout == "" {
			continue
		}
		if !strings.Contains(c.postLogout, domaine) {
			t.Errorf("client %q : le retour %q ne mentionne pas le domaine %q — une "+
				"adresse codée en dur enverrait cette installation chez une autre",
				c.id, c.postLogout, domaine)
		}
	}
}
