// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"os"
	"strings"
	"testing"
)

func sourceFiles(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile("files.go")
	if err != nil {
		t.Fatalf("reading files.go: %v", err)
	}
	return string(brut)
}

// TestLaCommandeIdentityReappliqueLesClientsOIDC : `ceffio identity` promet de déployer
// la couche identité SEULE, et il ne touchait pas aux clients OIDC.
//
// CE QUE ÇA A COÛTÉ : une correction du retour après déconnexion de nextcloud a dû être
// poussée à la main, par un programme jetable, sur une plateforme en service. Aucun test
// ne pouvait le voir, parce que le test regardait la fonction de correction — pas la
// commande qui devait l'appeler.
//
// LA PANNE EST SILENCIEUSE PAR NATURE : le realm est sain, les comptes se résolvent, les
// clients existent. Ce qui manque est À L'INTÉRIEUR d'un client — un attribut, une
// adresse de retour — et rien ne le signale avant que quelqu'un emprunte le chemin cassé.
func TestLaCommandeIdentityReappliqueLesClientsOIDC(t *testing.T) {
	src := sourceFiles(t)

	if !strings.Contains(src, "identity.PoserDomaine") {
		t.Error("`ceffio identity` ne transmet pas le domaine avant Deploy : les clients " +
			"OIDC seraient laissés tels quels sur une plateforme installée")
	}
	if !strings.Contains(src, "func domaineDeLaPlateforme") {
		t.Error("aucune lecture du domaine : la commande n'aurait aucun moyen de le " +
			"connaître, et n'a pas de --domain")
	}
}

// TestLeDomaineVientDeLIngressKeycloak : pas de deuxième source de vérité.
//
// UN FLAG --domain AJOUTÉ ICI en créerait une troisième, à côté de celle de la couche
// ingress et de celle de KC_HOSTNAME. L'Ingress est la configuration qui tourne : c'est
// elle qu'on lit.
func TestLeDomaineVientDeLIngressKeycloak(t *testing.T) {
	src := sourceFiles(t)
	if !strings.Contains(src, `"Ingress"`) {
		t.Error("la commande ne lit pas l'Ingress : le domaine viendrait d'ailleurs")
	}
	if !strings.Contains(src, `"keycloak."`) {
		t.Error("le domaine n'est pas déduit de l'hôte keycloak.<domaine>")
	}
	if !strings.Contains(src, `TrimPrefix(hote, "keycloak.")`) {
		t.Error("le préfixe keycloak. n'est pas retiré : le domaine serait keycloak.<domaine>")
	}
}

// TestUnDomaineAbsentNEcritRien : sans domaine lisible, Deploy doit s'abstenir plutôt que
// d'écrire des adresses de retour construites sur une supposition.
//
// UN DOMAINE DEVINÉ ENVERRAIT LES CLIENTS CHEZ QUELQU'UN D'AUTRE, et le symptôme serait
// une redirection vers un hôte inconnu au moment de la connexion.
func TestUnDomaineAbsentNEcritRien(t *testing.T) {
	src := sourceFiles(t)
	if !strings.Contains(src, `return ""`) {
		t.Error("aucun chemin de retour vide : la fonction retournerait toujours un domaine")
	}
	// Le commentaire doit dire pourquoi, pas seulement que.
	if !strings.Contains(src, "rather than") && !strings.Contains(src, "supposition") &&
		!strings.Contains(src, "guess") {
		t.Error("le code ne dit pas ce qui se passe quand le domaine est illisible")
	}
}

// TestDeployAppliqueLesClients : l'appel doit être dans Deploy, pas seulement dans les
// commandes qui l'entourent.
func TestDeployAppliqueLesClients(t *testing.T) {
	brut, err := os.ReadFile("../../internal/identity/identity.go")
	if err != nil {
		t.Fatalf("reading identity.go: %v", err)
	}
	if !strings.Contains(string(brut), "sso.EnsureOIDCClients") {
		t.Error("Deploy n'applique pas les clients OIDC : `ceffio identity` les " +
			"ignorerait toujours, et une correction de client devrait encore être " +
			"poussée à la main")
	}
}
