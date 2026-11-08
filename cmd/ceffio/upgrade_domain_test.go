// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"os"
	"strings"
	"testing"
)

func upgradeSource(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile("upgrade.go")
	if err != nil {
		t.Fatalf("reading upgrade.go: %v", err)
	}
	return string(brut)
}

// TestLUpgradeDeduitLeDomaineQuandLeFlagEstAbsent : le texte d'aide de la commande
// promettait « Base domain (deduced when absent) » et RIEN ne déduisait quoi que ce soit.
//
// CE QUE ÇA A COÛTÉ, MESURÉ EN PRODUCTION : `ceffio upgrade` sans --domain a rejoué la
// plateforme, la donnée et l'identité, puis s'est arrêté à la phase SSO sur
//
//	✗ application : the suite's OIDC clients could not be applied:
//	  domain required to build the OIDC redirect_uri
//
// c'est-à-dire APRÈS la sauvegarde, avec une pile à moitié rejouée et un message qui
// parle de redirect_uri. Le même binaire, relancé avec --domain, est passé du premier
// coup : l'absence de déduction était la seule cause.
//
// LE LECTEUR EXISTAIT DÉJÀ : domaineDeLaPlateforme lit l'Ingress keycloak pour
// `ceffio identity`. Ce test interdit qu'on réintroduise un upgrade qui n'en dépend pas.
func TestLUpgradeDeduitLeDomaineQuandLeFlagEstAbsent(t *testing.T) {
	src := upgradeSource(t)

	if !strings.Contains(src, "domaineDeLaPlateforme(") {
		t.Error("`ceffio upgrade` ne déduit pas le domaine : sans --domain il rejouerait " +
			"toute la pile pour échouer à la phase SSO, après la sauvegarde")
	}
	// Le domaine doit être déduit AVANT le rejeu et non au moment de l'appeler : c'est
	// la différence entre refuser sans rien toucher et échouer à mi-parcours.
	iDeduction := strings.Index(src, "domaineDeLaPlateforme(")
	iRejeu := strings.Index(src, "cluster.Redeployer(")
	if iDeduction < 0 || iRejeu < 0 || iDeduction > iRejeu {
		t.Error("le domaine n'est pas résolu avant le rejeu : l'échec surviendrait en " +
			"cours d'application, après la sauvegarde et les couches déjà rejouées")
	}
}

// TestLUpgradeRefuseSansDomaineAvantDeRienModifier : un domaine introuvable n'est pas un
// défaut à deviner. La commande doit s'arrêter là, pas empiler les couches puis échouer.
func TestLUpgradeRefuseSansDomaineAvantDeRienModifier(t *testing.T) {
	src := upgradeSource(t)

	if !strings.Contains(src, `pass --domain <domain>`) {
		t.Error("aucun message actionnable quand le domaine est introuvable : " +
			"l'opérateur ne saurait pas qu'il peut le passer en flag")
	}
	iRefus := strings.Index(src, "pass --domain <domain>")
	iPreflight := strings.Index(src, "upgrade.Preparer(")
	if iRefus < 0 || iPreflight < 0 || iRefus > iPreflight {
		t.Error("le refus n'a pas lieu au preflight : la commande aurait déjà commencé " +
			"à travailler avant de constater qu'elle n'a pas de domaine")
	}
}

// TestLeDomaineAnnonceNeSeReclamePasDeKeycloak : le nom de la fonction disait « read
// from what Keycloak itself announces » alors qu'elle rend une variable de paquet.
// KC_HOSTNAME n'est même pas posé sur le Deployment. Un nom qui décrit un mécanisme
// inexistant est un piège à relecture.
func TestLeDomaineAnnonceNeSeReclamePasDeKeycloak(t *testing.T) {
	src, err := os.ReadFile("../../internal/identity/identity.go")
	if err != nil {
		t.Fatalf("reading identity.go: %v", err)
	}
	if strings.Contains(string(src), "func domaineDepuisKeycloak(") {
		t.Error("domaineDepuisKeycloak est revenu : ce nom affirme une lecture de Keycloak " +
			"que le code ne fait pas")
	}
	if !strings.Contains(string(src), "func domaineAnnonce(") {
		t.Error("domaineAnnonce a disparu : le domaine annoncé par l'appelant est le seul " +
			"mécanisme en place")
	}
}
