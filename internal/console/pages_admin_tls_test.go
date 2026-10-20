// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console_test

import (
	"os"
	"strings"
	"testing"
)

// page returns the console's HTML as it ships.
func page(t *testing.T) string {
	t.Helper()
	brut, err := os.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("reading the page: %v", err)
	}
	return string(brut)
}

// TestLaPageAdministrationListeToutesLesInterfaces : la carte annonçait « ces
// interfaces » et n'en listait que trois sur cinq.
//
// LONGHORN ET KEYCLOAK MANQUAIENT, alors que les deux sont des interfaces
// d'administration à part entière : Longhorn sait les volumes, leurs répliques et leur
// santé ; Keycloak sait le realm, ses clients et ses sessions. Un opérateur qui cherche
// à révoquer une session n'a aucune raison d'aller dans les réglages d'un module.
func TestLaPageAdministrationListeToutesLesInterfaces(t *testing.T) {
	p := page(t)
	for _, attendu := range []struct{ nom, marqueur string }{
		{"Nextcloud", "url_admin_nextcloud"},
		{"Stalwart", "url_admin_stalwart"},
		{"OpenBao", "url_admin_coffre"},
		{"Longhorn", "url_admin_longhorn"},
		{"Keycloak", "url_admin_keycloak"},
	} {
		if !strings.Contains(p, attendu.marqueur) {
			t.Errorf("%s n'est pas listé dans la page Administration (marqueur %q absent) : "+
				"la carte dit « ces interfaces » et doit les lister toutes",
				attendu.nom, attendu.marqueur)
		}
	}
}

// TestLonghornAbsentEstExplique : le module est OPTIONNEL, donc le lien manque sur une
// installation qui ne l'a pas demandé.
//
// UNE LIGNE MANQUANTE SE LIT COMME UN BUG DE LA PAGE, pas comme un choix : la phrase de
// remplacement dit quoi installer, et où.
func TestLonghornAbsentEstExplique(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "Not installed") {
		t.Error("aucun texte de remplacement quand Longhorn n'est pas installé : la ligne " +
			"disparaîtrait sans rien dire")
	}
	if !strings.Contains(p, "module install longhorn-ui") {
		t.Error("le texte de remplacement ne dit pas quelle commande installe le module : " +
			"l'opérateur doit deviner")
	}
}

// TestLaPageTLSAfficheLeRenouvellement : l'échéance seule est rassurante et ne dit rien
// de l'automatisation.
//
// UN CERTIFICAT QUI EXPIRERA SANS JAMAIS SE RENOUVELER RESSEMBLE À UN CERTIFICAT SAIN
// jusqu'au jour où il cesse de fonctionner. Ce qui doit être visible est QUAND le
// renouvellement est PRÉVU.
func TestLaPageTLSAfficheLeRenouvellement(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "Renews") {
		t.Error("aucune colonne de renouvellement : la page affiche l'échéance sans dire " +
			"si le renouvellement est encore planifié")
	}
	if !strings.Contains(p, "rendreRenouvellement") {
		t.Error("aucun rendu du renouvellement : une date absente doit se lire « not " +
			"scheduled », pas « bientôt »")
	}
	if !strings.Contains(p, "not scheduled") {
		t.Error("un renouvellement absent n'est pas signalé comme anormal")
	}
}

// TestLaPageTLSAfficheLaConfiguration : sans elle, la page liste des certificats sans
// dire comment ils sont obtenus ni par quel hébergeur — le premier point à vérifier
// quand un renouvellement échoue.
func TestLaPageTLSAfficheLaConfiguration(t *testing.T) {
	p := page(t)
	for _, marqueur := range []string{"tlsConfig", "chargerTLS", "/api/certificates"} {
		if !strings.Contains(p, marqueur) {
			t.Errorf("%q absent : la page n'appelle pas la route qui rapporte la "+
				"configuration RÉSOLUE (challenge, provider, zone)", marqueur)
		}
	}
}

// TestUnDNSSansIdentifiantEstSignale : une configuration DNS-01 sans identifiant stocké
// ne peut pas se renouveler — et elle ne le dira qu'au moment du renouvellement, quand
// personne ne regarde.
func TestUnDNSSansIdentifiantEstSignale(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "identifiant_defini") {
		t.Error("la page ne lit pas identifiant_defini : un DNS-01 sans credential " +
			"paraîtrait sain jusqu'à l'échec du renouvellement")
	}
	if !strings.Contains(p, "renewal will fail") {
		t.Error("l'absence d'identifiant n'est pas annoncée comme un échec de " +
			"renouvellement à venir")
	}
}

// TestLEnTeteNeMentPasSurLAutorite : la page annonçait « authority ceffio-ca » alors que
// le wildcard est signé par Let's Encrypt.
//
// UNE PHRASE FAUSSE DANS UN EN-TÊTE EST PIRE QU'UNE PHRASE ABSENTE : elle oriente la
// recherche au mauvais endroit le jour où un navigateur refuse un certificat.
func TestLEnTeteNeMentPasSurLAutorite(t *testing.T) {
	p := page(t)
	if strings.Contains(p, `authority "ceffio-ca"`) {
		t.Error("l'en-tête affirme que tout est signé par ceffio-ca : le wildcard des " +
			"services publics est signé par Let's Encrypt, et la colonne Issuer le montre " +
			"désormais")
	}
}

// TestLaPageTLSListeLesHotesServis : le tableau liste les CERTIFICATS, pas les HÔTES.
//
// UN HÔTE QUI RÉUTILISE LE WILDCARD — longhorn.<domaine> — n'a aucun certificat à lui :
// il n'apparaissait donc NULLE PART, alors que son TLS fonctionne. On en conclut qu'il
// n'est pas protégé, et on va chercher un problème qui n'existe pas.
func TestLaPageTLSListeLesHotesServis(t *testing.T) {
	p := page(t)
	for _, marqueur := range []string{"tlsHosts", "renderTLSHosts", "Hosts served"} {
		if !strings.Contains(p, marqueur) {
			t.Errorf("%q absent : la page n'affiche pas les hôtes réellement servis, donc "+
				"un hôte couvert par le wildcard reste invisible", marqueur)
		}
	}
}

// TestLaPageTLSResoutLeWildcard : chaque hôte doit être rapproché du certificat qui le
// couvre, wildcard compris.
//
// SANS CETTE RÉSOLUTION, la colonne dirait « no certificate » sur un hôte servi par
// *.domaine — exactement le contraire de la réalité.
func TestLaPageTLSResoutLeWildcard(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "*.' + parts.slice(1)") {
		t.Error("aucune résolution du wildcard : un hôte comme longhorn.exemple.org serait " +
			"annoncé sans certificat alors que *.exemple.org le couvre")
	}
	if !strings.Contains(p, "no certificate") {
		t.Error("un hôte sans certificat n'est pas signalé")
	}
}

// TestChaqueNomEstAffiche : le certificat wildcard couvre deux noms, et n'en montrer
// qu'un rend le second invisible.
func TestChaqueNomEstAffiche(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "function couvre(") {
		t.Error("aucune fonction qui affiche TOUS les noms d'un certificat")
	}
	if !strings.Contains(p, "c.noms") {
		t.Error("la page ne lit pas la liste complète des noms couverts")
	}
}

// TestLaPageLitLaBonneCle : le statut expose « ingress », pas « ingresses ».
//
// UNE CLÉ MAL NOMMÉE DONNE UNE LISTE VIDE, donc une section qui ne s'affiche jamais —
// et un test qui vérifie la présence du code ne le voit pas. Celle-ci vérifie la clé.
func TestLaPageLitLaBonneCle(t *testing.T) {
	p := page(t)
	if !strings.Contains(p, "st.ingress ||") {
		t.Error("la page ne lit pas la clé « ingress » du statut : la section des hôtes " +
			"servis resterait vide sans rien signaler")
	}
}
