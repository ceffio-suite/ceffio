package version

import (
	"strings"
	"testing"
)

// TestRegistryEstCoherent vérifie ce que la documentation du registre promet :
// « Toute modification d'une image dans un module DOIT être répercutée ici : la
// fonction VerifierCoherence() le contrôle et le test le vérifie. »
//
// Ce test manquait. Une promesse écrite dans un commentaire et non vérifiée
// dérive au premier changement pressé — et c'est exactement par ce genre de
// trou qu'une version flottante entre en production.
func TestRegistryEstCoherent(t *testing.T) {
	if problemes := VerifierCoherence(); len(problemes) > 0 {
		for _, p := range problemes {
			t.Errorf("registre incohérent : %s", p)
		}
	}
}

// TestAucuneVersionFlottante interdit `latest` et `stable`.
//
// Un composant qui suit `latest` ne peut pas être mis à niveau de façon
// reproductible : on ne sait ni ce qui tourne avant, ni ce qui tournera après.
// C'est la règle que le paquet s'est lui-même fixée.
func TestAucuneVersionFlottante(t *testing.T) {
	for _, c := range Registry {
		switch c.Version {
		case "":
			t.Errorf("%s : image sans tag explicite (%s)", c.Nom, c.Image)
		case "latest", "stable":
			t.Errorf("%s : tag %q flottant, un tag pinné est requis", c.Nom, c.Version)
		}
	}
}

// TestImagesQualifiees impose un registre explicite dans la référence d'image.
//
// POURQUOI : `openbao/openbao:2.7.1` et `docker.io/openbao/openbao:2.7.1` ne
// désignent pas forcément la même chose selon la configuration du moteur. Sur
// une machine où un miroir est configuré, la forme courte peut tirer autre
// chose que ce qu'on croit — et c'est la sorte de panne qu'on ne voit qu'en
// production, sur la machine de quelqu'un d'autre.
func TestImagesQualifiees(t *testing.T) {
	for _, c := range Registry {
		// Les images officielles de la bibliothèque Docker sont une exception
		// assumée : `redis:7.4.11` est une forme reconnue, pas une imprécision.
		if strings.HasPrefix(c.Image, "redis:") {
			continue
		}
		if !strings.Contains(strings.SplitN(c.Image, "/", 2)[0], ".") {
			t.Errorf("%s : référence d'image non qualifiée (%s) — préfixer par docker.io/", c.Nom, c.Image)
		}
	}
}

// TestNomsUniques et les chemins : deux composants ne peuvent pas porter le même
// nom, sinon ParNom rend le premier et le second devient introuvable.
func TestNomsUniques(t *testing.T) {
	vus := make(map[string]bool, len(Registry))
	for _, c := range Registry {
		if vus[c.Nom] {
			t.Errorf("nom de composant en double : %s", c.Nom)
		}
		vus[c.Nom] = true
	}
}

// TestParNomTrouveTout vérifie que le registre est utilisable : chaque composant
// annoncé doit être retrouvable. Un registre qu'on ne peut pas interroger ne sert
// pas à grand-chose.
func TestParNomTrouveTout(t *testing.T) {
	for _, c := range Registry {
		got, ok := ParNom(c.Nom)
		if !ok {
			t.Errorf("ParNom(%q) ne trouve rien alors que le composant est déclaré", c.Nom)
			continue
		}
		if got.Image != c.Image {
			t.Errorf("%s : ParNom rend l'image %q au lieu de %q", c.Nom, got.Image, c.Image)
		}
	}
}

// TestOpenBaoDeclare vérifie explicitement que le coffre figure au registre.
//
// POURQUOI UN TEST NOMMÉ POUR UN COMPOSANT : le coffre est déployé par
// internal/vault et DOIT apparaître ici, sinon `upgrade` et `status` l'ignorent
// — un composant qui tourne sans être déclaré est un composant qu'on ne peut ni
// mettre à niveau ni diagnostiquer.
func TestOpenBaoDeclare(t *testing.T) {
	c, ok := ParNom("openbao")
	if !ok {
		t.Fatal("le coffre (openbao) est déployé par internal/vault mais absent du registre")
	}
	if !strings.Contains(c.Image, "openbao") {
		t.Errorf("image inattendue pour openbao : %s", c.Image)
	}
	if c.Module != "internal/vault" {
		t.Errorf("module annoncé pour openbao : %q, attendu internal/vault", c.Module)
	}
}