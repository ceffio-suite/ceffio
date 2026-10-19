package acme

import "testing"

// TestIdentifiantsDesProvidersInTree : les quatre in-tree ont une table.
func TestIdentifiantsDesProvidersInTree(t *testing.T) {
	for _, p := range []Provider{ProviderCloudflare, ProviderRoute53, ProviderRFC2136, ProviderACMEDNS} {
		c, ok := IdentifiantsDuProvider(p)
		if !ok || len(c) == 0 {
			t.Errorf("%s: pas de champs declares", p)
		}
	}
}

// TestAUcunChampSansNom : chaque champ porte un nom et un libelle.
func TestAUcunChampSansNom(t *testing.T) {
	for p, champs := range identifiantsProvider {
		for i, c := range champs {
			if c.Name == "" || c.Label == "" {
				t.Errorf("%s[%d]: nom ou libelle vide", p, i)
			}
		}
	}
}

// TestProviderInconnuAUnRepli : un provider absent de la table obtient des champs libres.
func TestProviderInconnuAUnRepli(t *testing.T) {
	c := ChampsIdentifiant("hebergeur-inexistant")
	if len(c) == 0 {
		t.Fatal("aucun champ pour un provider inconnu : il ne serait pas configurable")
	}
}
