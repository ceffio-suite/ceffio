package ingress

import "testing"

func TestChoixIssuer(t *testing.T) {
	cas := []struct{ domaine, attendu, quoi string }{
		{"ceffio.org", issuerACME, "domaine public -> Let's Encrypt"},
		{"ceffio.mandem-it.com", issuerACME, "domaine public -> Let's Encrypt"},
		{"ceffio.local", issuerCA, "domaine prive -> CA interne"},
		{"demo.test", issuerCA, "TLD reserve -> CA interne"},
		{"localhost", issuerCA, "sans point -> CA interne"},
		{"54.36.165.68", issuerCA, "IP -> CA interne"},
	}
	for _, c := range cas {
		if got := issuerPour(c.domaine); got != c.attendu {
			t.Errorf("%s : %s -> %s, attendu %s", c.domaine, c.quoi, got, c.attendu)
		}
	}
	// La variable force le choix
	t.Setenv("CEFFIO_TLS_ISSUER", "ca")
	if got := issuerPour("ceffio.org"); got != issuerCA {
		t.Errorf("CEFFIO_TLS_ISSUER=ca ignore sur un domaine public")
	}
	t.Setenv("CEFFIO_TLS_ISSUER", "letsencrypt")
	if got := issuerPour("ceffio.local"); got != issuerACME {
		t.Errorf("CEFFIO_TLS_ISSUER=letsencrypt ignore sur un domaine prive")
	}
}
