// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package theme

import (
	"strings"
	"testing"
)

// TestLeThemeEstComplet : the eleven files a Keycloak login theme needs, none of
// them empty.
//
// THE LIST IS EXPLICIT rather than "as many as there are". An embed directive that
// silently stops matching — a renamed directory, a stray .gitignore — produces a
// theme that still mounts and still renders, with Keycloak's default page, and no
// error anywhere. Naming the files is what turns that into a failure.
func TestLeThemeEstComplet(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}

	var attendus = []string{
		"login/theme.properties",
		"login/messages/messages_fr.properties",
		"login/messages/messages_en.properties",
		"login/resources/css/ceffio.css",
		"login/resources/img/logo.svg",
		"login/resources/img/background.jpg",
		"login/resources/img/favicon.ico",
		"login/resources/img/favicon.svg",
		"login/resources/fonts/sora-latin-400-normal.woff2",
		"login/resources/fonts/sora-latin-600-normal.woff2",
		"login/resources/fonts/OFL.txt",
	}
	pratique := map[string][]byte{}
	for _, f := range fs {
		pratique[f.Chemin] = f.Contenu
	}
	for _, a := range attendus {
		c, ok := pratique[a]
		if !ok {
			t.Errorf("%s is missing from the embedded theme", a)
			continue
		}
		if len(c) == 0 {
			t.Errorf("%s is empty: it would mount and be served as nothing", a)
		}
	}
	if len(fs) != len(attendus) {
		t.Errorf("%d files embedded, %d expected: a file added to the theme must be "+
			"named here, because a silent embed is a theme served with pieces missing",
			len(fs), len(attendus))
	}
}

// TestLaLicenceDesPolicesVoyage : Sora is SIL OFL 1.1, and the theme is a
// redistributable artifact. The licence has to be IN it, not only cited in
// THIRD_PARTY_LICENSES.md at the repository root.
func TestLaLicenceDesPolicesVoyage(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if !strings.HasSuffix(f.Chemin, "OFL.txt") {
			continue
		}
		texte := strings.ToLower(string(f.Contenu))
		if !strings.Contains(texte, "open font license") {
			t.Errorf("OFL.txt does not mention the Open Font License: it is not the " +
				"licence text, and the fonts travel unlicensed")
		}
		return
	}
	t.Fatal("OFL.txt is not embedded: the Sora fonts would be redistributed with no " +
		"licence, which SIL OFL 1.1 requires to accompany them")
}

// TestLesBinairesSontClassesBinaires : a JPEG in a ConfigMap's `data` is rejected by
// the API server with a message about invalid UTF-8 — naming neither the file nor
// the reason. The split has to be right BEFORE the API is called.
func TestLesBinairesSontClassesBinaires(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		switch {
		case strings.HasSuffix(f.Chemin, ".jpg"), strings.HasSuffix(f.Chemin, ".ico"),
			strings.HasSuffix(f.Chemin, ".woff2"):
			if !f.Binaire {
				t.Errorf("%s is classified as text: the API server would reject the "+
					"ConfigMap with an invalid UTF-8 message", f.Chemin)
			}
		case strings.HasSuffix(f.Chemin, ".css"), strings.HasSuffix(f.Chemin, ".svg"),
			strings.HasSuffix(f.Chemin, ".properties"), strings.HasSuffix(f.Chemin, ".txt"):
			if f.Binaire {
				t.Errorf("%s is classified as binary: it belongs in data, and base64 "+
					"would make it unreadable in `kubectl describe`", f.Chemin)
			}
		}
	}
}

// TestLaCleConfigMapEstLegale : a ConfigMap key cannot contain a slash, and must not
// begin or end with a dot. The flattening must produce a legal key, AND the inverse
// must give back the path — otherwise the volume mounts the file in the wrong place
// and Keycloak does not find it.
func TestLaCleConfigMapEstLegale(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.Contains(f.Cle, "/") {
			t.Errorf("%q contains a slash: the API server refuses the ConfigMap", f.Cle)
		}
		if strings.HasPrefix(f.Cle, ".") || strings.HasSuffix(f.Cle, ".") {
			t.Errorf("%q begins or ends with a dot, which is not a legal ConfigMap key", f.Cle)
		}
		if strings.ContainsAny(f.Cle, " \t\n") {
			t.Errorf("%q contains whitespace", f.Cle)
		}
		// THE ROUND TRIP IS THE POINT: the volume rebuilds the tree from the key.
		if retour := CheminDepuisCle(f.Cle); retour != f.Chemin {
			t.Errorf("key %q gives back %q, expected %q: the volume would mount the "+
				"file somewhere Keycloak does not look", f.Cle, retour, f.Chemin)
		}
	}
}

// TestLaSommeEstStable : the checksum goes on the pod template, so Kubernetes
// restarts Keycloak only when the theme really changed. A checksum that varies with
// the iteration order would restart the pod on every `ceffio install` — a login page
// outage each time, for no reason.
func TestLaSommeEstStable(t *testing.T) {
	a, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	if Somme(a) != Somme(b) {
		t.Error("two calls give different checksums: the pod would restart on every " +
			"install, cutting the login page for no reason")
	}
	if len(Somme(a)) != 64 {
		t.Errorf("the checksum is %d characters, expected 64 for a sha256 hex digest",
			len(Somme(a)))
	}

	// A ONE-BYTE CHANGE MUST CHANGE IT, otherwise an edited theme is never loaded:
	// in production Keycloak caches themes and only a restart picks up the change.
	copie := make([]Fichier, len(a))
	copy(copie, a)
	for i := range copie {
		if len(copie[i].Contenu) > 0 {
			copie[i].Contenu = append([]byte{}, copie[i].Contenu...)
			copie[i].Contenu[0] ^= 0xff
			break
		}
	}
	if Somme(a) == Somme(copie) {
		t.Error("a changed byte leaves the checksum identical: an edited theme would " +
			"never reach the browser")
	}
}

// TestLeThemeTientDansUneConfigMap : a ConfigMap is capped at 1 MiB, and the limit is
// the SUM of both maps. The theme is about 140 Kio today, so this test is not close —
// it exists because the next person adds a background image and finds out at deploy
// time otherwise.
func TestLeThemeTientDansUneConfigMap(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for _, f := range fs {
		total += len(f.Contenu)
		// Binary data costs about 4/3 once base64-encoded by the API client.
		if f.Binaire {
			total += len(f.Contenu) / 3
		}
	}
	const limite = 900 * 1024
	if total > limite {
		t.Errorf("the theme takes %d bytes, over the %d-byte budget: a ConfigMap is "+
			"capped at 1 MiB and the API server rejects it at deploy time, naming "+
			"nothing useful", total, limite)
	}
}

// TestLeParentEstKeycloakV2 : the theme EXTENDS keycloak.v2 and overrides no
// template. That is what makes a Keycloak upgrade safe: every page, every flow and
// every fix comes from upstream, and this theme only changes the look.
func TestLeParentEstKeycloakV2(t *testing.T) {
	fs, err := Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Chemin != "login/theme.properties" {
			continue
		}
		texte := string(f.Contenu)
		if !strings.Contains(texte, "parent=keycloak.v2") {
			t.Errorf("theme.properties does not declare parent=keycloak.v2:\n%s", texte)
		}
		// THE STYLESHEET ORDER IS THE MECHANISM: the parent's styles first, then
		// ceffio.css, so Ceffio's colours win without replacing PatternFly.
		if !strings.Contains(texte, "css/styles.css css/ceffio.css") {
			t.Errorf("the styles do not chain the parent's stylesheet before "+
				"ceffio.css:\n%s", texte)
		}
		return
	}
	t.Fatal("theme.properties is not embedded")
}
