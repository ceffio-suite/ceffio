// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package identity

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ceffio-suite/ceffio/internal/identity/theme"
	"github.com/ceffio-suite/ceffio/internal/k8sapi"
)

// TestLesClassesDuHeaderSontStylees is the check the plan asks for, and it catches a
// failure that looks like a broken theme rather than a missing rule.
//
// THE HEADER LIVES IN displayNameHtml, NOT IN A TEMPLATE. keycloak.v2 renders that
// string itself, which is what keeps the theme upgrade-safe — but it also means the
// two classes in it are the ONLY thing tying the header to Ceffio's styling. Rename
// one in the HTML without renaming it in the CSS and the header renders as unstyled
// text, centred in the card, in the wrong font, with the slogan at body size.
//
// THE TEST READS BOTH SIDES: the classes out of the constant, the selectors out of
// the stylesheet that actually ships.
func TestLesClassesDuHeaderSontStylees(t *testing.T) {
	classes := classesDuHeader()
	if len(classes) == 0 {
		t.Fatalf("no class in the display name HTML: %s", DisplayNameHTML)
	}

	css := cssEmbede(t)
	for _, c := range classes {
		// A CLASS FROM THE PARENT THEME IS LEGITIMATE. `kc-logo-text` belongs to
		// keycloak.v2, which styles it — that is exactly why the header can be built
		// from a realm string instead of a template. What must not happen is a class
		// that NEITHER this stylesheet nor the parent knows: it renders as unstyled
		// text inside the card.
		if classesParent[c] {
			continue
		}
		motif := regexp.MustCompile(`\.` + regexp.QuoteMeta(c) + `\b`)
		if !motif.MatchString(css) {
			t.Errorf("class %q appears in displayNameHtml but is styled by neither "+
				"ceffio.css nor keycloak.v2.\nThe header is rendered from that string, "+
				"so a class nobody styles renders as raw text inside the sign-in card.\n"+
				"HTML: %s", c, DisplayNameHTML)
		}
	}
}

// TestLeHeaderPorteLeLogoCeffio : the header names the product and carries the
// slogan. A theme that only recolours Keycloak's default page still says "Keycloak"
// above the card on a platform nobody should have to identify.
func TestLeHeaderPorteLeLogoCeffio(t *testing.T) {
	if !strings.Contains(DisplayNameHTML, "Ceffio") {
		t.Errorf("the header does not name Ceffio: %s", DisplayNameHTML)
	}
	if !strings.Contains(DisplayNameHTML, "ceffio-slogan") {
		t.Errorf("the header carries no ceffio-slogan element, so the slogan cannot be "+
			"styled or changed without touching the HTML: %s", DisplayNameHTML)
	}
	if !strings.Contains(DisplayNameHTML, "kc-logo-text") {
		t.Errorf("the header does not use kc-logo-text, the block keycloak.v2 styles "+
			"as the logo area: %s", DisplayNameHTML)
	}
	// THE STRING IS INSERTED INTO A SHELL COMMAND SINGLE-QUOTED, so an apostrophe
	// would break the kcadm call. The slogan is French and French text invites one.
	if strings.Contains(DisplayNameHTML, "'") {
		t.Error("the display name HTML contains an apostrophe, which breaks the " +
			"single-quoted kcadm argument: use a phrasing without one, or quote it")
	}
}

// TestLeRealmNEstPasMaster : the login page applies to the ceffio realm only. The
// master realm's page is how Keycloak itself is administered, and an administrator
// who lands on the wrong door must see it.
func TestLeRealmNEstPasMaster(t *testing.T) {
	if realmCeffio == "master" {
		t.Fatal("realmCeffio is master: theming it would replace the page used to " +
			"administer Keycloak, and an operator with a broken realm would have no " +
			"recognisable way back in")
	}
	if realmCeffio != "ceffio" {
		t.Errorf("realmCeffio = %q, expected ceffio", realmCeffio)
	}
}

// TestLesLocalesDeclareesSontSupportees : the default locale must be one of the
// supported ones, otherwise Keycloak ignores it silently and serves English.
func TestLesLocalesDeclareesSontSupportees(t *testing.T) {
	defaut := ReglagesParDefaut()
	script := localesSupportees
	var trouve bool
	for _, l := range script {
		if l == defaut.Locale {
			trouve = true
		}
	}
	if !trouve {
		t.Errorf("the default locale %q is not among the supported ones %v: Keycloak "+
			"ignores a default outside the list and serves its own default instead",
			defaut.Locale, script)
	}
	// THE PRODUCT IS FRENCH-FIRST.
	if defaut.Locale != "fr" {
		t.Errorf("the default locale is %q, expected fr: Ceffio is distributed to "+
			"French-speaking operators, and English-by-default is what they complained "+
			"about", defaut.Locale)
	}
}

// TestLeThemeParDefautEstCeffio : an installation gets the Ceffio page, not
// Keycloak's.
func TestLeThemeParDefautEstCeffio(t *testing.T) {
	if r := ReglagesParDefaut(); r.Theme != "ceffio" {
		t.Errorf("the default theme is %q, expected ceffio: the whole point of the "+
			"theme is that users see it without configuring anything", r.Theme)
	}
}

// classesParent lists the classes keycloak.v2 provides and styles itself.
//
// THEY ARE NAMED HERE RATHER THAN ASSUMED: adding an entry is a deliberate act that
// says "the parent handles this one", which is a claim someone can check against the
// keycloak.v2 sources. A typo in a class name would fall through to the regex check
// above and fail.
var classesParent = map[string]bool{
	"kc-logo-text": true,
}

// classesDuHeader returns the class names inside the display name HTML.
func classesDuHeader() []string {
	motif := regexp.MustCompile(`class="([^"]*)"`)
	var out []string
	for _, m := range motif.FindAllStringSubmatch(DisplayNameHTML, -1) {
		out = append(out, strings.Fields(m[1])...)
	}
	return out
}

// cssEmbede returns the stylesheet as it ships.
func cssEmbede(t *testing.T) string {
	t.Helper()
	fs, err := theme.Fichiers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if strings.HasSuffix(f.Chemin, "ceffio.css") {
			return string(f.Contenu)
		}
	}
	t.Fatal("ceffio.css is not in the embedded theme")
	return ""
}

// TestCorpsJSONIsoleLeDocument : kcadm writes its progress to the same stream as the
// document, and a straight Unmarshal fails on the 'L' of "Logging into…". This was
// found in production, where the settings form rendered empty with
// `invalid character 'L' after top-level value`.
func TestCorpsJSONIsoleLeDocument(t *testing.T) {
	for _, cas := range []struct {
		nom, entree, attendu string
	}{
		{
			"kcadm precede le document de sa ligne de connexion",
			"Logging into http://localhost:8080 as user admin of realm master\n" +
				"{\n  \"loginTheme\" : \"ceffio\",\n  \"defaultLocale\" : \"fr\"\n}\n",
			"{\n  \"loginTheme\" : \"ceffio\",\n  \"defaultLocale\" : \"fr\"\n}",
		},
		{
			"un document seul",
			`{"loginTheme":"keycloak.v2"}`,
			`{"loginTheme":"keycloak.v2"}`,
		},
		{
			"sans document, rien",
			"Invalid user credentials\n",
			"",
		},
		{
			"des accolades vides, rien d'exploitable",
			"}{",
			"",
		},
	} {
		if got := corpsJSON(cas.entree); got != cas.attendu {
			t.Errorf("%s :\n  obtenu  %q\n  attendu %q", cas.nom, got, cas.attendu)
		}
	}
}

// TestPodKeycloakIgnoreUnPodQuiMeurt: le pod en cours de suppression répond
// encore « Ready » quelques secondes, et un exec dessus est tué avec lui.
//
// LE DÉFAUT, MESURÉ : juste après le déploiement de Keycloak 26.8, l'application
// du thème a échoué avec « command terminated with exit code 137 » — rien
// d'autre. Le pod choisi était celui que le kubelet était en train de tuer.
func TestPodKeycloakIgnoreUnPodQuiMeurt(t *testing.T) {
	maintenant := time.Now()
	cli := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "keycloak-vieux", Namespace: "ceffio-identity",
				Labels:            map[string]string{"app": "keycloak"},
				CreationTimestamp: metav1.NewTime(maintenant.Add(-time.Hour)),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "keycloak", Ready: true}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "keycloak-neuf", Namespace: "ceffio-identity",
				Labels:            map[string]string{"app": "keycloak"},
				CreationTimestamp: metav1.NewTime(maintenant),
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "keycloak", Ready: true}}},
		},
	)
	// Le vieux pod est marqué pour suppression : il ne doit jamais être choisi.
	vieux, _ := cli.CoreV1().Pods("ceffio-identity").Get(context.Background(), "keycloak-vieux", metav1.GetOptions{})
	vieux.DeletionTimestamp = &metav1.Time{Time: maintenant}
	if _, err := cli.CoreV1().Pods("ceffio-identity").Update(context.Background(), vieux, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("marquage du pod : %v", err)
	}

	client := k8sapi.PourTest(cli, nil)
	nom, err := podKeycloak(context.Background(), client, "ceffio-identity")
	if err != nil {
		t.Fatalf("podKeycloak : %v", err)
	}
	if nom != "keycloak-neuf" {
		t.Errorf("pod choisi = %q, attendu keycloak-neuf (le plus récent, pas celui qui meurt)", nom)
	}
}
