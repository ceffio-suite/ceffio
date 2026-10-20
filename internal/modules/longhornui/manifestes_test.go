// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"strings"
	"testing"

	"github.com/ceffio-suite/ceffio/internal/module"
	"sigs.k8s.io/yaml"
)

// proxyDe rend le manifeste du proxy, parsé.
func proxyDe(t *testing.T) map[string]any {
	t.Helper()
	brut := manifesteProxy("exemple.org", "abc123")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(brut), &doc); err != nil {
		t.Fatalf("le manifeste du proxy n'est pas du YAML valide : %v", err)
	}
	return doc
}

// conteneurProxy rend le conteneur oauth2-proxy.
func conteneurProxy(t *testing.T) (map[string]any, []string) {
	t.Helper()
	doc := proxyDe(t)
	spec := doc["spec"].(map[string]any)
	tpl := spec["template"].(map[string]any)["spec"].(map[string]any)
	for _, c := range tpl["containers"].([]any) {
		m := c.(map[string]any)
		if m["name"] != "oauth2-proxy" {
			continue
		}
		var args []string
		for _, a := range m["args"].([]any) {
			args = append(args, a.(string))
		}
		return m, args
	}
	t.Fatal("aucun conteneur oauth2-proxy dans le manifeste")
	return nil, nil
}

// TestLImageEstEpinglee : a floating tag means the authorization decision changes
// between two installs of the same Ceffio version.
func TestLImageEstEpinglee(t *testing.T) {
	c, _ := conteneurProxy(t)
	img, _ := c["image"].(string)
	if !strings.HasPrefix(img, "quay.io/oauth2-proxy/oauth2-proxy:") {
		t.Errorf("image = %q, attendu l'image officielle épinglée", img)
	}
	tag := img[strings.LastIndex(img, ":")+1:]
	if tag == "latest" || !strings.HasPrefix(tag, "v") {
		t.Errorf("tag = %q : une étiquette flottante ferait varier la décision "+
			"d'autorisation entre deux installations de la même version de Ceffio", tag)
	}
}

// TestPasDeEmailDomain : a whole domain must never be opened.
//
// C'EST LA DÉCISION DE SÉCURITÉ DU MODULE : un domaine et un fichier d'adresses sont des
// ALTERNATIVES, et déclarer un domaine ouvrirait tout le domaine — y compris chaque
// compte qu'un administrateur créera plus tard — là où le fichier ouvre exactement ce
// qu'il liste.
func TestPasDeEmailDomain(t *testing.T) {
	c, args := conteneurProxy(t)
	for _, a := range args {
		if strings.HasPrefix(a, "--email-domain") {
			t.Errorf("l'argument %q ouvre un domaine entier : un compte créé plus tard y "+
				"entrerait sans que personne ne l'ait décidé", a)
		}
	}
	if envs, ok := c["env"].([]any); ok {
		for _, e := range envs {
			m := e.(map[string]any)
			if m["name"] == "OAUTH2_PROXY_EMAIL_DOMAINS" {
				t.Error("OAUTH2_PROXY_EMAIL_DOMAINS est posé : il ouvre un domaine entier, " +
					"et rend le fichier d'adresses inopérant")
			}
		}
	}
}

// TestLeFichierDAdressesEstLaSeuleAutorisation : the file is what decides, so it must be
// declared and mounted.
func TestLeFichierDAdressesEstLaSeuleAutorisation(t *testing.T) {
	_, args := conteneurProxy(t)
	var trouve bool
	for _, a := range args {
		if strings.HasPrefix(a, "--authenticated-emails-file=") {
			trouve = true
			if !strings.Contains(a, cheminAdresses) {
				t.Errorf("le fichier d'adresses est %q, attendu %q", a, cheminAdresses)
			}
		}
	}
	if !trouve {
		t.Fatal("aucun --authenticated-emails-file : le proxy accepterait TOUT compte " +
			"authentifié par Keycloak, alors que l'objectif est l'administrateur seul")
	}

	// THE VOLUME MUST EXIST, otherwise the file is named and absent — and the proxy
	// starts, then refuses everyone with a message about a missing file.
	spec := proxyDe(t)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	vols, _ := spec["volumes"].([]any)
	if len(vols) == 0 {
		t.Fatal("aucun volume : le proxy nomme un fichier qui n'existe pas dans le pod")
	}
	vu := false
	for _, v := range vols {
		m := v.(map[string]any)
		if cm, ok := m["configMap"].(map[string]any); ok && cm["name"] == nomConfig {
			vu = true
		}
	}
	if !vu {
		t.Errorf("aucun volume ne monte la ConfigMap %s", nomConfig)
	}
}

// TestAucuneOptionDangereuse : none of these may appear.
//
//   - insecure-oidc-allow-unverified-email : l'autorisation EST l'adresse, donc un
//     e-mail non vérifié ne prouve rien. La bonne réponse à un refus est de vérifier le
//     compte, pas de dire au proxy d'arrêter de vérifier ;
//   - cookie-secure=false : le cookie de session voyagerait en clair ;
//   - skip-auth-route : une route qui contourne la vérification sur une interface qui
//     supprime des volumes.
func TestAucuneOptionDangereuse(t *testing.T) {
	_, args := conteneurProxy(t)
	for _, a := range args {
		for _, interdit := range []string{
			"--insecure-oidc-allow-unverified-email",
			"--cookie-secure=false",
			"--skip-auth-route",
			"--skip-jwt-bearer-tokens=false",
		} {
			if strings.HasPrefix(a, interdit) {
				t.Errorf("option interdite dans le manifeste : %q", a)
			}
		}
	}
}

// TestLeProxyViseLonghornEtRienDUne : the upstream is the interface, through its
// ClusterIP Service.
func TestLeProxyViseLonghornEtRienDUne(t *testing.T) {
	_, args := conteneurProxy(t)
	var upstream string
	for _, a := range args {
		if strings.HasPrefix(a, "--upstream=") {
			upstream = a
		}
	}
	if upstream == "" {
		t.Fatal("aucun --upstream : le proxy n'a rien à servir")
	}
	attendu := "--upstream=http://longhorn-frontend.longhorn-system.svc:80"
	if upstream != attendu {
		t.Errorf("upstream = %q, attendu %q\nLe Service de l'interface Longhorn 1.13 a été "+
			"relevé sur l'installation : longhorn-frontend, port 80.", upstream, attendu)
	}
}

// TestLeProxyEstDurci : non-root, système de fichiers en lecture seule, capacités
// retirées, et les deux sondes.
func TestLeProxyEstDurci(t *testing.T) {
	c, _ := conteneurProxy(t)

	sc, _ := c["securityContext"].(map[string]any)
	if ro, _ := sc["readOnlyRootFilesystem"].(bool); !ro {
		t.Error("le système de fichiers n'est pas en lecture seule : un proxy qui écrit " +
			"sur son disque est un proxy qui peut être modifié par ce qu'il sert")
	}
	if esc, _ := sc["allowPrivilegeEscalation"].(bool); esc {
		t.Error("allowPrivilegeEscalation est vrai")
	}
	if _, ok := c["readinessProbe"]; !ok {
		t.Error("aucune sonde de disponibilité")
	}
	if _, ok := c["livenessProbe"]; !ok {
		t.Error("aucune sonde de vivacité")
	}

	// THE POD'S OWN CONTEXT: runAsNonRoot, otherwise the image's default user decides.
	spec := proxyDe(t)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	ps, _ := spec["securityContext"].(map[string]any)
	if nr, _ := ps["runAsNonRoot"].(bool); !nr {
		t.Error("le pod ne déclare pas runAsNonRoot")
	}
}

// TestLeChecksumRedemarreLePod : the address list is read at startup, so rewriting it
// changes nothing until the process restarts.
func TestLeChecksumRedemarreLePod(t *testing.T) {
	doc := proxyDe(t)
	tpl := doc["spec"].(map[string]any)["template"].(map[string]any)
	ann, _ := tpl["metadata"].(map[string]any)["annotations"].(map[string]any)
	if ann["ceffio.io/acces-somme"] != "abc123" {
		t.Errorf("l'annotation de somme vaut %v, attendue abc123 : sans elle, changer la "+
			"liste d'adresses ne change rien jusqu'au prochain redémarrage manuel",
			ann["ceffio.io/acces-somme"])
	}
}

// TestLaRouteViseLeProxy : the Ingress points at the proxy, NEVER at Longhorn.
//
// UNE ROUTE QUI VISERAIT longhorn-frontend exposerait une interface sans authentification
// sous un nom d'hôte qui a l'air protégé.
func TestLaRouteViseLeProxy(t *testing.T) {
	brut := manifesteServiceEtRoute("exemple.org")
	// THE SEPARATOR MUST BE AT INDENTATION ZERO. Kubernetes refuses an indented one with
	// "could not find expected ':'", and the message names neither the document nor the
	// line — found by deploying, not by reading.
	if strings.Contains(brut, "  ---") {
		t.Error("le séparateur de documents est indenté : kubectl refuse le manifeste avec " +
			"'could not find expected :'")
	}
	for _, doc := range strings.Split(brut, "\n---\n") {
		var o map[string]any
		if err := yaml.Unmarshal([]byte(doc), &o); err != nil {
			t.Fatalf("YAML invalide : %v", err)
		}
		if o["kind"] != "Ingress" {
			continue
		}
		spec := o["spec"].(map[string]any)
		rules := spec["rules"].([]any)
		r := rules[0].(map[string]any)
		if r["host"] != "longhorn.exemple.org" {
			t.Errorf("hôte = %v, attendu longhorn.exemple.org", r["host"])
		}
		http := r["http"].(map[string]any)
		chemins := http["paths"].([]any)
		p := chemins[0].(map[string]any)
		backend := p["backend"].(map[string]any)
		svc := backend["service"].(map[string]any)
		if svc["name"] != nomService {
			t.Errorf("la route vise le service %v, attendu %v (le proxy) — viser "+
				"longhorn-frontend exposerait une interface sans authentification",
				svc["name"], nomService)
		}
		return
	}
	t.Fatal("aucun Ingress dans le manifeste de route")
}

// TestLInfoEstCoherente : the declaration survives the contract's own verification.
func TestLInfoEstCoherente(t *testing.T) {
	m := &longhornUIModule{}
	i := m.Info()

	if i.Kind != module.Optional {
		t.Errorf("Kind = %v, attendu Optional : une interface d'administration qui peut "+
			"supprimer des volumes ne s'installe pas d'office", i.Kind)
	}
	if i.Default {
		t.Error("Default = true : le module s'installerait sur toute plateforme")
	}
	if i.Warning == "" {
		t.Error("aucun avertissement : l'opérateur doit lire, avant d'installer, que cette " +
			"page permet de supprimer des volumes")
	}
	if len(i.Requires) != 3 {
		t.Errorf("Requires = %v, attendu storage, identity et ingress", i.Requires)
	}
	if err := module.VerifierGroupesPourTest(idModule, m.Settings()); err != nil {
		t.Errorf("la déclaration est incohérente : %v", err)
	}
}

// TestAucunDroitSurLonghornSystem : the proxy reaches the interface through a ClusterIP
// Service, which is name resolution, not an API call.
func TestAucunDroitSurLonghornSystem(t *testing.T) {
	for _, p := range (&longhornUIModule{}).Info().Permissions {
		if p.Namespace == nsLonghorn {
			t.Errorf("le module demande des droits sur %s : le proxy n'y fait aucun appel "+
				"d'API. Les donner serait le premier pas vers un proxy qui pourrait "+
				"supprimer ce qu'il affiche", p.Namespace)
		}
	}
}

// TestLeServiceAccountDoitExister : le Deployment le nomme, et un pod dont le
// ServiceAccount n'existe pas n'est JAMAIS créé.
//
// TROUVÉ EN DÉPLOYANT : le Deployment s'appliquait proprement, restait à 0/1, et le
// ReplicaSet répondait FailedCreate en nommant le compte sans dire qui devait le créer.
func TestLeServiceAccountDoitExister(t *testing.T) {
	brut := manifesteServiceAccount()
	var o map[string]any
	if err := yaml.Unmarshal([]byte(brut), &o); err != nil {
		t.Fatalf("YAML invalide : %v", err)
	}
	if o["kind"] != "ServiceAccount" {
		t.Errorf("kind = %v", o["kind"])
	}
	md := o["metadata"].(map[string]any)
	if md["name"] != nomServiceAccount {
		t.Errorf("nom = %v, attendu %v", md["name"], nomServiceAccount)
	}

	// ET LE POD LE NOMME BIEN : un compte créé sous un autre nom ne servirait à rien.
	doc := proxyDe(t)
	spec := doc["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	if spec["serviceAccountName"] != md["name"] {
		t.Errorf("le pod tourne comme %v alors que le compte créé est %v : le pod ne "+
			"serait jamais créé", spec["serviceAccountName"], md["name"])
	}
}
