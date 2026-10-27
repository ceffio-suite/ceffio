// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package longhornui

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/vault"
	"sigs.k8s.io/yaml"
)

// proxyDe rend le manifeste du proxy, parsé.
func proxyDe(t *testing.T) map[string]any {
	t.Helper()
	ann, err := annotationsProxy("abc123")
	if err != nil {
		t.Fatalf("les annotations du pod sont refusées : %v", err)
	}
	brut := manifesteProxy("exemple.org", ann)
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(brut), &doc); err != nil {
		t.Fatalf("le manifeste du proxy n'est pas du YAML valide : %v", err)
	}
	return doc
}

// podSpec rend le spec du pod du proxy.
func podSpec(t *testing.T) map[string]any {
	t.Helper()
	return proxyDe(t)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}

// annotationsPod rend les annotations du pod du proxy.
func annotationsPod(t *testing.T) map[string]string {
	t.Helper()
	tpl := proxyDe(t)["spec"].(map[string]any)["template"].(map[string]any)
	brut, _ := yaml.Marshal(tpl["metadata"].(map[string]any)["annotations"])
	var m map[string]string
	if err := yaml.Unmarshal(brut, &m); err != nil {
		t.Fatalf("les annotations ne sont pas une carte de chaînes : %v", err)
	}
	return m
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

// TestLesSecretsSontDesFichiersInjectes covers the shape of the A4 migration: the
// two credentials reach the process as FILES the injector renders, and nothing in
// the pod reads a Kubernetes Secret any more.
//
// THE ENVIRONMENT VARIABLES ARE THE TRAP. oauth2-proxy returns the variable when
// it is set and NEVER OPENS THE FILE (ProviderData.GetClientSecret, v7.15.5), so
// leaving OAUTH2_PROXY_CLIENT_SECRET in the manifest would make the injected file
// decorative: everything would look migrated, and a rotation in the vault would
// change nothing.
func TestLesSecretsSontDesFichiersInjectes(t *testing.T) {
	ann := annotationsPod(t)

	// THE ROLE IS THE MODULE'S ID — that is the name the vault layer gives the
	// Kubernetes auth role built from the registry. Any other value asks for a
	// role nobody created and the pod hangs in Init.
	if ann["vault.hashicorp.com/role"] != idModule {
		t.Errorf("role = %q, attendu %q (le nom que la couche coffre crée)",
			ann["vault.hashicorp.com/role"], idModule)
	}
	if ann["vault.hashicorp.com/agent-inject"] != "true" {
		t.Error("le pod ne demande pas l'injection : il démarrerait sans secrets")
	}
	if ann["vault.hashicorp.com/secret-volume-path"] != "/secrets" {
		t.Errorf("secret-volume-path = %q", ann["vault.hashicorp.com/secret-volume-path"])
	}
	// THE AGENT MUST RUN AS THE POD'S USER: a file in 0400 is readable only by
	// its owner, and the agent is what creates it.
	if ann["vault.hashicorp.com/agent-run-as-user"] != "65532" {
		t.Errorf("agent-run-as-user = %q : le fichier appartiendrait à l'agent, et le "+
			"proxy (65532) ne pourrait pas le lire", ann["vault.hashicorp.com/agent-run-as-user"])
	}

	for _, nom := range []string{"client-secret", "cookie-secret"} {
		if got := ann["vault.hashicorp.com/agent-inject-secret-"+nom]; got != cheminCoffre {
			t.Errorf("agent-inject-secret-%s = %q, attendu %q", nom, got, cheminCoffre)
		}
		if got := ann["vault.hashicorp.com/agent-inject-perms-"+nom]; got != "0400" {
			t.Errorf("agent-inject-perms-%s = %q, attendu 0400", nom, got)
		}
		if got := ann["vault.hashicorp.com/error-on-missing-key-"+nom]; got != "true" {
			t.Errorf("error-on-missing-key-%s = %q : une clé absente doit arrêter le pod", nom, got)
		}
	}

	_, args := conteneurProxy(t)
	var client, cookie bool
	for _, a := range args {
		switch a {
		case "--client-secret-file=" + cheminSecretClient:
			client = true
		case "--cookie-secret-file=" + cheminSecretCookie:
			cookie = true
		case "--client-secret-file=", "--cookie-secret-file=":
			t.Errorf("argument vide : %q", a)
		}
	}
	if !client || !cookie {
		t.Errorf("args = %v : les deux fichiers doivent être nommés (client %v, cookie %v)",
			args, client, cookie)
	}

	c, _ := conteneurProxy(t)
	if envs, ok := c["env"].([]any); ok {
		for _, e := range envs {
			m := e.(map[string]any)
			if n, _ := m["name"].(string); strings.HasPrefix(n, "OAUTH2_PROXY_") {
				t.Errorf("variable d'environnement %q : elle l'emporterait sur le fichier "+
					"injecté, qui ne serait alors jamais lu", n)
			}
		}
	}

	// NO VOLUME FROM A KUBERNETES SECRET: the pod must read what the agent
	// renders, and nothing else.
	for _, v := range podSpec(t)["volumes"].([]any) {
		m := v.(map[string]any)
		if _, ok := m["secret"]; ok {
			t.Errorf("le pod monte un Secret Kubernetes (%v) : les valeurs sont rendues "+
				"par l'injecteur, un Secret serait une seconde copie", m)
		}
	}
}

// TestLesFichiersRendusNeFinissentPasParUnSautDeLigne executes the templates the
// pod actually receives, with a fake `secret` function, and compares the bytes.
//
// THIS IS THE TEST THAT PROTECTS THE SIGN-IN. oauth2-proxy reads both files with
// os.ReadFile and uses the bytes as they are: a trailing newline makes the secret
// differ from the one Keycloak issued, and the only symptom is a refused login.
func TestLesFichiersRendusNeFinissentPasParUnSautDeLigne(t *testing.T) {
	ann := annotationsPod(t)

	donnees := map[string]any{"Data": map[string]any{"data": map[string]any{
		"client-secret": "cs-valeur",
		"cookie_secret": "ck-valeur",
	}}}
	attendu := map[string]string{
		"client-secret": "cs-valeur",
		"cookie-secret": "ck-valeur",
	}

	for _, nom := range []string{"client-secret", "cookie-secret"} {
		gabarit := ann["vault.hashicorp.com/agent-inject-template-"+nom]
		if gabarit == "" {
			t.Fatalf("%s : aucun modèle d'injection", nom)
		}
		// THE BLOCK SCALAR'S NEWLINE IS PART OF WHAT THE AGENT RECEIVES; without
		// it the template would never meet the case this test is about.
		if !strings.HasSuffix(gabarit, "\n") {
			t.Fatalf("%s : le modèle décodé ne finit pas par le saut de ligne du bloc YAML", nom)
		}

		tpl, err := template.New(nom).Funcs(template.FuncMap{
			"secret": func(p string) map[string]any {
				if p != cheminCoffre {
					t.Fatalf("%s : le modèle lit %q, attendu %q", nom, p, cheminCoffre)
				}
				return donnees
			},
		}).Parse(gabarit)
		if err != nil {
			t.Fatalf("%s : modèle illisible : %v", nom, err)
		}
		var b bytes.Buffer
		if err := tpl.Execute(&b, nil); err != nil {
			t.Fatalf("%s : le modèle ne s'exécute pas : %v", nom, err)
		}

		rendu := b.String()
		if rendu != attendu[nom] {
			t.Errorf("%s : le fichier contiendrait %q, attendu %q (un saut de ligne final "+
				"rend le secret plus long que celui que Keycloak a émis)", nom, rendu, attendu[nom])
		}
	}
}

// TestLAccesAuCoffreEstDeclare : the module declares its own vault access, and the
// declaration is what the policy is built from.
func TestLAccesAuCoffreEstDeclare(t *testing.T) {
	info := (&longhornUIModule{}).Info()
	if len(info.Vault) != 1 {
		t.Fatalf("Vault = %+v, attendu une déclaration", info.Vault)
	}
	a := info.Vault[0]
	if a.ServiceAccount != nomServiceAccount {
		t.Errorf("ServiceAccount = %q, attendu %q : c'est le compte que le pod porte",
			a.ServiceAccount, nomServiceAccount)
	}
	if a.Namespace != nsSysteme {
		t.Errorf("Namespace = %q, attendu %q", a.Namespace, nsSysteme)
	}
	if len(a.Paths) != 1 || a.Paths[0] != cheminCoffre {
		t.Errorf("Paths = %v, attendu [%q]", a.Paths, cheminCoffre)
	}

	// THE PREFIX RULE IS ENFORCED BY THE VAULT LAYER: the declaration must pass
	// it, which also proves the component name and the module ID agree.
	if _, err := vault.PolitiqueModule(idModule, a.Paths); err != nil {
		t.Errorf("la déclaration serait refusée au provisionnement : %v", err)
	}

	// THE INJECTOR READS A ROLE NAMED AFTER THE MODULE, so the component name in
	// the vault path must be the module ID: otherwise the entry would live under
	// another module's prefix, which the policy refuses.
	if coffreComposant != idModule {
		t.Errorf("composant du coffre = %q, attendu %q (le préfixe de la politique)",
			coffreComposant, idModule)
	}
}
