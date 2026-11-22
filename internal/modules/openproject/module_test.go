// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package openproject

import (
	"context"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/ceffio-suite/ceffio/internal/module"
	"github.com/ceffio-suite/ceffio/internal/version"
)

// TestInfoValide pins the display contract and the two values that silently
// change what every installation receives: Kind and Default.
func TestInfoValide(t *testing.T) {
	info := (&openprojectModule{}).Info()

	if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(info.ID) || info.ID != "openproject" {
		t.Errorf("Info.ID = %q, expected the kebab-case id %q", info.ID, "openproject")
	}
	if info.Title == "" || info.Description == "" || info.Resources == "" || info.Warning == "" {
		t.Error("Title, Description, Resources and Warning must all be filled: the operator reads them before installing")
	}
	if info.Kind != module.Optional {
		t.Errorf("Kind = %v, expected module.Optional", info.Kind)
	}
	if info.Default {
		t.Error("Default must be false: ~4 GiB of RAM is installed on request only")
	}
	// EACH DEPENDENCY IS LOAD-BEARING: without "vault" the injector has no
	// role, without "data" there is no database, and so on. A missing one
	// installs a module that never starts, with no error naming the cause.
	for _, dep := range []string{"storage", "data", "identity", "vault", "ingress"} {
		found := false
		for _, r := range info.Requires {
			found = found || r == dep
		}
		if !found {
			t.Errorf("Requires lacks %q", dep)
		}
	}
	if !reflect.DeepEqual(info.Namespaces, []string{"ceffio-system"}) {
		t.Errorf("Namespaces = %v, expected [ceffio-system]", info.Namespaces)
	}
	if len(info.Vault) != 1 || len(info.Vault[0].Paths) != 1 ||
		!strings.HasPrefix(info.Vault[0].Paths[0], "kv/data/ceffio/openproject/") {
		t.Errorf("Vault access must be one read rule under kv/data/ceffio/openproject/: %+v", info.Vault)
	}
	if info.Vault[0].ServiceAccount != nomServiceAccount || info.Vault[0].Namespace != nsProjets {
		t.Errorf("the vault role must bind the pods' ServiceAccount: %+v", info.Vault[0])
	}
}

// documents parses every manifest the module applies, by kind and name.
func documents(t *testing.T) map[string]map[string]interface{} {
	t.Helper()
	ap, err := annotationsProxy()
	if err != nil {
		t.Fatal(err)
	}
	brut := strings.Join([]string{
		manifesteBase("longhorn"),
		manifestePolitique(),
		manifesteRepondant(),
		manifesteApp("example.com", annotationsApp(), "docker.io/openproject/openproject:1-slim@sha256:0"),
		manifesteProxy("example.com", ap, "quay.io/oauth2-proxy/oauth2-proxy:v1@sha256:0"),
		manifesteRoute("example.com", "letsencrypt-prod"),
	}, "---\n")
	res := map[string]map[string]interface{}{}
	for i, doc := range strings.Split(brut, "\n---\n") {
		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("document %d is not valid YAML: %v\n%s", i, err, doc)
		}
		if obj == nil {
			continue
		}
		meta := obj["metadata"].(map[string]interface{})
		if meta["namespace"] != nil && meta["namespace"] != nsProjets {
			t.Errorf("%s/%s lands in namespace %v, expected %s", obj["kind"], meta["name"], meta["namespace"], nsProjets)
		}
		res[obj["kind"].(string)+"/"+meta["name"].(string)] = obj
	}
	return res
}

// champ walks a parsed document.
func champ(t *testing.T, v interface{}, chemin ...interface{}) interface{} {
	t.Helper()
	for _, p := range chemin {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]interface{})
			if !ok {
				t.Fatalf("expected a map before %q", k)
			}
			v = m[k]
		case int:
			l, ok := v.([]interface{})
			if !ok || len(l) <= k {
				t.Fatalf("expected a list of at least %d items", k+1)
			}
			v = l[k]
		}
	}
	return v
}

// TestManifestesComplets proves every object the module relies on is
// rendered, and parses: a format-string slip is a YAML error at apply time
// that names neither the module nor the verb.
func TestManifestesComplets(t *testing.T) {
	docs := documents(t)
	for _, cle := range []string{
		"ServiceAccount/openproject", "PersistentVolumeClaim/openproject-assets",
		"NetworkPolicy/openproject-only-from-proxy",
		"Deployment/openproject", "Service/openproject",
		"Deployment/openproject-proxy", "Service/openproject-proxy",
		"Deployment/openproject-ldap", "Service/openproject-ldap",
		"NetworkPolicy/openproject-ldap-only-from-app",
		"Ingress/openproject",
	} {
		if docs[cle] == nil {
			t.Errorf("manifest %s is missing", cle)
		}
	}
	if len(docs) != 11 {
		t.Errorf("%d documents rendered, expected 11", len(docs))
	}
}

// TestLaRouteMeneAuProxy: the Ingress must reach the proxy and NEVER the
// application — a route to OpenProject would let a browser forge the header.
func TestLaRouteMeneAuProxy(t *testing.T) {
	ing := documents(t)["Ingress/openproject"]
	backend := champ(t, ing, "spec", "rules", 0, "http", "paths", 0, "backend", "service", "name")
	if backend != nomProxy {
		t.Fatalf("the Ingress points at %v, expected the proxy %s", backend, nomProxy)
	}
	if champ(t, ing, "spec", "rules", 0, "host") != "projects.example.com" {
		t.Error("the Ingress host must be projects.<domain>")
	}
	ann := champ(t, ing, "metadata", "annotations").(map[string]interface{})
	if ann["cert-manager.io/cluster-issuer"] != "letsencrypt-prod" {
		t.Errorf("the issuer must be the one passed in: %v", ann)
	}
	if !strings.HasPrefix(ann["traefik.ingress.kubernetes.io/router.middlewares"].(string), nsProjets+"-") {
		t.Error("the redirection middleware must be referenced in the Ingress's own namespace")
	}
}

// TestSeulLeProxyAtteintOpenProject: the policy selects the application and
// admits only the proxy. A policy that selected nothing would accept the
// manifest and protect nothing — the control must be able to fail.
func TestSeulLeProxyAtteintOpenProject(t *testing.T) {
	np := documents(t)["NetworkPolicy/openproject-only-from-proxy"]
	if champ(t, np, "spec", "podSelector", "matchLabels", "app") != nomApp {
		t.Error("the NetworkPolicy must select the application pod")
	}
	regles := champ(t, np, "spec", "ingress").([]interface{})
	if len(regles) != 1 {
		t.Fatalf("exactly one ingress rule expected, got %d", len(regles))
	}
	sources := champ(t, regles[0], "from").([]interface{})
	if len(sources) != 1 || champ(t, sources[0], "podSelector", "matchLabels", "app") != nomProxy {
		t.Errorf("the only allowed source must be the proxy: %v", sources)
	}
	// THE LABELS MUST MATCH THE PODS: a typo in either name would make the
	// policy refuse the proxy too, and the site would answer 502.
	if champ(t, documents(t)["Deployment/openproject-proxy"], "spec", "template", "metadata", "labels", "app") != nomProxy {
		t.Error("the proxy pods do not carry the label the policy admits")
	}
}

// TestLesTroisProcessusPartagentLeurEnvironnement: the seeder, the web server
// and the worker must agree on the host name and the SSO header; the env is
// rendered once, and this proves it reached all three.
func TestLesTroisProcessusPartagentLeurEnvironnement(t *testing.T) {
	spec := champ(t, documents(t)["Deployment/openproject"], "spec", "template", "spec")
	seeder := champ(t, spec, "initContainers", 0)
	web := champ(t, spec, "containers", 0)
	worker := champ(t, spec, "containers", 1)
	if champ(t, seeder, "name") != "seeder" || champ(t, web, "name") != "web" || champ(t, worker, "name") != "worker" {
		t.Fatal("expected init container seeder, then containers web and worker")
	}
	env := champ(t, web, "env")
	if !reflect.DeepEqual(env, champ(t, seeder, "env")) || !reflect.DeepEqual(env, champ(t, worker, "env")) {
		t.Error("the three processes must receive the same environment")
	}
	var header, optional, locked string
	for _, e := range env.([]interface{}) {
		m := e.(map[string]interface{})
		switch m["name"] {
		case "OPENPROJECT_AUTH__SOURCE__SSO_HEADER":
			header = m["value"].(string)
		case "OPENPROJECT_AUTH__SOURCE__SSO_OPTIONAL":
			optional = m["value"].(string)
		case "OPENPROJECT_SEED__ADMIN__USER__LOCKED":
			locked = m["value"].(string)
		}
	}
	if header != enTeteUtilisateur || optional != "false" || locked != "true" {
		t.Errorf("SSO header %q / optional %q / seeded admin locked %q: expected %q / false / true",
			header, optional, locked, enTeteUtilisateur)
	}
}

// TestLeCoffrePasseAvantLeSeeder: without agent-init-first, the injector's
// init container runs AFTER the seeder, which then starts without
// DATABASE_URL.
func TestLeCoffrePasseAvantLeSeeder(t *testing.T) {
	ann := champ(t, documents(t)["Deployment/openproject"], "spec", "template", "metadata", "annotations").(map[string]interface{})
	if ann["vault.hashicorp.com/agent-init-first"] != "true" {
		t.Error("agent-init-first must be \"true\": the seeder needs /secrets/env")
	}
	if ann["vault.hashicorp.com/role"] != idModule {
		t.Errorf("the vault role must be the module ID (built by the vault layer from Info.Vault): %v",
			ann["vault.hashicorp.com/role"])
	}
	if !strings.Contains(ann["vault.hashicorp.com/agent-inject-template-env"].(string), "DATABASE_URL") {
		t.Error("the rendered env must carry DATABASE_URL")
	}
}

// TestDeconnexionFermeLesDeuxSessions: signing out must end the proxy's cookie
// AND Keycloak's session, and the nested URL must be escaped — an unescaped
// "&" would cut Keycloak's parameters off.
func TestDeconnexionFermeLesDeuxSessions(t *testing.T) {
	u := urlDeconnexion("example.com")
	if !strings.HasPrefix(u, "https://projects.example.com/oauth2/sign_out?rd=https%3A%2F%2Fkeycloak.example.com%2F") {
		t.Errorf("unexpected sign-out URL: %s", u)
	}
	if strings.Count(u, "&") != 0 {
		t.Errorf("the nested Keycloak URL is not escaped: %s", u)
	}
}

// TestLoginsRefuses: the reserved names and anything outside the username
// alphabet never reach Ruby or SQL.
func TestLoginsRefuses(t *testing.T) {
	for _, login := range []string{"admin", "Admin", "system", "anonymous", "", "a b", "x'; DROP", `#{1}`, "-start"} {
		if err := verifierLogin(login); err == nil {
			t.Errorf("verifierLogin(%q) accepted a login it must refuse", login)
		}
	}
	for _, login := range []string{"okba", "merouane.agar", "z_djennane", "user@example.com", compteAdmin} {
		if err := verifierLogin(login); err != nil {
			t.Errorf("verifierLogin(%q) refused a valid login: %v", login, err)
		}
	}
}

// TestScriptCompteNInterpreteRien: the data travels as JSON inside a quoted
// heredoc, so a hostile address cannot become Ruby code.
func TestScriptCompteNInterpreteRien(t *testing.T) {
	s, err := scriptCompte(compteOP{Login: "okba", Mail: "#{`id`}@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "<<~'CEFFIO'") {
		t.Error("the heredoc must be single-quoted, which disables interpolation")
	}
	if strings.Count(s, "\nCEFFIO\n") != 1 {
		t.Error("the heredoc terminator must appear exactly once")
	}
	if _, err := scriptCompte(compteOP{Login: "okba"}); err == nil {
		t.Error("an account without e-mail must be refused before Rails is asked")
	}
	if _, err := scriptCompte(compteOP{Login: "admin", Mail: "a@b.c"}); err == nil {
		t.Error("the reserved login admin must be refused")
	}
}

// TestLaSourceLDAPViseLeRepondant: the auth source every account is linked to
// must point at the responder this module ships, and it must be UPDATED — not
// only created — or an installation from an earlier release keeps pointing at
// 127.0.0.1:389, where the lookup answers "Connection refused" and nobody can
// sign in.
func TestLaSourceLDAPViseLeRepondant(t *testing.T) {
	// BOTH PATHS ARE CHECKED: the console creates one account, the installation
	// reconciles many, and the source block they render must not drift apart.
	s, err := scriptCompte(compteOP{Login: "okba", Mail: "okba@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	lot, err := scriptComptes([]compteOP{
		{Login: "okba", Mail: "okba@example.com"},
		{Login: "amina", Mail: "amina@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for nom, script := range map[string]string{"one account": s, "many accounts": lot} {
		for _, attendu := range []string{
			`src.host = "` + hoteRespondant() + `"`,
			"src.port = " + strconv.Itoa(portRepondant),
			`src.attr_login = "uid"`,
			"src.tls_mode = :plain_ldap",
			"src.onthefly_register = false",
			"src.save!",
		} {
			if !strings.Contains(script, attendu) {
				t.Errorf("[%s] the auth source script lacks %q:\n%s", nom, attendu, script)
			}
		}
		// THE SOURCE IS FOUND OR INITIALISED, never "found or created": a
		// created row keeps its old values, so the update would silently not
		// happen.
		if !strings.Contains(script, `find_or_initialize_by(name: "Ceffio SSO")`) {
			t.Errorf("[%s] the source must be initialised and then saved, so an existing "+
				"row is corrected", nom)
		}
		if strings.Contains(script, "find_or_create_by!") {
			t.Errorf("[%s] find_or_create_by! would leave an existing source untouched", nom)
		}
		// THE LOOPBACK MAY APPEAR IN THE COMMENT that explains the old defect,
		// never as the value assigned.
		if strings.Contains(script, `src.host = "127.0.0.1"`) {
			t.Errorf("[%s] the source must not point at the loopback address: nothing "+
				"listens there", nom)
		}
	}
}

// TestLeRepondantEstJoignableDepuisLApplication: the responder's own policy must
// admit the application pod on the responder's port. A policy selecting a label
// the pods do not carry, or a port nothing listens on, would make every sign-in
// fail while the manifests still apply cleanly.
func TestLeRepondantEstJoignableDepuisLApplication(t *testing.T) {
	docs := documents(t)
	dep := docs["Deployment/"+nomRepondant]
	labels := champ(t, dep, "spec", "template", "metadata", "labels", "app")
	if labels != nomRepondant {
		t.Errorf("the responder pods carry %v, expected %s", labels, nomRepondant)
	}
	conteneur := champ(t, dep, "spec", "template", "spec", "containers").([]interface{})[0]
	if !strings.HasSuffix(champ(t, conteneur, "image").(string), version.ImageTag()) {
		t.Errorf("the responder must run the Ceffio image itself, got %v", champ(t, conteneur, "image"))
	}
	if champ(t, conteneur, "imagePullPolicy") != "IfNotPresent" {
		t.Errorf("the responder image must be pinned, got pull policy %v", champ(t, conteneur, "imagePullPolicy"))
	}
	// AN EXEC PROBE WOULD NEVER RUN: the image is FROM scratch, so a probe that
	// needs a shell reports the pod unhealthy for the rest of its life.
	if champ(t, conteneur, "readinessProbe", "tcpSocket", "port") != "ldap" {
		t.Error("the readiness probe must be a TCP probe on the named ldap port")
	}
	if _, present := conteneur.(map[string]interface{})["command"]; present {
		t.Error("the responder must be started by the image's own entrypoint")
	}
	np := docs["NetworkPolicy/"+nomRepondant+"-only-from-app"]
	if champ(t, np, "spec", "podSelector", "matchLabels", "app") != nomRepondant {
		t.Error("the responder's policy must select the responder pods")
	}
	regles := champ(t, np, "spec", "ingress").([]interface{})
	if len(regles) != 1 {
		t.Fatalf("exactly one ingress rule expected, got %d", len(regles))
	}
	sources := champ(t, regles[0], "from").([]interface{})
	if len(sources) != 1 || champ(t, sources[0], "podSelector", "matchLabels", "app") != nomApp {
		t.Errorf("the only allowed source must be the application: %v", sources)
	}
	ports := champ(t, regles[0], "ports").([]interface{})
	if len(ports) != 1 || champ(t, ports[0], "port") != float64(portRepondant) {
		t.Errorf("the policy must admit the responder's port: %v", ports)
	}
	// THE SERVICE IS WHAT THE AUTH SOURCE NAMES: it must exist, select the same
	// pods, and expose the port the source dials.
	svc := docs["Service/"+nomRepondant]
	if champ(t, svc, "spec", "selector", "app") != nomRepondant {
		t.Error("the Service must select the responder pods")
	}
	svcPorts := champ(t, svc, "spec", "ports").([]interface{})
	if len(svcPorts) != 1 || champ(t, svcPorts[0], "port") != float64(portRepondant) {
		t.Errorf("the Service must expose port %d: %v", portRepondant, svcPorts)
	}
}

// TestSQLBaseRefuseUnMotDePasseInattendu: only the hexadecimal value the
// module generates may enter the SQL literal.
func TestSQLBaseRefuseUnMotDePasseInattendu(t *testing.T) {
	for _, mdp := range []string{"", "abc'def", "ABCDEF", "a b"} {
		if _, err := sqlBase(mdp); err == nil {
			t.Errorf("sqlBase(%q) accepted a value it must refuse", mdp)
		}
	}
	sql, err := sqlBase("0a1b2c")
	if err != nil {
		t.Fatal(err)
	}
	for _, attendu := range []string{"CREATE ROLE openproject", "PASSWORD '0a1b2c'", "\\gexec"} {
		if !strings.Contains(sql, attendu) {
			t.Errorf("the SQL lacks %q:\n%s", attendu, sql)
		}
	}
}

// TestSecretsHexadecimaux: what genererSecret returns is what sqlBase accepts.
func TestSecretsHexadecimaux(t *testing.T) {
	s, err := genererSecret(24)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 48 {
		t.Errorf("24 random bytes must give 48 hex characters, got %d", len(s))
	}
	if _, err := sqlBase(s); err != nil {
		t.Errorf("a generated password is refused by sqlBase: %v", err)
	}
}

// TestAnalyserComptes reads psql's unaligned output and skips what does not
// parse instead of inventing an account.
func TestAnalyserComptes(t *testing.T) {
	got := analyserComptes("okba\t1\nMerouane\t3\n\ngarbage\nzoheir\tx\n")
	want := map[string]int{"okba": 1, "merouane": 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("analyserComptes = %v, expected %v", got, want)
	}
}

// TestAccountActionInconnue: an action the module never offered is an error.
func TestAccountActionInconnue(t *testing.T) {
	err := (&openprojectModule{}).AccountAction(context.Background(), module.Env{}, module.User{Username: "okba"}, "explode", nil)
	if err == nil {
		t.Error("an unknown action must be refused")
	}
}

// TestEtatLitLeCluster: Unknown without a client (never Absent), Absent with
// nothing deployed, Degraded as soon as ONE of the three deployments is not
// ready, Installed only with all three — the responder included, because it is
// what makes a sign-in possible.
func TestEtatLitLeCluster(t *testing.T) {
	ctx := context.Background()
	if e := lireEtat(ctx, module.Env{}); e.Status != module.Unknown {
		t.Errorf("without a client: %s, expected unknown", e.Status)
	}

	kube := fake.NewSimpleClientset()
	env := module.Env{Kube: kube}
	if e := lireEtat(ctx, env); e.Status != module.Absent {
		t.Errorf("nothing deployed: %s, expected absent", e.Status)
	}

	poser := func(nom string, prets int32) {
		d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: nom, Namespace: nsProjets}}
		d.Status.ReadyReplicas = prets
		if _, err := kube.AppsV1().Deployments(nsProjets).Get(ctx, nom, metav1.GetOptions{}); err == nil {
			_, _ = kube.AppsV1().Deployments(nsProjets).Update(ctx, d, metav1.UpdateOptions{})
			return
		}
		_, _ = kube.AppsV1().Deployments(nsProjets).Create(ctx, d, metav1.CreateOptions{})
	}
	poser(nomProxy, 1)
	poser(nomApp, 0)
	if e := lireEtat(ctx, env); e.Status != module.Degraded || e.Detail == "" {
		t.Errorf("proxy ready, application not: %s %q, expected degraded with a detail", e.Status, e.Detail)
	}
	poser(nomApp, 1)
	if e := lireEtat(ctx, env); e.Status != module.Degraded {
		t.Errorf("application and proxy ready, responder not: %s, expected degraded", e.Status)
	}
	poser(nomRepondant, 1)
	if e := lireEtat(ctx, env); e.Status != module.Installed {
		t.Errorf("all three ready: %s, expected installed", e.Status)
	}
}
