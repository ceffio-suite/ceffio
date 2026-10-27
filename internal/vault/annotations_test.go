// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"sigs.k8s.io/yaml"
)

// annotationsEnMap turns the produced YAML block into its annotation map.
//
// The block is written at the indentation the manifest needs, and YAML refuses a
// uniformly indented root only when it is mixed with other text: dedenting here
// keeps the test reading the SAME bytes the manifest embeds.
func annotationsEnMap(t *testing.T, bloc string, indent int) map[string]string {
	t.Helper()
	var sb strings.Builder
	for _, l := range strings.Split(strings.TrimSuffix(bloc, "\n"), "\n") {
		if !strings.HasPrefix(l, strings.Repeat(" ", indent)) {
			t.Fatalf("line %q is not indented by %d spaces", l, indent)
		}
		sb.WriteString(strings.TrimPrefix(l, strings.Repeat(" ", indent)) + "\n")
	}
	var m map[string]string
	if err := yaml.Unmarshal([]byte(sb.String()), &m); err != nil {
		t.Fatalf("the annotations are not valid YAML: %v\n%s", err, sb.String())
	}
	return m
}

// TestAnnotationsAgentFichiers covers the contract the multi-file helper owes a
// workload: one annotation triple per file, and nothing that writes the shell
// form by accident.
func TestAnnotationsAgentFichiers(t *testing.T) {
	bloc, err := AnnotationsAgentFichiers(8, "longhorn-ui", []FichierInjecte{
		{Nom: "client-secret", Chemin: `kv/data/ceffio/longhorn-ui/oauth2-proxy`,
			Gabarit: GabaritValeur("kv/data/ceffio/longhorn-ui/oauth2-proxy", "client-secret"),
			Perms:   "0400"},
		{Nom: "cookie-secret", Chemin: `kv/data/ceffio/longhorn-ui/oauth2-proxy`,
			Gabarit: GabaritValeur("kv/data/ceffio/longhorn-ui/oauth2-proxy", "cookie_secret"),
			Perms:   "0400"},
	})
	if err != nil {
		t.Fatalf("the helper refused a valid declaration: %v", err)
	}

	m := annotationsEnMap(t, bloc, 8)
	if m["vault.hashicorp.com/agent-inject"] != "true" {
		t.Errorf("agent-inject = %q", m["vault.hashicorp.com/agent-inject"])
	}
	// THE ROLE IS THE MODULE'S ID: that is the name the vault layer creates the
	// Kubernetes role under. Any other value asks for a role that does not exist
	// and the pod hangs in Init with `invalid role name`.
	if m["vault.hashicorp.com/role"] != "longhorn-ui" {
		t.Errorf("role = %q, expected the module ID", m["vault.hashicorp.com/role"])
	}
	if m["vault.hashicorp.com/secret-volume-path"] != "/secrets" {
		t.Errorf("secret-volume-path = %q", m["vault.hashicorp.com/secret-volume-path"])
	}

	for _, nom := range []string{"client-secret", "cookie-secret"} {
		if got := m["vault.hashicorp.com/agent-inject-secret-"+nom]; got !=
			"kv/data/ceffio/longhorn-ui/oauth2-proxy" {
			t.Errorf("agent-inject-secret-%s = %q", nom, got)
		}
		// 0400 IS THE DECISION: the file holds a credential, and nothing but the
		// process that needs it has any reason to read it.
		if got := m["vault.hashicorp.com/agent-inject-perms-"+nom]; got != "0400" {
			t.Errorf("agent-inject-perms-%s = %q, expected 0400", nom, got)
		}
		if got := m["vault.hashicorp.com/error-on-missing-key-"+nom]; got != "true" {
			t.Errorf("error-on-missing-key-%s = %q: a missing key must stop the pod", nom, got)
		}
	}

	// THE ONE-FILE FORM MUST NOT LEAK IN: `/secrets/env` would be a shell file
	// this workload never sources, and its presence would mean the helper falls
	// back to the old behaviour.
	if _, ok := m["vault.hashicorp.com/agent-inject-secret-env"]; ok {
		t.Error("the helper declared /secrets/env: this workload reads individual files")
	}
}

// TestAnnotationsAgentFichiersRefuse covers the declarations that would produce
// a file the program cannot use — each one silently, which is why they are
// refused at the source.
func TestAnnotationsAgentFichiersRefuse(t *testing.T) {
	valide := FichierInjecte{Nom: "a", Chemin: "kv/data/ceffio/x/y",
		Gabarit: "{{- 1 -}}", Perms: "0400"}

	cas := map[string][]FichierInjecte{
		"no file":         nil,
		"name is a path":  {{Nom: "sous/dossier", Chemin: valide.Chemin, Gabarit: valide.Gabarit, Perms: valide.Perms}},
		"no vault path":   {{Nom: "a", Gabarit: valide.Gabarit, Perms: valide.Perms}},
		"empty template":  {{Nom: "a", Chemin: valide.Chemin, Perms: valide.Perms}},
		"mode sans zéro":  {{Nom: "a", Chemin: valide.Chemin, Gabarit: valide.Gabarit, Perms: "400"}},
		"mode non octal":  {{Nom: "a", Chemin: valide.Chemin, Gabarit: valide.Gabarit, Perms: "04z0"}},
		"same name twice": {valide, valide},
	}
	for nom, fichiers := range cas {
		if _, err := AnnotationsAgentFichiers(8, "x", fichiers); err == nil {
			t.Errorf("%s: accepted, expected a refusal", nom)
		}
	}
}

// executerGabarit runs a template the way the agent does, with a fake `secret`
// function, and returns the bytes that would land in the file.
//
// The template comes from the YAML block, not from the Go constant: what is
// tested is the bytes the injector receives, trailing newline of the block
// scalar included.
func executerGabarit(t *testing.T, gabarit, chemin string) string {
	t.Helper()
	// THE VALUE CARRIES NO SPACE AND NO NEWLINE, so the only newline that can
	// appear in the output comes from the template itself.
	donnees := map[string]any{
		"Data": map[string]any{"data": map[string]any{
			"client-secret": "cs-valeur",
			"cookie_secret": "ck-valeur",
		}},
	}
	funcs := template.FuncMap{
		"secret": func(p string) map[string]any {
			if p != chemin {
				t.Fatalf("the template reads %q, expected %q", p, chemin)
			}
			return donnees
		},
	}
	tpl, err := template.New("fichier").Funcs(funcs).Parse(gabarit)
	if err != nil {
		t.Fatalf("the template does not parse: %v\n%s", err, gabarit)
	}
	var b bytes.Buffer
	if err := tpl.Execute(&b, nil); err != nil {
		t.Fatalf("the template does not execute: %v", err)
	}
	return b.String()
}

// TestGabaritValeurNeFinitPasParUnSautDeLigne is THE test of this lot.
//
// oauth2-proxy reads --client-secret-file and --cookie-secret-file with
// os.ReadFile and sends the bytes as they are. A trailing newline therefore
// makes the secret differ from the one Keycloak issued, and the only symptom is
// a refused sign-in — after a login page that worked. The template's trims are
// what prevent it, and they are checked here on the RENDERED bytes.
func TestGabaritValeurNeFinitPasParUnSautDeLigne(t *testing.T) {
	const chemin = "kv/data/ceffio/longhorn-ui/oauth2-proxy"

	for _, champ := range []string{"client-secret", "cookie_secret"} {
		bloc, err := AnnotationsAgentFichiers(8, "longhorn-ui", []FichierInjecte{{
			Nom: "secret", Chemin: chemin,
			Gabarit: GabaritValeur(chemin, champ), Perms: "0400",
		}})
		if err != nil {
			t.Fatalf("%s: %v", champ, err)
		}
		m := annotationsEnMap(t, bloc, 8)
		gabarit := m["vault.hashicorp.com/agent-inject-template-secret"]
		if gabarit == "" {
			t.Fatalf("%s: no template annotation", champ)
		}
		// THE BLOCK SCALAR'S NEWLINE MUST BE THERE, otherwise this test would
		// pass on a template that never faced the case.
		if !strings.HasSuffix(gabarit, "\n") {
			t.Fatalf("%s: the decoded template does not end with the block scalar's newline: %q",
				champ, gabarit)
		}

		rendu := executerGabarit(t, gabarit, chemin)
		if strings.HasSuffix(rendu, "\n") {
			t.Errorf("%s: the rendered file ends with a newline (%q): oauth2-proxy does not "+
				"trim it, so the secret would be one byte longer than the one issued",
				champ, rendu)
		}
		attendu := map[string]string{
			"client-secret": "cs-valeur",
			"cookie_secret": "ck-valeur",
		}[champ]
		if rendu != attendu {
			t.Errorf("%s: the file holds %q, expected %q", champ, rendu, attendu)
		}
	}
}

// TestGabaritValeurGardeLeTiretDuChamp: a field whose name has a dash cannot be
// written ".Data.data.client-secret" — the dash is an operator — and the failure
// the agent reports speaks of an invalid template, never of the dash.
func TestGabaritValeurGardeLeTiretDuChamp(t *testing.T) {
	rendu := executerGabarit(t, GabaritValeur("kv/data/ceffio/x/y", "client-secret")+"\n",
		"kv/data/ceffio/x/y")
	if rendu != "cs-valeur" {
		t.Errorf("rendered %q, expected the value of the dashed field", rendu)
	}
}
