// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// WHY THESE TESTS EXIST.
//
// The vault is the one part of the archive that cannot be rebuilt by replaying
// a manifest: if it is missing or truncated, the restored installation starts
// and its integrations fail. Four claims therefore need proof, not intent:
//
//  1. The tree is dumped ENTIRELY — folders included — and not just the paths
//     the test happened to think of. A hand-written list of paths would go
//     stale the day a module adds one.
//  2. Values keep their JSON TYPE. The vault holds what `ceffio module config`
//     wrote; a number restored as "587" is rejected by a decoder into an int
//     field, and nothing names the backup as the cause.
//  3. The token and the values never travel on a command line (readable in
//     /proc/<pid>/cmdline, in `kubectl get events`, in a shell history).
//  4. An installation WITHOUT a vault is not a failed backup, while a vault
//     that exists and does not answer IS one.
//
// The first live run of this code sent `kv list` (not `bao kv list`) to the
// shell: the pod answered 127 "kv: not found" and the archive lost its vault
// section while the rest looked complete. Claim 1 is asserted against a fake
// that dispatches on the `bao` binary name, so that mistake now fails here.

const jetonEssai = "jeton-de-test"

// fauxCoffre stands in for the vault pod.
//
// arbre is what `bao kv list` and `bao kv get` answer, shaped like the real
// output: a folder is a name ending in "/", and a value may be a string, a
// number or a boolean.
func fauxCoffre(arbre map[string]map[string]any) *kubectlFactice {
	enfants := func(chemin string) []string {
		vus := map[string]bool{}
		var noms []string
		prefixe := chemin + "/"
		for p := range arbre {
			if !strings.HasPrefix(p, prefixe) {
				continue
			}
			reste := strings.TrimPrefix(p, prefixe)
			if i := strings.Index(reste, "/"); i >= 0 {
				reste = reste[:i] + "/"
			}
			if !vus[reste] {
				vus[reste] = true
				noms = append(noms, reste)
			}
		}
		return noms
	}

	return &kubectlFactice{repondre: func(args []string, entree string) (string, error) {
		// The token Secret: the fake returns it base64-encoded, as kubectl does
		// for `.data.token`.
		if len(args) > 1 && args[0] == "get" && args[1] == "secret" {
			return base64.StdEncoding.EncodeToString([]byte(jetonEssai)), nil
		}
		if len(args) > 1 && args[0] == "get" && args[1] == "pods" {
			return "pod/openbao-0", nil
		}
		if len(args) == 0 || args[0] != "exec" {
			return "", fmt.Errorf("unexpected kubectl command: %s", argsEnTexte(args))
		}
		script := args[len(args)-1]

		// The token must arrive on stdin, never in the command line.
		if strings.Contains(argsEnTexte(args), jetonEssai) {
			return "", fmt.Errorf("the token appears in the command line: %s", argsEnTexte(args))
		}
		if !strings.HasPrefix(entree, jetonEssai+"\n") {
			return "", fmt.Errorf("the token was not fed through stdin (stdin starts with %q)", premieres(entree, 20))
		}

		// `bao kv list` : the path is the last quoted argument of the script.
		// The fake dispatches on the exact binary name: a live run of the first
		// draft sent `kv list` to the shell and lost the vault section.
		if i := strings.Index(script, "bao kv list -format=json "); i >= 0 {
			chemin := trimCiter(script[i+len("bao kv list -format=json "):])
			enf := enfants(chemin)
			raw, _ := json.Marshal(enf)
			return string(raw) + "\n", nil
		}
		if i := strings.Index(script, "bao kv get -format=json "); i >= 0 {
			chemin := trimCiter(script[i+len("bao kv get -format=json "):])
			vals, ok := arbre[chemin]
			if !ok {
				return "", fmt.Errorf("unknown path read: %s", chemin)
			}
			doc := map[string]any{"data": map[string]any{"data": vals, "metadata": map[string]any{}}}
			raw, _ := json.Marshal(doc)
			return string(raw) + "\n", nil
		}
		if i := strings.Index(script, "bao kv put "); i >= 0 {
			reste := script[i+len("bao kv put "):]
			chemin := trimCiter(reste)
			// The body is decoded in the pod from stdin, as the real script does:
			// first line the token, second line the base64 JSON body.
			lignes := strings.SplitN(entree, "\n", 3)
			if len(lignes) < 2 {
				return "", fmt.Errorf("no body on stdin for the write")
			}
			corps, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lignes[1]))
			if err != nil {
				return "", fmt.Errorf("the body is not base64: %w", err)
			}
			var entree map[string]json.RawMessage
			if err := json.Unmarshal(corps, &entree); err != nil {
				return "", fmt.Errorf("the body is not a JSON object: %w", err)
			}
			arbre[chemin] = map[string]any{}
			for cle, brut := range entree {
				var v any
				if err := json.Unmarshal(brut, &v); err != nil {
					return "", err
				}
				arbre[chemin][cle] = v
			}
			return "", nil
		}
		return "", fmt.Errorf("unexpected command in the vault pod (no `bao` binary name found): %s", script)
	}}
}

// trimCiter removes the shell quoting added by citerShell.
func trimCiter(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' {
		if i := strings.Index(s[1:], "'"); i >= 0 {
			return s[1 : 1+i]
		}
	}
	// Unquoted: take the first token.
	if i := strings.IndexAny(s, " ;"); i >= 0 {
		return s[:i]
	}
	return s
}

func premieres(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// egalJSON compares two values through their JSON form, so that the test does
// not depend on the concrete Go type json.Unmarshal produced.
func egalJSON(t *testing.T, got, want any, ou string) {
	t.Helper()
	a, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("%s: %v", ou, err)
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("%s: %v", ou, err)
	}
	var av, bv any
	_ = json.Unmarshal(a, &av)
	_ = json.Unmarshal(b, &bv)
	if !reflect.DeepEqual(av, bv) {
		t.Errorf("%s = %s, want %s", ou, a, b)
	}
}

func arbreEssai() map[string]map[string]any {
	return map[string]map[string]any{
		"kv/ceffio/stalwart/admin": {"username": "ceffio", "password": "s3cret"},
		// Types matter: a relay port written by `ceffio module config` is a
		// number and its switch is a boolean.
		"kv/ceffio/mail/relay": {"host": "smtp.example.com", "port": 587, "enabled": true},
		"kv/ceffio/tls/cert":   {"certificate": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"},
	}
}

func TestLeCoffreEstSauvegardeEnEntier(t *testing.T) {
	arbre := arbreEssai()
	f := fauxCoffre(arbre)
	installerFauxKubectl(t, f)

	dst := t.TempDir() + "/vault/kv-ceffio.json"
	if err := dumpCoffre(context.Background(), dst); err != nil {
		t.Fatalf("dumpCoffre: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("the archive file was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: the file carries the platform's credentials", perm)
	}

	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var relu map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &relu); err != nil {
		t.Fatalf("the archive is not valid JSON: %v", err)
	}
	if len(relu) != len(arbre) {
		t.Fatalf("%d entries archived, want %d: %v", len(relu), len(arbre), relu)
	}
	for chemin, vals := range arbre {
		got, ok := relu[chemin]
		if !ok {
			t.Errorf("entry %s is missing from the archive", chemin)
			continue
		}
		for cle, attendu := range vals {
			var v any
			if err := json.Unmarshal(got[cle], &v); err != nil {
				t.Errorf("%s/%s is not valid JSON: %v", chemin, cle, err)
				continue
			}
			egalJSON(t, v, attendu, chemin+"/"+cle)
		}
	}
}

func TestLeCoffreEstRestaureSansExposerLesValeurs(t *testing.T) {
	arbre := map[string]map[string]any{}
	f := fauxCoffre(arbre)
	installerFauxKubectl(t, f)

	dossier := t.TempDir()
	source := dossier + "/kv-ceffio.json"
	contenu := map[string]map[string]any{
		"kv/ceffio/stalwart/admin": {"username": "ceffio", "password": "s3cret"},
		"kv/ceffio/mail/relay":     {"host": "smtp.example.com", "port": 587, "enabled": true},
		"kv/ceffio/tls/cert":       {"certificate": "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"},
	}
	raw, _ := json.Marshal(contenu)
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var errs []string
	if err := restaurerCoffre(context.Background(), source, &errs); err != nil {
		t.Fatalf("restaurerCoffre: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("unexpected failures: %v", errs)
	}

	if len(arbre) != len(contenu) {
		t.Fatalf("%d entries written, want %d: %v", len(arbre), len(contenu), arbre)
	}
	for chemin, vals := range contenu {
		for cle, attendu := range vals {
			got, ok := arbre[chemin][cle]
			if !ok {
				t.Errorf("%s/%s was not written", chemin, cle)
				continue
			}
			egalJSON(t, got, attendu, chemin+"/"+cle)
		}
	}

	// No write may carry the value in its arguments.
	for _, a := range f.appels {
		texte := argsEnTexte(a.Args)
		if strings.Contains(texte, "s3cret") || strings.Contains(texte, "BEGIN CERTIFICATE") {
			t.Errorf("a value appears in a command line: %s", texte)
		}
	}
}

func TestUnCoffreAbsentNEstPasUneErreur(t *testing.T) {
	f := &kubectlFactice{repondre: func(args []string, entree string) (string, error) {
		if len(args) > 0 && args[0] == "get" && len(args) > 1 && args[1] == "secret" {
			return "", fmt.Errorf(`Error from server (NotFound): secrets "openbao-token" not found`)
		}
		return "", fmt.Errorf("unexpected kubectl command: %s", argsEnTexte(args))
	}}
	installerFauxKubectl(t, f)

	err := dumpCoffre(context.Background(), t.TempDir()+"/kv-ceffio.json")
	if !errors.Is(err, errCoffreAbsent) {
		t.Fatalf("err = %v, want errCoffreAbsent: an installation without a vault must not fail its backup", err)
	}
}

func TestUnCoffreDeployeMaisInjoignableEstUneErreur(t *testing.T) {
	f := fauxCoffre(arbreEssai())
	// The token exists (the vault is deployed) but no pod answers.
	f.repondre = func(args []string, entree string) (string, error) {
		if len(args) > 1 && args[0] == "get" && args[1] == "secret" {
			return base64.StdEncoding.EncodeToString([]byte(jetonEssai)), nil
		}
		if len(args) > 1 && args[0] == "get" && args[1] == "pods" {
			return "", nil
		}
		return "", fmt.Errorf("unexpected kubectl command: %s", argsEnTexte(args))
	}
	installerFauxKubectl(t, f)

	err := dumpCoffre(context.Background(), t.TempDir()+"/kv-ceffio.json")
	if err == nil {
		t.Fatalf("dumpCoffre returned nil although the vault is deployed and did not answer")
	}
	if errors.Is(err, errCoffreAbsent) {
		t.Fatalf("err = errCoffreAbsent, want a real error: the operator asked for a vault backup and did not get one")
	}
}

func TestLesSecretsCouvrentLeJetonEtLaCleDeDescellement(t *testing.T) {
	voulus := map[string]string{
		"openbao-token":      "ceffio-vault",
		"openbao-unseal-key": "ceffio-vault",
	}
	trouves := map[string]string{}
	for _, s := range Secrets {
		if _, ok := voulus[s.Name]; ok {
			trouves[s.Name] = s.Namespace
		}
	}
	for nom, ns := range voulus {
		got, ok := trouves[nom]
		if !ok {
			t.Errorf("Secret %s is not in the backup list: a restored vault cannot be read without its token", nom)
			continue
		}
		if got != ns {
			t.Errorf("Secret %s comes from %s, want %s", nom, got, ns)
		}
	}
}

func TestUnCoffreQuiEchoueSurUneEntreeContinueLesAutres(t *testing.T) {
	arbre := map[string]map[string]any{}
	f := fauxCoffre(arbre)
	// Refuse the second entry only.
	reference := f.repondre
	var echecs int
	f.repondre = func(args []string, entree string) (string, error) {
		if len(args) > 0 && args[0] == "exec" && strings.Contains(args[len(args)-1], "bao kv put") {
			echecs++
			if echecs == 2 {
				return "", fmt.Errorf("permission denied")
			}
		}
		return reference(args, entree)
	}
	installerFauxKubectl(t, f)

	source := t.TempDir() + "/kv-ceffio.json"
	contenu := map[string]map[string]any{
		"kv/ceffio/a": {"x": "1"},
		"kv/ceffio/b": {"y": "2"},
		"kv/ceffio/c": {"z": "3"},
	}
	raw, _ := json.Marshal(contenu)
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var errs []string
	if err := restaurerCoffre(context.Background(), source, &errs); err != nil {
		t.Fatalf("restaurerCoffre: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("failures recorded = %v, want exactly one (and the other entries still written)", errs)
	}
	if _, ok := arbre["kv/ceffio/a"]; !ok {
		t.Errorf("the entry before the failure was not written")
	}
	if _, ok := arbre["kv/ceffio/c"]; !ok {
		t.Errorf("the entry after the failure was not written: one refusal must not stop the rest")
	}
}
