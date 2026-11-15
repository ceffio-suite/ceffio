// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file backs up the OpenBao vault — the KEY-VALUE tree, not the vault's
// own infrastructure.
//
// WHY IT EXISTS. Until 0.11.0, `ceffio backup` did not cover the vault at all,
// and docs/secrets.md said it did: the sentence "ceffio backup includes the
// vault's data" was false. The vault is where the platform keeps the things it
// cannot regenerate — OIDC client secrets, the relay's SMTP credentials, the
// DKIM keys, the Nextcloud application password. Restoring workloads without
// this tree gives an installation whose pods all start and whose integrations
// all fail, with no error naming the vault.
//
// WHAT IS NOT COVERED, AND WHY: the vault's RECOVERY keys. A backup carrying
// both the data and the keys that open it is not a backup, it is a copy of the
// risk (docs/secrets.md). A full rebuild of a lost vault therefore remains a
// documented manual procedure — `operator init` with the recovery keys — not
// something this code pretends to automate.

const (
	nsCoffre          = "ceffio-vault"
	etiquetteCoffre   = "app=openbao"
	secretJetonCoffre = "openbao-token"
	cleJetonCoffre    = "token"
	cheminCoffre      = "kv/ceffio"
	adresseCoffre     = "http://127.0.0.1:8200"
)

// errCoffreAbsent says "there is no vault on this installation", which is a
// normal state (an installation may not have deployed it) and must not fail a
// backup. It is distinguished from "the vault is deployed but unreachable",
// which IS an error: the operator asked for a vault backup and did not get one.
var errCoffreAbsent = errors.New("vault not deployed")

// jetonCoffre reads the application token from its Secret.
//
// The token is read from the Secret rather than from the pod's environment
// because the environment does not carry it: measured on the demo host, `bao
// kv list` with only BAO_ADDR answers 403 — the pod's own process has no
// VAULT_TOKEN, and the token used by `ceffio vault` lives in this Secret.
func jetonCoffre(ctx context.Context) (string, error) {
	out, err := sortieKubectl(ctx, "get", "secret", secretJetonCoffre, "-n", nsCoffre,
		"-o", "jsonpath={.data."+cleJetonCoffre+"}")
	if err != nil {
		return "", errCoffreAbsent
	}
	brut := strings.TrimSpace(out)
	if brut == "" {
		return "", errCoffreAbsent
	}
	jeton, err := base64.StdEncoding.DecodeString(brut)
	if err != nil || len(jeton) == 0 {
		return "", errCoffreAbsent
	}
	return string(jeton), nil
}

// podPour returns the name of the first pod matching label, or "".
func podPour(ctx context.Context, ns, label string) string {
	out, err := sortieKubectl(ctx, "get", "pods", "-n", ns, "-l", label, "-o", "name")
	if err != nil {
		return ""
	}
	champs := strings.Fields(strings.TrimSpace(out))
	if len(champs) == 0 {
		return ""
	}
	return strings.TrimPrefix(champs[0], "pod/")
}

// baoDansCoffre runs a `bao` command inside the vault pod, with the token fed
// through STANDARD INPUT.
//
// WHY STDIN RATHER THAN AN ARGUMENT: the command line of any process is
// readable by every account of the pod (/proc/<pid>/cmdline), and the token
// appears there for the lifetime of the command. `IFS= read -r T` consumes the
// first line of stdin into a shell variable, which is not exposed that way; the
// rest of stdin stays available to the command itself.
func baoDansCoffre(ctx context.Context, pod, jeton, commande string, entree io.Reader, sortie io.Writer) error {
	script := "IFS= read -r T; export BAO_ADDR=" + adresseCoffre + "; export BAO_TOKEN=\"$T\"; " + commande
	if entree == nil {
		entree = strings.NewReader("")
	}
	stdin := io.MultiReader(strings.NewReader(jeton+"\n"), entree)
	return executerKubectl(ctx, stdin, sortie, "exec", "-i", "-n", nsCoffre, pod, "--", "sh", "-c", script)
}

// dumpCoffre writes the whole kv/ceffio tree, values included, as one JSON
// file: { "<path>": { "<key>": <value as JSON> } }.
//
// Values keep their JSON TYPE rather than being flattened to strings: the vault
// stores what `ceffio module config` wrote, and a port is a number, a switch is
// a boolean. Writing them back as their JSON text (`bao kv put key=…`) would
// turn 587 into "587" and true into "true" — readable by a human, rejected by a
// decoder into a struct with an int or a bool field.
//
// The tree is walked by listing and re-listing folders, because the vault has
// no "export everything" call: `bao kv list` returns names, and a name ending in
// "/" is a folder.
func dumpCoffre(ctx context.Context, dst string) error {
	jeton, err := jetonCoffre(ctx)
	if err != nil {
		return err
	}
	pod := podPour(ctx, nsCoffre, etiquetteCoffre)
	if pod == "" {
		return fmt.Errorf("no pod %s in %s: the vault is deployed but not running, its entries were not backed up", etiquetteCoffre, nsCoffre)
	}

	arbre := map[string]map[string]json.RawMessage{}
	var parcourir func(chemin string) error
	parcourir = func(chemin string) error {
		var b bytes.Buffer
		if err := baoDansCoffre(ctx, pod, jeton,
			"bao kv list -format=json "+citerShell(chemin), nil, &b); err != nil {
			return fmt.Errorf("listing %s: %w", chemin, err)
		}
		var entrees []string
		if err := json.Unmarshal(b.Bytes(), &entrees); err != nil {
			return fmt.Errorf("listing %s: unexpected answer %.200s", chemin, b.String())
		}
		sort.Strings(entrees)
		for _, nom := range entrees {
			complet := strings.TrimSuffix(chemin+"/"+strings.TrimSuffix(nom, "/"), "/")
			if strings.HasSuffix(nom, "/") {
				if err := parcourir(complet); err != nil {
					return err
				}
				continue
			}
			doc, err := lireEntreeCoffre(ctx, pod, jeton, complet)
			if err != nil {
				return err
			}
			arbre[complet] = doc
		}
		return nil
	}
	if err := parcourir(cheminCoffre); err != nil {
		return err
	}
	if len(arbre) == 0 {
		return fmt.Errorf("the vault tree %s is empty: nothing was backed up", cheminCoffre)
	}

	raw, err := json.MarshalIndent(arbre, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	// 0600 like the secrets file: this is the same kind of content.
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// lireEntreeCoffre reads one entry and returns its values AS THEY ARE STORED,
// JSON types included (see dumpCoffre for why the type matters).
func lireEntreeCoffre(ctx context.Context, pod, jeton, chemin string) (map[string]json.RawMessage, error) {
	var b bytes.Buffer
	if err := baoDansCoffre(ctx, pod, jeton,
		"bao kv get -format=json "+citerShell(chemin), nil, &b); err != nil {
		return nil, fmt.Errorf("reading %s: %w", chemin, err)
	}
	var doc struct {
		Data struct {
			Data map[string]json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("reading %s: unexpected answer %.200s", chemin, b.String())
	}
	valeurs := make(map[string]json.RawMessage, len(doc.Data.Data))
	for cle, brut := range doc.Data.Data {
		valeurs[cle] = brut
	}
	return valeurs, nil
}

// restaurerCoffre re-writes every entry of the archive into the vault.
//
// One `bao kv put <path> @file` per ENTRY, with the entry's JSON body — that is
// what preserves the types (see dumpCoffre) and what makes each entry atomic.
//
// Per-entry failures are collected in errs and do NOT stop the rest: a vault
// entry that cannot be written (a deleted engine, a policy narrower than the
// archive expects) must not prevent the other entries from coming back.
func restaurerCoffre(ctx context.Context, chemin string, errs *[]string) error {
	raw, err := os.ReadFile(chemin)
	if err != nil {
		return err
	}
	var arbre map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arbre); err != nil {
		return fmt.Errorf("vault archive unreadable: %w", err)
	}
	if len(arbre) == 0 {
		return nil
	}
	jeton, err := jetonCoffre(ctx)
	if err != nil {
		return fmt.Errorf("the vault entries were NOT restored: %w", err)
	}
	pod := podPour(ctx, nsCoffre, etiquetteCoffre)
	if pod == "" {
		return fmt.Errorf("the vault entries were NOT restored: no pod %s in %s",
			etiquetteCoffre, nsCoffre)
	}

	chemins := make([]string, 0, len(arbre))
	for c := range arbre {
		chemins = append(chemins, c)
	}
	sort.Strings(chemins)
	for _, c := range chemins {
		if err := poserEntreeCoffre(ctx, pod, jeton, c, arbre[c]); err != nil {
			*errs = append(*errs, fmt.Sprintf("vault %s : %v", c, err))
		}
	}
	return nil
}

// poserEntreeCoffre writes ONE whole entry.
//
// The body never goes through the command line: it is base64-encoded, fed to
// the pod's standard input, decoded into a file of the pod's /tmp, and read by
// `bao kv put <path> @<file>`. A password or a private key therefore does not
// appear in /proc/<pid>/cmdline — the command line of a pod's process is
// readable by every account in it — and multi-line values (PEM certificates
// live under kv/ceffio/tls) survive intact.
func poserEntreeCoffre(ctx context.Context, pod, jeton, chemin string, entree map[string]json.RawMessage) error {
	corps, err := json.Marshal(entree)
	if err != nil {
		return err
	}
	encode := base64.StdEncoding.EncodeToString(corps)
	script := "IFS= read -r T; export BAO_ADDR=" + adresseCoffre + "; export BAO_TOKEN=\"$T\"; " +
		"base64 -d > /tmp/ceffio-entree.json; " +
		"bao kv put " + citerShell(chemin) + " @/tmp/ceffio-entree.json; rc=$?; " +
		"rm -f /tmp/ceffio-entree.json; exit $rc"
	stdin := io.MultiReader(strings.NewReader(jeton+"\n"), strings.NewReader(encode+"\n"))
	return executerKubectl(ctx, stdin, nil, "exec", "-i", "-n", nsCoffre, pod, "--", "sh", "-c", script)
}
