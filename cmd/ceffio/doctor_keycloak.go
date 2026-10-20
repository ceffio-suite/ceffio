// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/stack"
)

// LireKeycloakArgs returns the keycloak container's command line, as the cluster
// runs it. An empty result with no error means the deployment does not exist —
// which is not this check's problem: a missing identity layer is reported by the
// layer diagnostics, and saying it twice would bury the first message.
//
// IT IS A VARIABLE SO A TEST CAN ANSWER INSTEAD OF CALLING kubectl: a doctor check
// that can only be exercised against a live cluster is a check nobody runs.
var LireKeycloakArgs = func(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "deploy", "keycloak",
		"-n", "ceffio-identity",
		"-o", "jsonpath={range .spec.template.spec.containers[*]} {.name}{\"\\n\"}{.args}{\"\\n\"}{end}")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		// A missing deployment is not an error to report here.
		if strings.Contains(err.Error(), "NotFound") {
			return "", nil
		}
		return "", err
	}
	return string(out), nil
}

// VerifierKeycloakProduction is the doctor check for lot K1.
//
// WHY IT IS AN ERROR AND NOT A WARNING: `start-dev` is not a degraded setting, it
// is a mode Keycloak's own documentation forbids in production. It disables the
// caches — so an installed theme is silently not served — and loosens protections
// meant to stay on. A platform can run that way for months without a visible
// symptom, which is exactly why a doctor should say it plainly rather than let it
// pass as "unusual".
//
// IT READS THE RUNNING DEPLOYMENT, not the source: an installation made before the
// switch keeps its manifest until `ceffio install` reapplies it, and upgrading the
// binary alone does not change what runs.
func VerifierKeycloakProduction(ctx context.Context) []stack.Finding {
	args, err := LireKeycloakArgs(ctx)
	if err != nil {
		return []stack.Finding{{
			Severity: "warning",
			Scope:    "identity",
			Title:    "Cannot read the Keycloak deployment",
			Detail:   err.Error(),
			Action:   "Check that the kubeconfig designates the right cluster and that ceffio-identity exists.",
		}}
	}
	// Nothing to judge: the identity layer is not deployed.
	if strings.TrimSpace(args) == "" {
		return nil
	}

	// THE WORD, NOT A SUBSTRING. A manifest carries comments; a comment saying
	// "no longer start-dev" would be read as a fault by a substring check, and a
	// check that cries wolf is turned off.
	if !contientMotCle(args, "start-dev") {
		return nil
	}

	return []stack.Finding{{
		Severity: "error",
		Scope:    "identity",
		Title:    "Keycloak runs in development mode",
		Detail: "The keycloak container is started with \"kc.sh start-dev\". Keycloak's " +
			"documentation forbids this mode in production: it disables the caches — " +
			"including the theme cache, so an installed login page is silently not " +
			"served — and loosens protections meant to stay on.",
		Action: "Reapply the manifest so the deployment switches to production mode: " +
			"`ceffio install`. The realm lives in PostgreSQL, so no account, client or " +
			"setting is lost.",
	}}
}

// contientMotCle reports whether a command line RUNS the given word.
//
// THREE THINGS HAVE TO BE RIGHT, and each was wrong in a first version:
//
//  1. THE SEPARATORS. kubectl's jsonpath renders args as ["a","b"], whose lines
//     end inside a quoted string; splitting on \n alone leaves `start-dev"]` glued
//     to its neighbour, and the word never matches.
//
//  2. THE COMMENTS. A manifest carries the prose that explains it, and this very
//     codebase has a comment saying the platform no longer uses start-dev. Counting
//     that as the fault it describes is the worst failure mode: the true fault is
//     hidden and a false one is reported.
//
//  3. THE WORD ITSELF. `start-dev-backup`, `--no-start-dev` and a path segment
//     like /opt/start-dev/kc.sh are not the argument. Only a token that IS the
//     word, or a path whose LAST segment is the word, counts.
func contientMotCle(args, mot string) bool {
	// kubectl's jsonpath escapes the newlines INSIDE a quoted argument, so the
	// shell lines of a multi-line command arrive as the two characters \ and n.
	// Treating them as line breaks is what lets the comment rule apply to each
	// line of the script, not to the whole blob.
	args = strings.ReplaceAll(args, `\n`, "\n")
	for _, ligne := range strings.Split(args, "\n") {
		// A shell line may carry a trailing comment: `kc.sh start # not start-dev`.
		// Cutting at a # that opens a word keeps the explanation out of the answer.
		if i := commentaireHorsGuillemets(ligne); i >= 0 {
			ligne = ligne[:i]
		}
		for _, jeton := range jetons(ligne) {
			// A QUOTED ARGUMENT HOLDS A WHOLE COMMAND LINE: kubectl returns
			// ["/bin/bash","-c","exec kc.sh start-dev"], so the third token is the
			// shell line itself. The word is inside it, so the token is split on
			// whitespace before the comparison — otherwise the only shape a real
			// deployment produces would be the one this function missed.
			for _, part := range strings.Fields(jeton) {
				// A SHELL LINE CARRIES ITS OWN COMMENT: 'exec kc.sh start # no
				// longer start-dev' is one token, and everything after the # is
				// prose. Cutting each word at a leading # is what stops the
				// explanation from being read as the fault.
				if strings.HasPrefix(part, "#") {
					break
				}
				if part == mot || strings.HasSuffix(part, "/"+mot) {
					return true
				}
			}
		}
	}
	return false
}

// jetons splits a line into shell-ish tokens: quotes group, and the punctuation
// kubectl's jsonpath emits separates.
func jetons(ligne string) []string {
	var out []string
	var courant strings.Builder
	var quote rune
	flush := func() {
		if courant.Len() > 0 {
			out = append(out, courant.String())
			courant.Reset()
		}
	}
	for _, r := range ligne {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			courant.WriteRune(r)
		case r == '"' || r == '\'':
			// A QUOTE OPENS A GROUP AND ALSO SEPARATES: in ["a","b"] the comma
			// sits BETWEEN quotes, so the token closes at the opening quote of
			// the next one. Splitting before the quote is what makes ["a","b"]
			// two tokens instead of one.
			flush()
			quote = r
		case r == '[' || r == ']' || r == '{' || r == '}' || r == ',' ||
			r == ' ' || r == '\t' || r == ';' || r == '|' || r == '(' || r == ')':
			flush()
		default:
			courant.WriteRune(r)
		}
	}
	flush()
	return out
}

// commentaireHorsGuillemets returns the index where a shell comment starts, or -1.
//
// A # opens a comment only at the start of a word: `kc.sh start # why` is a
// comment, while `foo#bar` is a word.
func commentaireHorsGuillemets(ligne string) int {
	var quote rune
	for i, r := range ligne {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			if i == 0 || ligne[i-1] == ' ' || ligne[i-1] == '\t' {
				return i
			}
		}
	}
	return -1
}
