// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package vault

import (
	"fmt"
	"strings"
)

// This file produces the annotations that make OpenBao's injector place the
// secrets.
//
// WHY THE INJECTOR RATHER THAN A HAND-WRITTEN INIT-CONTAINER. A home-made
// init-container forces you to compose the agent's HCL yourself, the ConfigMap
// carrying it, the shared volume, its mounts, and to set the user and group —
// without which the rendered file is unreadable by the application container,
// and the pod loops on "Permission denied". The injector does all of that from
// these few annotations: it places the agent with the right user/group pair,
// and keeps the secrets in an IN-MEMORY volume (medium: Memory), never on
// disk. Measured on two workloads: forty manifest lines replaced by nine
// annotations.
//
// WHAT REMAINS OURS, and that is all:
//   - the ServiceAccount — it is what the vault role designates to
//     authenticate;
//   - the policy and the role, placed once by the "vault" command;
//   - the line that loads the rendered file at service startup:
//     "set -a; . /secrets/env; set +a" — unavoidable, neither Stalwart nor
//     ONLYOFFICE read a file by themselves.

// AnnotationsAgent renders the YAML block to insert into the pod template's
// annotations. indent is the indentation, in spaces, of the produced lines: it
// must match that of the pod's other annotations.
func AnnotationsAgent(indent int, role, chemin, gabarit string) string {
	marge := strings.Repeat(" ", indent)
	interne := strings.Repeat(" ", indent+2)

	var b strings.Builder
	for _, l := range [][2]string{
		{"vault.hashicorp.com/agent-inject", "true"},
		{"vault.hashicorp.com/role", role},
		// INIT-CONTAINER MODE ONLY: the agent renders the secrets then stops,
		// and no sidecar keeps running. That is the pattern matching these
		// services, which read their variables once at startup.
		{"vault.hashicorp.com/agent-pre-populate-only", "true"},
		{"vault.hashicorp.com/secret-volume-path", "/secrets"},
		{"vault.hashicorp.com/agent-inject-secret-env", chemin},
		{"vault.hashicorp.com/agent-inject-perms-env", "0644"},
		// LOUD FAILURE: a missing key makes the render fail instead of writing
		// an empty value. An empty secret is worse than a pod that does not
		// start.
		{"vault.hashicorp.com/error-on-missing-key-env", "true"},
	} {
		fmt.Fprintf(&b, "%s%s: %q\n", marge, l[0], l[1])
	}

	// The template goes out as a literal block: it contains newlines.
	fmt.Fprintf(&b, "%svault.hashicorp.com/agent-inject-template-env: |\n", marge)
	for _, l := range strings.Split(strings.TrimRight(gabarit, "\n"), "\n") {
		fmt.Fprintf(&b, "%s%s\n", interne, l)
	}
	return b.String()
}

// ChampCoffre renders access to one field of a versioned KV entry.
//
// THE DASH MATTERS: ".Data.data.hash-key" is NOT a valid expression in Go
// template syntax — the dash is an operator there —, and the error the agent
// renders speaks of an "invalid template" without ever mentioning the dash.
// Going through "index" settles the case, and the dot too, as a precaution.
func ChampCoffre(champ string) string {
	if strings.ContainsAny(champ, "-.") {
		return fmt.Sprintf("{{ index .Data.data %q }}", champ)
	}
	return "{{ .Data.data." + champ + " }}"
}

// Source designates one vault entry and the variables to draw from it.
type Source struct {
	Chemin string
	Paires [][2]string
}

// GabaritMulti composes a template that reads SEVERAL vault entries and writes
// a single file.
//
// WHY SEVERAL ENTRIES IN ONE FILE: a service often draws its values from
// distinct accounts — Nextcloud takes its database credentials from
// "nextcloud/db", its administration account from "nextcloud/admin", and its
// sending relay from yet another place. The container does not have to know
// about that split: it loads ONE file, and the injector composes it.
func GabaritMulti(sources []Source) string {
	var b strings.Builder
	for _, s := range sources {
		b.WriteString("{{ with secret \"" + s.Chemin + "\" }}\n")
		for _, p := range s.Paires {
			b.WriteString("export " + p[0] + "='" + p[1] + "'\n")
		}
		b.WriteString("{{ end }}\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// GabaritExports renders a template that writes shell assignments, loadable
// with "set -a; . /secrets/env; set +a" — the documented way to serve an
// application that expects nothing but environment variables.
//
// Each pair is {shell variable name, value}. The value is most often a
// ChampCoffre, but it can be composed — "admin:" followed by the password, for
// example, because Stalwart expects "user:password" in ONE SINGLE string.
func GabaritExports(chemin string, paires ...[2]string) string {
	return GabaritMulti([]Source{{Chemin: chemin, Paires: paires}})
}

// AnnotationsAgentSecret renders the annotations for a workload that needs the
// vault entry AS A KUBERNETES SECRET rather than as a file.
//
// WHY A SECOND MODE EXISTS AT ALL, when every other component of the suite uses
// the file: some software reads its credentials from the Kubernetes API, by
// naming a Secret, and cannot be told about a file — the DNS-01 solver is the
// case that forced this. It loads EVERY key of the named Secret and marshals
// them to its provider library. A pod-local file full of shell exports would
// give it nothing usable, and the failure would appear as an authentication
// error with no mention of the shape mismatch.
//
// THE INJECTOR'S ROLE IS THE SAME. What changes is where it puts the result:
// `agent-inject-secret-<name>` with a name that is NOT `env` creates a Secret
// named <name> in the pod's namespace, instead of a file under
// `secret-volume-path`. The workload side (`secretRef`) then reads it through
// the API, with the Role granting `get` on secrets in that one namespace.
//
// THE GABARIT MUST WRITE `key: value` PAIRS, NOT `export VAR=…`: the injector
// serialises the rendered document into the Secret's data, key by key. An
// export line would produce a single key named `export CF_API_TOKEN='…'`.
func AnnotationsAgentSecret(indent int, role, chemin, gabarit string) string {
	// The Secret's name is derived from the vault path's last segment. It must
	// match what the ClusterIssuer passes in `config.secretRef.name` — the two
	// are one identity written in two places, and a mismatch means the solver
	// reads a Secret that does not exist while the injector fills another.
	n, _ := NomSecretDepuisChemin(chemin)
	return AnnotationsAgentNamed(indent, role, n, chemin, gabarit)
}

// NomSecretDepuisChemin returns the Secret name the injector creates for a
// vault path, plus whether it could be derived at all.
//
// "kv/data/ceffio/tls/dns-provider" → "dns-provider". The rule is stated once,
// here, because both the injector annotations and the ClusterIssuer have to
// agree on it.
func NomSecretDepuisChemin(chemin string) (string, bool) {
	p := strings.Trim(chemin, "/")
	if p == "" {
		return "", false
	}
	segments := strings.Split(p, "/")
	dernier := segments[len(segments)-1]
	if dernier == "" {
		return "", false
	}
	// A vault path is not a DNS name: underscores and dots would be refused by
	// Kubernetes. We normalise rather than reject — the name only has to be
	// stable and identical on both sides.
	remplace := strings.NewReplacer("_", "-", ".", "-")
	return remplace.Replace(dernier), true
}

// AnnotationsAgentNamed renders the annotations for an explicitly named Secret.
//
// Exists so the Secret name is decided by the CALLER when the default derivation
// does not fit — and so a rename is a one-line change rather than a silent
// divergence between the injector and the workload.
func AnnotationsAgentNamed(indent int, role, nomSecret, chemin, gabarit string) string {
	marge := strings.Repeat(" ", indent)
	interne := strings.Repeat(" ", indent+2)

	cleInject := "agent-inject-secret-" + nomSecret

	var b strings.Builder
	for _, l := range [][2]string{
		{"vault.hashicorp.com/agent-inject", "true"},
		{"vault.hashicorp.com/role", role},
		// INIT-CONTAINER MODE ONLY, like the file mode: the agent renders then
		// stops. Nothing has to keep running for a Secret that Kubernetes
		// stores.
		{"vault.hashicorp.com/agent-pre-populate-only", "true"},
		{"vault.hashicorp.com/" + cleInject, chemin},
		// LOUD FAILURE, same reasoning as the file mode: a render that quietly
		// produces an empty credential is worse than a pod that refuses to
		// start.
		{"vault.hashicorp.com/error-on-missing-key-" + nomSecret, "true"},
	} {
		fmt.Fprintf(&b, "%s%s: %q\n", marge, l[0], l[1])
	}

	fmt.Fprintf(&b, "%svault.hashicorp.com/agent-inject-template-%s: |\n", marge, nomSecret)
	for _, l := range strings.Split(strings.TrimRight(gabarit, "\n"), "\n") {
		fmt.Fprintf(&b, "%s%s\n", interne, l)
	}
	return b.String()
}

// GabaritSecret rend un gabarit qui écrit des paires "clé: valeur" pour un
// Secret Kubernetes, à partir d'une entrée du coffre.
//
// LA CLÉ DU SECRET ET LE CHAMP DU COFFRE SONT DEUX NOMS DIFFÉRENTS, et c'est
// tout l'intérêt de cette variante : cert-manager impose ses propres noms de
// clés (`api-token`, avec un tiret), tandis que le champ stocké dans le coffre
// est celui que l'opérateur a écrit (`api_token`, avec un souligné, le nom que
// libdns utilise). Écrire le même nom des deux côtés ferait demander au coffre
// un champ que personne n'a déposé — le rendu échouerait en nommant un champ
// que l'opérateur n'a jamais saisi, après une sauvegarde qui semblait réussie.
//
// paires est une liste de {clé du Secret, champ du coffre}.
func GabaritSecretPaires(chemin string, paires [][2]string) string {
	var b strings.Builder
	b.WriteString("{{ with secret \"" + chemin + "\" }}\n")
	for _, p := range paires {
		b.WriteString(p[0] + ": '" + ChampCoffre(p[1]) + "'\n")
	}
	b.WriteString("{{ end }}\n")
	return strings.TrimRight(b.String(), "\n")
}

// GabaritSecret écrit un Secret dont les clés portent le MÊME nom que les champs
// du coffre — le cas du solver webhook, qui marshale le Secret entier vers
// libdns sans renommer quoi que ce soit.
func GabaritSecret(chemin string, cles []string) string {
	paires := make([][2]string, 0, len(cles))
	for _, c := range cles {
		paires = append(paires, [2]string{c, c})
	}
	return GabaritSecretPaires(chemin, paires)
}
