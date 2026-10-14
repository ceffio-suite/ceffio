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
