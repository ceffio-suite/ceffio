// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package charts

import (
	"strings"
	"testing"
)

// TestNamespacesRendus guards the platform namespace list.
//
// Three defects lived in these two files, all found by deploying rather than by
// reading:
//
//   - "chat" was declared: it belonged to the Matrix stack (Synapse + Element),
//     removed when Ceffio became a Nextcloud product. Every fresh install got an
//     empty ceffio-chat namespace.
//   - "vault" was MISSING: everything OpenBao-related lives in ceffio-vault, but
//     no manifest created it — it only existed because the OpenBao Helm release
//     used --create-namespace, and so carried none of the platform labels.
//   - managedBy said "ceffio-operator": there is no Operator in Ceffio, the CLI
//     applies the manifests itself. The label pointed at code that does not exist.
//
// The comments in values.yaml mention those removals on purpose (a reader needs
// to know why), so the checks below look at the RENDERED data — the parsed keys
// — and skip comment lines, never the raw text.
func TestNamespacesRendus(t *testing.T) {
	b, err := FS.ReadFile("ceffio/values.yaml")
	if err != nil {
		t.Fatalf("values.yaml unreadable: %v", err)
	}

	// A namespace entry is exactly "<name>: {}" on a trimmed line. Comments
	// start with '#' and never match.
	declares := func(nom string) bool {
		for _, ligne := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(ligne) == nom+": {}" {
				return true
			}
		}
		return false
	}

	// What the platform actually needs.
	for _, attendu := range []string{
		"identity", "data", "files", "office", "video", "mail", "vault", "observability",
	} {
		if !declares(attendu) {
			t.Errorf("values.yaml does not declare the %q namespace", attendu)
		}
	}

	// What must NOT be there.
	if declares("chat") {
		t.Error(`values.yaml declares "chat": that namespace belonged to the removed Matrix stack`)
	}
	if declares("system") {
		t.Error(`values.yaml declares "system": it is the Helm release namespace, created by --create-namespace`)
	}

	// managedBy must not name the Operator that does not exist.
	for _, ligne := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(ligne)
		if strings.HasPrefix(l, "#") {
			continue // a comment may legitimately mention it
		}
		if strings.Contains(l, "ceffio-operator") {
			t.Errorf("managedBy references ceffio-operator, which does not exist: %q", l)
		}
	}

	// The template must render "ceffio-<name>".
	tpl, err := FS.ReadFile("ceffio/templates/namespaces.yaml")
	if err != nil {
		t.Fatalf("template unreadable: %v", err)
	}
	if !strings.Contains(string(tpl), `printf "ceffio-%s"`) {
		t.Error("the template does not render namespace names with the ceffio- prefix")
	}
}
