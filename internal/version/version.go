// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package version records the image and chart versions deployed by Ceffio.
// It is the single source of truth for:
//
//   - "what exactly is this installation running?" (status);
//   - "what would change if I upgraded?" (upgrade).
//
// Before this registry, each module carried its image constants in its own
// corner (files.nextcloudImage, identity.keycloakImage…). It was enough to
// deploy, but made any comparison impossible: an upgrade command has nothing
// to compare if it must read nine files.
//
// Rule: versions are PINNED and never `latest`. A component following
// `latest` cannot be upgraded reproducibly — we know neither what runs
// before, nor what will run after.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Binary, Commit and Date describe the binary itself. They are injected at
// compile time by the CI/release workflows via
// -ldflags "-X github.com/ceffio-suite/ceffio/internal/version.Binary=...".
//
// WHY HERE AND NOT IN package main: these values must be readable by the
// internal code (ImageTag, to build the image references), not only by cobra
// for `--version`. Keeping them in main made them invisible to the rest of the
// program and forced the ldflags to target a symbol nobody else could reach.
var (
	Binary = "0.0.0-dev"
	Commit = ""
	Date   = ""
)

// reRelease recognizes a release tag (`v0.6.0`, `v0.6.0-rc.1`): only a
// release version can serve as an image tag as-is, a development build must be
// identified by the content of the binary.
var reRelease = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// cheminExecutable is a package variable rather than a direct call to
// os.Executable so that tests can replace it: without that, the development
// tag would depend on the real test binary currently running, hence on the
// machine launching `go test` — impossible to verify deterministically.
var cheminExecutable = os.Executable

// ImageTag returns the Docker image tag corresponding to the current binary.
//
// WHY THIS DOUBLE REGIME: a release binary carries a public version
// (v0.6.0 → tag 0.6.0). A development build has no reliable version — two
// developers can have the same "0.0.0-dev" with different code. We then
// identify the binary by the hash of its content: same binary, same tag;
// different binary, different tag.
//
// The returned value must NEVER be empty: it becomes a Docker image tag, and a
// `registry/image:` reference (empty tag) is invalid — the deployment would
// fail with a message that would not say where the problem comes from.
func ImageTag() string {
	if reRelease.MatchString(Binary) {
		return strings.TrimPrefix(Binary, "v")
	}

	chemin, err := cheminExecutable()
	if err != nil {
		// Cannot locate the binary: we return a fixed tag rather than an
		// empty string (see the function's comment).
		return "dev-inconnu"
	}

	f, err := os.Open(chemin)
	if err != nil {
		return "dev-inconnu"
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "dev-inconnu"
	}
	// 12 hexadecimal characters: long enough to avoid practical collisions,
	// short enough to stay readable in `kubectl get pods`.
	return "dev-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Composant describes a deployed element and its pinned version.
type Composant struct {
	Nom     string `json:"nom"`     // readable name (keycloak, nextcloud…)
	Image   string `json:"image"`   // full reference, tag included
	Module  string `json:"module"`  // Go package that deploys it
	Role    string `json:"role"`    // what it is for, in one line
	Version string `json:"version"` // extracted tag, for comparison
}

// Registry is the default inventory, aligned with the deployment code.
// Any change of an image in a module MUST be reflected here: the
// VerifierCoherence() function checks it and the test verifies it.
var Registry = []Composant{
	{
		Nom: "keycloak", Image: "quay.io/keycloak/keycloak:26.7.3",
		Module: "internal/identity", Role: "identity, OIDC SSO",
	},
	{
		Nom: "nextcloud", Image: "docker.io/library/nextcloud:34.0.3",
		Module: "internal/files", Role: "files and documents",
	},
	{
		Nom: "talk-signaling", Image: "docker.io/strukturag/nextcloud-spreed-signaling:2.1.1",
		Module: "internal/talk", Role: "Talk: session coordination",
	},
	{
		Nom: "janus", Image: "ghcr.io/ceffio-suite/janus-gateway:1.4.3-1",
		Module: "internal/talk", Role: "Talk: SFU, media transport",
	},
	{
		// L'image de capture a SON dépôt (ceffio-suite/ceffio-capture) : elle
		// porte sa propre pile Python (WebRTC, whisper) et son propre cycle de
		// publication, indépendant des versions du binaire. On épingle donc une
		// version d'IMAGE, pas le tag du binaire — même règle que janus.
		Nom: "ceffio-capture", Image: "ghcr.io/ceffio-suite/ceffio-capture:v0.1.0",
		Module: "internal/capture", Role: "per-participant audio capture and CPU transcription",
	},
	{
		// The recording server is published ONLY with date tags upstream
		// (20261014_095932), never a version number: the project ships it as
		// part of Nextcloud AIO. We pin an exact date rather than "latest" —
		// a floating tag would make an installation non-reproducible, which is
		// the rule this file enforces.
		Nom: "talk-recording", Image: "docker.io/nextcloud/aio-talk-recording:20261014_095932",
		Module: "internal/recording", Role: "server-side call recording for Talk",
	},
	{
		Nom: "coturn", Image: "docker.io/coturn/coturn:4.18",
		Module: "internal/talk", Role: "Talk: TURN/STUN relay",
	},
	{
		Nom: "nats", Image: "docker.io/library/nats:2.15",
		Module: "internal/talk", Role: "Talk: signaling messaging",
	},
	{
		Nom: "openbao", Image: "docker.io/openbao/openbao:2.7.1",
		Module: "internal/vault", Role: "secrets vault: centralization, rotation, audit",
	},
	{
		Nom: "onlyoffice", Image: "docker.io/onlyoffice/documentserver:9.4.0.1",
		Module: "internal/office", Role: "document editing",
	},
	{
		Nom: "valkey", Image: "docker.io/valkey/valkey:8.1.10",
		Module: "internal/data", Role: "cache and shared state",
	},
	{
		Nom: "stalwart", Image: "docker.io/stalwartlabs/stalwart:v0.16.26",
		Module: "internal/mail", Role: "mail: inbound SMTP, IMAP, filters",
	},
	{
		// The DNS-01 webhook solver, deployed ONLY for providers cert-manager
		// does not know natively. Cloudflare, Route 53, RFC 2136 and acme-dns
		// are handled by the cert-manager binary itself and deploy NOTHING —
		// see EmpreinteWebhook in internal/ingress.
		//
		// THE VERSION IS THE UPSTREAM ONE, verified with `webhook --version`
		// rather than read from a README.
		Nom: "acme-dns-webhook", Image: "ghcr.io/ceffio-suite/acme-dns-webhook:v1.1.0",
		Module: "internal/ingress", Role: "TLS: DNS-01 solver for out-of-tree DNS hosts (libdns)",
	},

	// THE SIGN-IN IN FRONT OF AN ADMINISTRATION INTERFACE.
	//
	// It is pinned like every other image: oauth2-proxy carries the whole
	// authorization decision, and an unpinned tag would let that decision change
	// between two installs of the same Ceffio version.
	{
		Nom: "oauth2-proxy", Image: "quay.io/oauth2-proxy/oauth2-proxy:v7.15.5",
		Module: "internal/modules/longhornui",
		Role:   "Put a single sign-on in front of the Longhorn interface, which has none",
	},
}

// Helm charts used by the platform (operators).
var Charts = []Composant{
	{Nom: "cloudnative-pg", Image: "cloudnative-pg:0.29.0", Module: "internal/data",
		Role: "PostgreSQL operator", Version: "0.29.0"},
	{Nom: "cert-manager", Image: "cert-manager:v1.21.1", Module: "internal/platform",
		Role: "TLS certificate management", Version: "v1.21.1"},
}

func init() {
	for i := range Registry {
		Registry[i].Version = TagDe(Registry[i].Image)
	}
}

// TagDe exposes tag extraction (also used by `upgrade` to compare
// what runs with the target).
func TagDe(image string) string { return tagDe(image) }

// tagDe extracts the tag from an image reference.
// "docker.io/library/nextcloud:34.0.3" → "34.0.3".
// Returns "" if the image has no tag (thus implicit: latest).
func tagDe(image string) string {
	i := strings.LastIndex(image, ":")
	if i < 0 {
		return ""
	}
	tag := image[i+1:]
	if strings.Contains(tag, "/") { // the ':' belongs to the registry (host:port)
		return ""
	}
	return tag
}

// ParNom finds a component.
func ParNom(nom string) (Composant, bool) {
	for _, c := range Registry {
		if c.Nom == nom {
			return c, true
		}
	}
	return Composant{}, false
}

// ImageDe returns the image reference of a registry component.
//
// WHY THIS SINGLE ENTRY POINT: several modules need the VAULT image — not to
// deploy it, but to run a client there whose version must EXACTLY match the
// server's. Two references written in two places diverge at the first update,
// and the divergence shows up as an authentication failure, not as a message
// saying what to fix.
//
// Returns an empty string if the component is unknown: the caller decides
// what to do with it, rather than receiving an invented reference that would
// fail later.
func ImageDe(nom string) string {
	if c, ok := ParNom(nom); ok {
		return c.Image
	}
	return ""
}

// Noms returns the component names, sorted (for display and tests).
func Noms() []string {
	out := make([]string, 0, len(Registry))
	for _, c := range Registry {
		out = append(out, c.Nom)
	}
	sort.Strings(out)
	return out
}

// VerifierCoherence checks that no image follows `latest` nor an implicit
// tag: without a pinned tag, an upgrade is not reproducible.
func VerifierCoherence() []string {
	var problemes []string
	for _, c := range Registry {
		if c.Version == "" {
			problemes = append(problemes,
				fmt.Sprintf("%s: image without an explicit tag (%s) — non-reproducible version", c.Nom, c.Image))
			continue
		}
		if c.Version == "latest" || c.Version == "stable" {
			problemes = append(problemes,
				fmt.Sprintf("%s: floating tag %q — pinned required in production", c.Nom, c.Version))
		}
	}
	return problemes
}

// Comparer indicates, for each component, the installed version and the one
// from the registry. Used by `upgrade` to show what would change.
type Ecart struct {
	Nom       string
	Installee string
	Cible     string
}

// ExtraireImages extracts the versions actually in service from the pod
// images. This is what makes `upgrade` honest: it does not compare two file
// lists, it compares what RUNS with what the code would deploy.
func ExtraireImages(podsJSON string) map[string]string {
	out := map[string]string{}
	// Deliberately tolerant parsing: we look for image/version pairs without
	// depending on a full JSON decoding, because the function is also used on
	// partial outputs.
	for _, ligne := range strings.Split(podsJSON, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" {
			continue
		}
		out[ligne] = tagDe(ligne)
	}
	return out
}
