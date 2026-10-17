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

// Binary, Commit et Date décrivent le binaire lui-même. Elles sont injectées
// à la compilation par les workflows CI/release via
// -ldflags "-X github.com/ceffio-suite/ceffio/internal/version.Binary=...".
//
// POURQUOI ICI ET PAS DANS package main : ces valeurs doivent être lisibles
// par le code interne (ImageTag pour construire les références d'images),
// pas seulement par cobra pour `--version`. Les garder dans main les rendait
// invisibles du reste du programme et obligeaient les ldflags à viser un
// symbole que personne d'autre ne pouvait atteindre.
var (
	Binary = "0.0.0-dev"
	Commit = ""
	Date   = ""
)

// reRelease reconnaît un tag de release (`v0.6.0`, `v0.6.0-rc.1`) : seule
// une version de release peut servir de tag d'image tel quel, un build de
// développement doit être identifié par le contenu du binaire.
var reRelease = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// cheminExecutable est une variable de package plutôt qu'un appel direct à
// os.Executable pour que les tests puissent la remplacer : sans cela, le tag
// de développement dépendrait du vrai binaire de test en cours d'exécution,
// donc de la machine qui lance `go test` — impossible à vérifier
// déterministiquement.
var cheminExecutable = os.Executable

// ImageTag retourne le tag d'image Docker correspondant au binaire en cours.
//
// POURQUOI CE DOUBLE RÉGIME : un binaire de release porte une version
// publique (v0.6.0 → tag 0.6.0). Un build de développement n'a pas de
// version fiable — deux développeurs peuvent avoir le même "0.0.0-dev" avec
// du code différent. On identifie alors le binaire par le hachage de son
// contenu : même binaire, même tag ; binaire différent, tag différent.
//
// La valeur retournée ne doit JAMAIS être vide : elle devient un tag
// d'image Docker, et une référence `registry/image:` (tag vide) est
// invalide — le déploiement échouerait avec un message qui ne dirait pas
// d'où vient le problème.
func ImageTag() string {
	if reRelease.MatchString(Binary) {
		return strings.TrimPrefix(Binary, "v")
	}

	chemin, err := cheminExecutable()
	if err != nil {
		// Impossible de localiser le binaire : on retourne un tag fixe
		// plutôt qu'une chaîne vide (voir commentaire de la fonction).
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
	// 12 caractères hexadécimaux : assez long pour éviter les collisions
	// pratiques, assez court pour rester lisible dans `kubectl get pods`.
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
