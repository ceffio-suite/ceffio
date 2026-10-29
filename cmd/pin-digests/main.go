// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// pin-digests pins every container image of the version registry by digest.
//
// WHY A COMMAND, AND NOT A HAND EDITED FILE: the tags of this registry move on
// their registries. A digest does not. Pinning by hand means copying fourteen
// long strings correctly, at every version bump — and the failure mode is a
// silent one, a typo that resolves to another image or to nothing.
//
// WHY NOT A CI JOB THAT REWRITES THE FILE: a workflow that commits has to hold a
// token that can push, and this file is reviewed. The pinning is a maintainer's
// act, deliberate, with the diff in front of them.
//
// WHAT IT DOES NOT TOUCH: the Helm charts (var Charts) — their "Image" field
// names a chart, not a container, and a chart has no registry digest. The
// distinction is the '/' in the reference: a chart entry has none.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// motifImage captures the whole value of an Image field, with its quotes.
var motifImage = regexp.MustCompile(`Image:\s*"([^"]+)"`)

func main() {
	const chemin = "internal/version/version.go"
	brut, err := os.ReadFile(chemin)
	if err != nil {
		fatal("lecture de %s : %v", chemin, err)
	}
	source := string(brut)

	// THE REGISTRY ONLY. Charts start after the "var Charts" declaration, and a
	// chart reference has no '/' in it — both conditions are checked, so an
	// entry added in the wrong block is skipped rather than corrupted.
	fin := strings.Index(source, "var Charts")
	if fin < 0 {
		fatal("la déclaration var Charts est introuvable : le fichier a changé de forme")
	}
	registre, suite := source[:fin], source[fin:]

	var remplacements, echecs int
	nouveau := motifImage.ReplaceAllStringFunc(registre, func(trouve string) string {
		image := motifImage.FindStringSubmatch(trouve)[1]
		if strings.Contains(image, "@sha256:") {
			fmt.Printf("  déjà épinglée : %s\n", image)
			return trouve
		}
		if !strings.Contains(image, "/") {
			fmt.Printf("  ignorée (ce n'est pas une image de conteneur) : %s\n", image)
			return trouve
		}
		digest, err := digestDe(image)
		if err != nil {
			echecs++
			fmt.Printf("  ÉCHEC : %s : %v\n", image, err)
			return trouve
		}
		remplacements++
		fmt.Printf("  épinglée : %s -> %s\n", image, digest[:19]+"…")
		return strings.Replace(trouve, `"`+image+`"`, `"`+image+"@"+digest+`"`, 1)
	})

	if echecs > 0 {
		// NOTHING IS WRITTEN when one image could not be resolved: a half-pinned
		// registry is worse than an unpinned one, because it looks done.
		fatal("%d image(s) non résolue(s) : fichier inchangé", echecs)
	}
	if remplacements == 0 {
		fmt.Println("rien à faire : toutes les images sont déjà épinglées")
		return
	}
	if err := os.WriteFile(chemin, []byte(nouveau+suite), 0o644); err != nil {
		fatal("écriture de %s : %v", chemin, err)
	}
	fmt.Printf("%d image(s) épinglée(s) dans %s\n", remplacements, chemin)
}

// digestDe asks the registry for the digest of an image's index.
//
// THE INDEX, NOT A PLATFORM MANIFEST: `docker buildx imagetools inspect` reports
// the digest that `@sha256:` must carry — the one a pull resolves per platform.
// Using the amd64 manifest's digest instead would break arm64 installations.
func digestDe(image string) (string, error) {
	cmd := exec.Command("docker", "buildx", "imagetools", "inspect", image,
		"--format", "{{json .Manifest.Digest}}")
	sortie, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("imagetools inspect : %w", err)
	}
	var digest string
	if err := json.Unmarshal(sortie, &digest); err != nil {
		return "", fmt.Errorf("réponse inattendue (%s) : %w", strings.TrimSpace(string(sortie)), err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("digest inattendu : %q", digest)
	}
	return digest, nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "pin-digests : "+format+"\n", a...)
	os.Exit(1)
}
