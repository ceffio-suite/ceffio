// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package theming applies the Ceffio visual identity to Nextcloud.
//
// WHY IT IS A PACKAGE AND NOT THE SCRIPT IN branding/: branding/nextcloud/
// carries the sources and a script that applies the theme BY HAND on a running
// installation. That script is right for designing the theme; it is wrong for
// installing Ceffio — a product that requires a manual step after `install` has
// a hole in it, and the hole widens at each release because nothing replays
// the step. The script and this package therefore set THE SAME values; the
// script stays the place where one iterates on the design.
//
// WHY THE IMAGES TRAVEL INSIDE THE BINARY: the `ceffio` binary must be able to
// theme an installation with no repository beside it — an air-gapped machine
// receives the binary alone, and the branding sources are not shipped with it.
// Embedding four files costs a few dozen kilobytes and removes the dependency
// on a directory that may not exist.
//
// WHAT WE DELIBERATELY DO NOT DO:
//   - no theming_customcss app and no hand-written CSS: the CSS breaks at
//     Nextcloud upgrades, which is exactly what the built-in Theming app
//     exists to avoid (same exclusion rule as internal/apps);
//   - no themes/ folder inside Nextcloud: a legacy mechanism the occurrence
//     and the Theming app supersede;
//   - no Keycloak theming: that is a separate chantier, with its own sources
//     and its own constraints.
package theming

import (
	"context"
	"embed"
	"fmt"
	"strings"

	"github.com/ceffio-suite/ceffio/internal/k8s"
)

// Les quatre fichiers image servis par Nextcloud.
//
// The three source files of branding/nextcloud/ (background.svg, favicon.svg,
// logo-ink.svg) are NOT here: Nextcloud never reads them, and background.jpg
// plus favicon.png already carry the same drawing. Only the files that end up
// in the container are embedded.
//
//go:embed assets/logo.svg assets/logoheader.svg assets/favicon.png assets/background.jpg
var assets embed.FS

// Image embarquée : le fichier dans le binaire, et le nom qu'il portera dans
// le conteneur.
type image struct {
	Embede   string // chemin dans le binaire (sous assets/)
	Nom      string // nom du fichier écrit dans le conteneur
	Cle      string // clé `occ theming:config` correspondante
	Pourquoi string // raison du FORMAT choisi, reprise en sortie
}

// Les images, dans l'ordre où elles sont posées puis configurées.
//
// THE FORMAT OF EACH FILE IS A CONSTRAINT, NOT A PREFERENCE:
//   - favicon in PNG because Nextcloud only accepts an SVG favicon when
//     ImageMagick has SVG support, which the official image does not guarantee
//     — an SVG favicon silently yields no icon;
//   - background in JPEG because Nextcloud derives the colour of the text laid
//     over the background FROM THE IMAGE ITSELF, which needs a raster image;
//     handed an SVG it cannot compute that colour.
var images = []image{
	{Embede: "assets/logo.svg", Nom: "logo.svg", Cle: "logo", Pourquoi: "login page and e-mail header"},
	{Embede: "assets/logoheader.svg", Nom: "logoheader.svg", Cle: "logoheader", Pourquoi: "top-left of every page"},
	{Embede: "assets/favicon.png", Nom: "favicon.png", Cle: "favicon", Pourquoi: "PNG: the official image does not guarantee ImageMagick handles SVG"},
	{Embede: "assets/background.jpg", Nom: "background.jpg", Cle: "background", Pourquoi: "JPEG: Nextcloud computes the text colour from the image"},
}

// Les valeurs du thème. Constants of the package, because they describe the
// product and not the installation — the only one that could vary, `url`,
// keeps its default: pointing it at a local address would break the footer of
// an installation exposed on the Internet, and the repository is the honest
// destination for a project whose source is public.
const (
	Nom             = "Ceffio"
	Slogan          = "La suite collaborative souveraine"
	URL             = "https://github.com/ceffio-suite/ceffio"
	CouleurPrimaire = "#2B4FD8" // buttons, links, focus — 6.5:1 on white
	CouleurFond     = "#12151C" // ground behind the background image
)

// repertoireTemporaire : where the images are written inside the container
// before occ reads them.
//
// WHY A TEMPORARY DIRECTORY AND NOT /var/www/html: occ takes an absolute path
// and copies the file into Nextcloud's own storage. Writing into the served
// directory would leave a stray file in the web root, and would keep it after
// the theme is applied.
const repertoireTemporaire = "/tmp/ceffio-theme"

// Les textes et couleurs posés par Deploy, dans l'ordre.
//
// EXPORTED FROM THE PACKAGE AND NOT DUPLICATED IN THE TEST: the test asserted
// once on its own copy of this list, and removing a key from Deploy then left
// the test green — it was checking its own description of the theme rather
// than the theme. A single source means the test cannot drift from the code it
// is meant to protect.
var textesEtCouleurs = [][2]string{
	{"name", Nom},
	{"slogan", Slogan},
	{"url", URL},
	{"primary_color", CouleurPrimaire},
	{"background_color", CouleurFond},
}

// Deploy applies the Ceffio theme to the Nextcloud of a running installation,
// idempotently.
//
// Idempotent in the strict sense: `theming:config <key> <value>` overwrites,
// so replaying the deployment re-poses the same values without error. That is
// what makes `ceffio theme` safe to run after a Nextcloud upgrade, which is
// the case the command exists for — an upgrade can reset theming values.
func Deploy(ctx context.Context) error {
	fmt.Println("\nApplying the Ceffio theme to Nextcloud (Phase 13)...")

	// 1. The images are copied FIRST: occ validates the path, so configuring
	//    an image before writing it fails with "file not found".
	if err := poserImages(ctx); err != nil {
		return err
	}

	// 2. Texts and colours.
	//
	// `primary_color` AND NOT `color`: `color` is deprecated, occ prints a
	// warning and converts it. Writing the deprecated key works today and
	// breaks the day it is removed — and the warning is buried in a long
	// installation output.
	for _, kv := range textesEtCouleurs {
		if err := occ(ctx, "theming:config", kv[0], kv[1]); err != nil {
			return fmt.Errorf("theming: setting %s: %w", kv[0], err)
		}
	}

	// 3. The images, by ABSOLUTE path inside the container. A relative path is
	//    refused by occ; the file must be reachable from the Nextcloud
	//    process, not from where the command is typed.
	for _, img := range images {
		if err := occ(ctx, "theming:config", img.Cle, repertoireTemporaire+"/"+img.Nom); err != nil {
			return fmt.Errorf("theming: setting %s: %w", img.Cle, err)
		}
	}

	// 4. Cleanup. A failure here does not fail the deployment: the theme is
	//    applied, and leaving four files in /tmp is not worth reporting an
	//    error for — the next run overwrites them anyway.
	if err := effacerRepertoire(ctx); err != nil {
		fmt.Printf("  ! temporary directory not removed: %v\n", err)
	}

	fmt.Printf("  ✓ theme applied (%s · %s)\n", Nom, Slogan)
	return nil
}

// poserImages copies each embedded image into the Nextcloud container.
//
// THE CONTENT TRAVELS ON STANDARD INPUT, never through `kubectl cp`: the file
// exists only inside the binary, and `cp` requires it on disk beforehand.
// Piping it means the deployment carries its own assets, with no temporary
// file on the operator's machine.
func poserImages(ctx context.Context) error {
	if err := creerRepertoire(ctx); err != nil {
		return err
	}
	for _, img := range images {
		contenu, err := assets.ReadFile(img.Embede)
		if err != nil {
			return fmt.Errorf("theming: reading %s embedded in the binary: %w", img.Embede, err)
		}
		if len(contenu) == 0 {
			return fmt.Errorf("theming: %s is empty in the binary", img.Embede)
		}
		// chmod 0644: the Nextcloud process must be able to READ the file, and
		// the default umask inside the container is not guaranteed.
		script := fmt.Sprintf("cat > %s/%s && chmod 0644 %s/%s",
			repertoireTemporaire, img.Nom, repertoireTemporaire, img.Nom)
		if err := kx(ctx, contenu, "sh", "-c", script); err != nil {
			return fmt.Errorf("theming: writing %s into the container: %w", img.Nom, err)
		}
	}
	return nil
}

func creerRepertoire(ctx context.Context) error {
	return kx(ctx, nil, "mkdir", "-p", repertoireTemporaire)
}

func effacerRepertoire(ctx context.Context) error {
	return kx(ctx, nil, "rm", "-rf", repertoireTemporaire)
}

// kx runs a command inside the Nextcloud container.
//
// WHY THE EXISTING occ HELPER IS NOT REUSED: it lives in internal/apps and is
// unexported; exporting it would make two packages depend on each other for
// one line of plumbing. The duplication is three lines and the parameters are
// named once — the trade-off is stated here rather than left implicit.
func kx(ctx context.Context, entree []byte, args ...string) error {
	complet := append([]string{
		"exec", "-i", "-n", "ceffio-files", "deploy/nextcloud", "-c", "nextcloud", "--",
	}, args...)
	cmd := k8s.Command(ctx, "kubectl", complet...)
	cmd.Env = k8s.Env()
	if entree != nil {
		cmd.Stdin = strings.NewReader(string(entree))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// occ runs a php occ command inside the Nextcloud container.
func occ(ctx context.Context, args ...string) error {
	occArgs := append([]string{"php", "occ"}, args...)
	return kx(ctx, nil, occArgs...)
}
