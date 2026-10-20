// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

// Package theme ships the Ceffio login theme into the Keycloak pod.
//
// THE FILES LIVE HERE, NOT IN branding/, and that is a deliberate trade: Go's
// //go:embed cannot reach outside the package directory, so a theme under branding/
// would have to be COPIED into the package — two copies of 168 K, and the kind of
// drift where the one that ships is not the one that was edited. branding/keycloak/
// keeps the README that explains the theme; the assets themselves are here, named
// once.
package theme

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// themeFiles is the theme as it is served. The tree is:
//
//	login/theme.properties
//	login/messages/messages_{fr,en}.properties
//	login/resources/css/ceffio.css
//	login/resources/img/{logo.svg,background.jpg,favicon.ico,favicon.svg}
//	login/resources/fonts/{sora-latin-400,600}-normal.woff2 + OFL.txt
//
//go:embed all:ceffio
var themeFiles embed.FS

// racine is where the theme sits inside the embedded tree.
const racine = "ceffio"

// VolumeMountPath is where Keycloak expects third-party themes. Keycloak reads this
// directory AT STARTUP; nothing here needs `kc.sh build`.
const VolumeMountPath = "/opt/keycloak/themes/ceffio"

// BinaryExtensions lists what a ConfigMap cannot hold in `data`: these go to
// `binaryData`. The split matters — a JPEG in `data` is rejected by the API server
// with a message about invalid UTF-8, which names neither the file nor the reason.
var BinaryExtensions = map[string]bool{
	".jpg":   true,
	".jpeg":  true,
	".png":   true,
	".gif":   true,
	".ico":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".otf":   true,
}

// CleConfigMap flattens a path into a legal ConfigMap key.
//
// A CONFIGMAP KEY CANNOT CONTAIN A SLASH, and cannot start or end with a dot. The
// path is therefore joined with a double underscore, which cannot occur in any of
// these filenames — a single underscore would make `resources_img` ambiguous with a
// directory called `resources_img`, and the collision would only appear the day
// someone created one.
//
//	login/resources/css/ceffio.css -> login__resources__css__ceffio.css
func CleConfigMap(chemin string) string {
	propre := path.Clean(strings.TrimPrefix(chemin, "/"))
	return strings.ReplaceAll(propre, "/", "__")
}

// CheminDepuisCle is the inverse of CleConfigMap, used for the volume's items[].path.
func CheminDepuisCle(cle string) string {
	return strings.ReplaceAll(cle, "__", "/")
}

// Fichier is one entry of the theme, ready to be written into a ConfigMap.
type Fichier struct {
	// Cle is the flattened ConfigMap key.
	Cle string
	// Chemin is the path inside the theme, relative to the theme root.
	Chemin string
	// Binaire selects `binaryData` over `data`.
	Binaire bool
	// Contenu is the file itself.
	Contenu []byte
}

// Fichiers returns the theme's files, sorted by key so the output is stable.
//
// A STABLE ORDER IS NOT COSMETIC: the checksum that triggers a pod restart is
// computed from this list, and a map's iteration order would change it on every
// run — restarting the pod on every `ceffio install` for no reason.
func Fichiers() ([]Fichier, error) {
	var out []Fichier
	err := fs.WalkDir(themeFiles, racine, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		contenu, err := themeFiles.ReadFile(p)
		if err != nil {
			return fmt.Errorf("theme: reading embedded %s: %w", p, err)
		}
		// The embedded tree begins at `ceffio`, which is the THEME NAME, not a
		// directory inside it. Keycloak expects login/ at the root of the theme, so
		// the leading segment is dropped here — io/fs has no Rel, and this is the
		// only relative path the package needs.
		rel := strings.TrimPrefix(p, racine+"/")
		out = append(out, Fichier{
			Cle:     CleConfigMap(rel),
			Chemin:  rel,
			Binaire: BinaryExtensions[strings.ToLower(path.Ext(rel))],
			Contenu: contenu,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cle < out[j].Cle })
	if len(out) == 0 {
		return nil, fmt.Errorf("theme: the embedded theme has no file, which means the " +
			"embed directive and the assets drifted apart")
	}
	return out, nil
}

// Somme returns a stable checksum of the theme's content.
//
// IT GOES ON THE POD TEMPLATE AS AN ANNOTATION. In production Keycloak caches
// themes, so replacing the files in a mounted volume changes nothing until the
// process restarts. The annotation makes Kubernetes restart the pod by itself when
// the theme changes — and, just as importantly, NOT restart it when nothing did.
func Somme(fichiers []Fichier) string {
	h := sha256.New()
	for _, f := range fichiers {
		// The key AND the content: a rename with identical bytes is still a change
		// for the theme loader.
		fmt.Fprintf(h, "%s\n", f.Cle)
		h.Write(f.Contenu)
	}
	return hex.EncodeToString(h.Sum(nil))
}
