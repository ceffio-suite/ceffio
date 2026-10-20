// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package theme

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// NomConfigMap is the ConfigMap the theme travels in.
const NomConfigMap = "keycloak-theme-ceffio"

// NomVolume is the volume that mounts it.
const NomVolume = "keycloak-theme"

// ManifesteConfigMap builds the ConfigMap that carries the theme.
//
// YAML IS BUILT BY HAND, NOT FROM A LIBRARY, and the reason is base64: a binary
// entry has to become a STRING in `binaryData`, and a generic marshaller encodes
// []byte as base64 for us but also re-encodes the map keys and quotes every scalar,
// which makes the output unreadable in a diff. The theme is eleven known files, so
// hand-building it is cheaper than teaching a marshaller to leave it alone.
//
// THE TWO MAPS ARE THE POINT: `data` for text, `binaryData` for what is not. A JPEG
// in `data` is refused by the API server with a message about invalid UTF-8 that
// names neither the file nor the reason.
func ManifesteConfigMap(ns string) (string, error) {
	fichiers, err := Fichiers()
	if err != nil {
		return "", err
	}

	var texte, binaire []Fichier
	for _, f := range fichiers {
		if f.Binaire {
			binaire = append(binaire, f)
		} else {
			texte = append(texte, f)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", NomConfigMap, ns)
	fmt.Fprintf(&b, "  labels:\n    app.kubernetes.io/part-of: ceffio\n")
	fmt.Fprintf(&b, "    app.kubernetes.io/managed-by: ceffio\n")
	fmt.Fprintf(&b, "  annotations:\n")
	fmt.Fprintf(&b, "    ceffio.io/theme-checksum: %q\n", Somme(fichiers))

	if len(texte) > 0 {
		fmt.Fprintf(&b, "data:\n")
		for _, f := range texte {
			fmt.Fprintf(&b, "  %s: |\n", f.Cle)
			for _, ligne := range strings.Split(strings.TrimSuffix(string(f.Contenu), "\n"), "\n") {
				fmt.Fprintf(&b, "    %s\n", ligne)
			}
		}
	}

	if len(binaire) > 0 {
		fmt.Fprintf(&b, "binaryData:\n")
		for _, f := range binaire {
			fmt.Fprintf(&b, "  %s: %s\n", f.Cle, base64.StdEncoding.EncodeToString(f.Contenu))
		}
	}
	return b.String(), nil
}

// ManifesteVolume rend le bloc YAML du volume, à insérer dans le pod.
//
// ITEMS[].PATH IS WHAT REBUILDS THE TREE. A ConfigMap is flat and its keys cannot
// hold a slash, so mounting it without items would put `login__resources__css__ceffio.css`
// at the theme root, where Keycloak looks for neither — and the failure is a page
// that renders with the default theme, with no error in any log.
//
// The items are sorted so the manifest is stable: an unstable order produces a
// different pod template on every run, and Kubernetes restarts the pod for nothing.
func ManifesteVolume() (string, error) {
	fichiers, err := Fichiers()
	if err != nil {
		return "", err
	}
	cles := make([]string, 0, len(fichiers))
	for _, f := range fichiers {
		cles = append(cles, f.Cle)
	}
	sort.Strings(cles)

	var b strings.Builder
	fmt.Fprintf(&b, "      - name: %s\n", NomVolume)
	fmt.Fprintf(&b, "        configMap:\n")
	fmt.Fprintf(&b, "          name: %s\n", NomConfigMap)
	fmt.Fprintf(&b, "          items:\n")
	for _, cle := range cles {
		fmt.Fprintf(&b, "            - key: %s\n              path: %s\n",
			cle, CheminDepuisCle(cle))
	}
	return b.String(), nil
}

// BlocMontage rend le volumeMount, à insérer dans le conteneur.
//
// READ-ONLY, ALWAYS: Keycloak reads this directory at startup and never writes to
// it. A writable mount would let a compromised process rewrite the page every user
// signs in through.
func BlocMontage() string {
	return fmt.Sprintf(`            - name: %s
              mountPath: %s
              readOnly: true
`, NomVolume, VolumeMountPath)
}

// Checksum returns the value that goes on the pod template's annotation.
//
// THE ANNOTATION IS THE RESTART MECHANISM, not a label for humans: in production
// Keycloak caches themes, so replacing the files in the volume changes nothing until
// the process restarts. Kubernetes restarts the pod when the annotation's value
// changes — and only then.
func Checksum() (string, error) {
	fichiers, err := Fichiers()
	if err != nil {
		return "", err
	}
	return Somme(fichiers), nil
}

// ItemsYAML rend les items du volume, déjà indentés pour le manifeste du pod.
//
// THE INDENTATION IS ELEVEN COLUMNS because that is the depth of `items:` inside a
// volume inside a container spec. Building it here rather than in the template keeps
// the theme's shape in one place: the day a file is added, this function follows and
// the manifest does not need editing.
func ItemsYAML() string {
	fichiers, err := Fichiers()
	if err != nil {
		return ""
	}
	cles := make([]string, 0, len(fichiers))
	for _, f := range fichiers {
		cles = append(cles, f.Cle)
	}
	sort.Strings(cles)
	var b strings.Builder
	for _, cle := range cles {
		fmt.Fprintf(&b, "              - key: %s\n                path: %s\n",
			cle, CheminDepuisCle(cle))
	}
	return strings.TrimSuffix(b.String(), "\n")
}
