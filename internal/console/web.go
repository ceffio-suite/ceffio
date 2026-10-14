// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © MANDEM

package console

import (
	"embed"
	"net/http"
)

//go:embed web/index.html web/favicon.svg web/favicon.ico web/favicon-32.png web/apple-touch-icon.png
var webFS embed.FS

// handleIndex serves the page.
//
// THE PAGE COMES FROM THE EMBED, never from a file mounted into the pod: no
// manifest mounts /app/web, and the image is built from the binary alone. A
// previous version looked for /app/web/index.html first — a fallback that
// could only ever fail, described by a comment that claimed otherwise.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		apiErr(w, 500, "page not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// iconeFichiers maps icon routes to the embedded files and their types.
//
// THE ICONS ARE SERVED BY THE BINARY, not fetched from a CDN: this console runs
// on isolated networks, and a favicon request leaving the host would be both a
// failure and a leak.
var iconeFichiers = map[string]struct{ fichier, typeMIME string }{
	"/favicon.ico":          {"web/favicon.ico", "image/x-icon"},
	"/favicon.svg":          {"web/favicon.svg", "image/svg+xml"},
	"/favicon-32.png":       {"web/favicon-32.png", "image/png"},
	"/apple-touch-icon.png": {"web/apple-touch-icon.png", "image/png"},
}

// handleIcone serves the favicon and the touch icon.
func (s *Server) handleIcone(w http.ResponseWriter, r *http.Request) {
	entree, ok := iconeFichiers[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile(entree.fichier)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", entree.typeMIME)
	// The icons change only with a new binary, so they can be cached hard.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}
