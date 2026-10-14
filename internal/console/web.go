package console

import (
	"embed"
	"net/http"
	"os"
)

//go:embed web/index.html
var webFS embed.FS

// handleIndex serves the page. In production (image), the web is also mounted at
// /app/web/index.html (the Deployment manifest mounts it); the embed serves as
// fallback.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if b, err := os.ReadFile("/app/web/index.html"); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		apiErr(w, 500, "page not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
