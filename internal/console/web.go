package console

import (
	"embed"
	"net/http"
	"os"
)

//go:embed web/index.html
var webFS embed.FS

// handleIndex sert la page. En production (image), le web est aussi monté à
// /app/web/index.html (le manifest Deployment le monte) ; l'embed sert de secours.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if b, err := os.ReadFile("/app/web/index.html"); err == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		apiErr(w, 500, "page introuvable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
