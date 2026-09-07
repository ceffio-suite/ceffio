package console

import (
	"embed"
	"net/http"
)

//go:embed index.html
var webFS embed.FS

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("index.html")
	if err != nil {
		apiErr(w, 500, "page introuvable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
