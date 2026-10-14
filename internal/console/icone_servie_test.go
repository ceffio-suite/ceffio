package console

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIconesServies(t *testing.T) {
	s := &Server{}
	h := s.Handler()
	for _, c := range []struct{ chemin, typeMIME string }{
		{"/favicon.ico", "image/x-icon"},
		{"/favicon.svg", "image/svg+xml"},
		{"/favicon-32.png", "image/png"},
		{"/apple-touch-icon.png", "image/png"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.chemin, nil))
		if rec.Code != 200 {
			t.Errorf("%s -> %d, attendu 200", c.chemin, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != c.typeMIME {
			t.Errorf("%s -> Content-Type %q, attendu %q", c.chemin, got, c.typeMIME)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s -> corps vide", c.chemin)
		}
		t.Logf("%s -> 200, %s, %d octets", c.chemin, c.typeMIME, rec.Body.Len())
	}
	// la page ne doit pas etre cassee
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 {
		t.Errorf("/ -> %d", rec.Code)
	}
	t.Logf("/ -> 200, %d octets", rec.Body.Len())
}
