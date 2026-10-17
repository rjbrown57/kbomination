package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalOnly(t *testing.T) {
	handler := localOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, host, origin, site string
		status                   int
	}{
		{"published localhost", "localhost:8080", "", "", 204},
		{"same origin", "127.0.0.1:8080", "http://127.0.0.1:8080", "same-origin", 204},
		{"IPv6", "[::1]:8080", "", "", 204},
		{"remote host", "example.com:8080", "", "", 403},
		{"container hostname", "kbomination:8080", "", "", 403},
		{"foreign origin", "localhost:8080", "http://example.com", "", 403},
		{"different port", "localhost:8080", "http://localhost:8081", "", 403},
		{"cross-site", "localhost:8080", "", "cross-site", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
		})
	}
}
