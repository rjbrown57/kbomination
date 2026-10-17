package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionEndpoint(t *testing.T) {
	handler := (&API{Version: "1.2.3", Commit: "abcdef0123456789"}).Handler()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/version", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	var got map[string]string
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != "1.2.3" || got["commit"] != "abcdef0123456789" {
		t.Fatalf("version response = %#v", got)
	}
}

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
		{"local HTTPS", "kbomination.localhost:8443", "https://kbomination.localhost:8443", "same-origin", 204},
		{"HTTPS foreign origin", "kbomination.localhost:8443", "https://example.com:8443", "", 403},
		{"HTTPS different port", "kbomination.localhost:8443", "https://kbomination.localhost", "", 403},
		{"unapproved local name", "other.localhost:8443", "", "", 403},
		{"invalid origin scheme", "kbomination.localhost:8443", "ftp://kbomination.localhost:8443", "", 403},
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
