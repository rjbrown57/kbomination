package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rjbrown57/kbomination/internal/model"
)

func TestValidateListen(t *testing.T) {
	for _, tc := range []struct {
		address string
		allow   bool
		valid   bool
	}{
		{"127.0.0.1:8080", false, true},
		{"[::1]:8080", false, true},
		{"0.0.0.0:8080", false, false},
		{"[::]:8080", false, false},
		{"192.0.2.1:8080", false, false},
		{"0.0.0.0:8080", true, true},
		{"[::]:8080", true, true},
		{"localhost:8080", true, false},
		{":8080", true, false},
		{"invalid", true, false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			if err := validateListen(tc.address, tc.allow); (err == nil) != tc.valid {
				t.Fatalf("validateListen(%q, %v) = %v, want valid=%v", tc.address, tc.allow, err, tc.valid)
			}
		})
	}
}

func TestValidateServerURL(t *testing.T) {
	for _, tc := range []struct {
		url   string
		valid bool
	}{
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://localhost:8080", true},
		{"https://kbomination.localhost:8443", true},
		{"https://localhost:8443", true},
		{"https://example.com", false},
		{"https://other.localhost", false},
		{"https://kbomination.localhost.example.com", false},
		{"ftp://localhost", false},
		{"https://user@kbomination.localhost", false},
		{"https://kbomination.localhost?x=1", false},
		{"https://kbomination.localhost#fragment", false},
		{"https://", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			if err := validateServerURL(tc.url); (err == nil) != tc.valid {
				t.Fatalf("validateServerURL(%q) = %v, want valid=%v", tc.url, err, tc.valid)
			}
		})
	}
}

func TestStandaloneImportUsesClusterName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	received := make(chan model.Artifact, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var artifact model.Artifact
		if err := json.NewDecoder(r.Body).Decode(&artifact); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- artifact
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	command := root()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"import", path, "--cluster", "production", "--collected-at", "2026-10-18T00:00:00Z", "--server", server.URL})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	select {
	case artifact := <-received:
		if artifact.Cluster.Name != "production" || artifact.Cluster.Source != "" {
			t.Fatalf("unexpected cluster: %+v", artifact.Cluster)
		}
	default:
		t.Fatal("no artifact was imported")
	}
}
