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

func TestImportCollectionOptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kbom.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	received := make(chan model.Artifact, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a model.Artifact
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			t.Error(err)
		}
		received <- a
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	run := func(args ...string) error {
		cmd := root()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append(args, "--server", server.URL))
		return cmd.Execute()
	}
	if err := run("import", path, "--cluster", "test", "--collected-at", "2026-10-24T00:00:00Z", "--scan-images", "--offline-scan", "--include-kinds", "Pod,service", "--exclude-namespaces", "z,dev"); err != nil {
		t.Fatal(err)
	}
	a := <-received
	if a.CollectionOptions == nil || !a.CollectionOptions.ScanImages || a.CollectionOptions.IncludeKinds[0] != "pod" || a.CollectionOptions.ExcludeNamespaces[0] != "dev" {
		t.Fatalf("coverage lost: %+v", a)
	}
	for _, version := range []int{1, 2} {
		options := a.CollectionOptions
		if version == 1 {
			options = nil
		}
		manifest := model.Manifest{Version: version, Entries: []model.ManifestEntry{{Artifact: model.Artifact{Cluster: model.Cluster{Name: "test"}, CollectedAt: a.CollectedAt, CollectionOptions: options}, File: "kbom.json", Status: "succeeded"}}}
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(dir, "manifest.json")
		if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := run("import", "--manifest", manifestPath); err != nil {
			t.Fatal(err)
		}
		got := <-received
		if (got.CollectionOptions == nil) != (version == 1) {
			t.Fatalf("version %d coverage lost", version)
		}
		if err := run("import", "--manifest", manifestPath, "--scan-images"); err == nil {
			t.Fatal("manifest override accepted")
		}
	}
	if err := run("import", path, "--cluster", "test", "--collected-at", "2026-10-24T00:00:00Z", "--namespaces", "prod", "--exclude-namespaces", "prod"); err == nil {
		t.Fatal("contradictory import accepted")
	}
}

func TestCollectionFlagDefaults(t *testing.T) {
	command, _, err := root().Find([]string{"collect"})
	if err != nil {
		t.Fatal(err)
	}
	if err := command.ParseFlags([]string{"--parallel=0", "--scan-images", "--image-src=remote,docker", "--qps=2.5"}); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"exclude-namespaces", "include-kinds", "exclude-kinds", "qps", "burst", "scan-images", "parallel", "image-src", "cache-dir", "cacert", "db-repository", "java-db-repository", "skip-db-update", "skip-java-db-update", "offline-scan"} {
		if command.Flags().Lookup(flag) == nil {
			t.Fatalf("missing flag %s", flag)
		}
	}
	if got, _ := command.Flags().GetInt("parallel"); got != 0 {
		t.Fatalf("parallel=%d", got)
	}
	if got, _ := command.Flags().GetInt("burst"); got != 10 {
		t.Fatalf("burst=%d", got)
	}
}
