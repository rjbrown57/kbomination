package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rjbrown57/kbomination/internal/model"
	"github.com/rjbrown57/kbomination/internal/store"
)

func TestCatalogNameGroups(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "catalog.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	components := []map[string]string{}
	for i := range 105 {
		version := "1.0"
		if i == 0 {
			version = "2.0"
		}
		components = append(components, map[string]string{"bom-ref": fmt.Sprint(i), "name": "dns", "type": "application", "version": version, "purl": fmt.Sprintf("pkg:generic/vendor%d/dns@%s", i, version)})
	}
	components = append(components, map[string]string{"bom-ref": "other", "name": "dns-tools", "type": "application"})
	raw, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
	if err != nil {
		t.Fatal(err)
	}
	// Repeated observations in different clusters must not inflate identity counts.
	for _, cluster := range []string{"north", "south"} {
		if _, err := s.Import(context.Background(), model.Artifact{Cluster: model.Cluster{Name: cluster}, CollectedAt: time.Now().UTC(), KBOM: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Exec(context.Background(), "UPDATE component_catalog SET labels=? WHERE purl=?", `{"team":"platform"}`, "pkg:generic/vendor0/dns@2.0"); err != nil {
		t.Fatal(err)
	}
	handler := (&API{Store: s}).Handler()
	get := func(path string) []map[string]any {
		t.Helper()
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/"+path, nil))
		if res.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, res.Code, res.Body.String())
		}
		var result store.Result
		if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		rows := []map[string]any{}
		for _, values := range result.Rows {
			row := map[string]any{}
			for i, column := range result.Columns {
				row[column.Name] = values[i]
			}
			rows = append(rows, row)
		}
		return rows
	}
	for _, tc := range []struct {
		query, name  string
		count, total int
	}{
		{"group_by=name&limit=1", "dns", 105, 2},
		{"group_by=name&limit=1&offset=1", "dns-tools", 1, 2},
		{"group_by=name&name=DNS&version=2.0", "dns", 1, 1},
		{"group_by=name&label=platform", "dns", 1, 1},
		{"group_by=name&cluster_id=" + model.ClusterID("north") + "&exact_name=dns", "dns", 105, 1},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rows := get("catalog?" + tc.query)
			if len(rows) != 1 || rows[0]["name"] != tc.name || rows[0]["component_count"] != float64(tc.count) || rows[0]["total_count"] != float64(tc.total) {
				t.Fatalf("unexpected groups: %+v", rows)
			}
		})
	}
	rows := get("catalog?exact_name=dns&limit=100&offset=100")
	if len(rows) != 5 {
		t.Fatalf("expected remaining 5 identities, got %d", len(rows))
	}
	for _, row := range rows {
		if row["name"] != "dns" || row["total_count"] != float64(105) {
			t.Fatalf("unexpected identity: %+v", row)
		}
	}
	id := rows[0]["component_id"].(string)
	if detail := get("catalog/" + id); len(detail) != 1 || detail[0]["component_id"] != id {
		t.Fatalf("direct detail lookup: %+v", detail)
	}
	if clusters := get("catalog/" + id + "/clusters"); len(clusters) != 2 {
		t.Fatalf("linked clusters: %+v", clusters)
	}
	for _, query := range []string{"group_by=name&name=missing", "exact_name=dns&offset=105", "group_by=name&cluster_id=missing"} {
		if rows := get("catalog?" + query); len(rows) != 0 {
			t.Fatalf("%s: expected no matches, got %+v", query, rows)
		}
	}
}

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

func TestCollectionOptionsAPI(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	handler := (&API{Store: s}).Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(method, "http://127.0.0.1/api/v1/"+path, strings.NewReader(body)))
		return res
	}
	res := request("POST", "profiles", `{"name":"images","collection_options":{"scan_images":true,"parallel":0,"qps":2.5,"burst":4,"image_src":["remote"],"include_kinds":["Pod"],"exclude_namespaces":["dev"],"cache_dir":"/cache","cacert":"/ca.pem","db_repository":["mirror/db:2"],"java_db_repository":["mirror/java:1"],"skip_db_update":true,"skip_java_db_update":true,"offline_scan":true}}`)
	if res.Code != 200 {
		t.Fatalf("save: %s", res.Body.String())
	}
	var saved model.Profile
	if err := json.Unmarshal(res.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if *saved.CollectionOptions.Parallel != 0 || saved.CollectionOptions.IncludeKinds[0] != "pod" {
		t.Fatalf("save normalization: %+v", saved)
	}
	res = request("GET", "profiles", "")
	var profiles []model.Profile
	if err := json.Unmarshal(res.Body.Bytes(), &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].CollectionOptions.CACert != "/ca.pem" || !profiles[0].CollectionOptions.SkipDBUpdate {
		t.Fatalf("read: %+v", profiles)
	}
	if res := request("POST", "profiles", `{"name":"bad","collection_options":{"parallel":-1}}`); res.Code != 400 {
		t.Fatalf("invalid settings status: %d", res.Code)
	}
	a := model.Artifact{Cluster: model.Cluster{Name: "test"}, CollectedAt: time.Now().UTC(), CollectionOptions: &saved.CollectionOptions, KBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)}
	raw, _ := json.Marshal(a)
	res = request("POST", "import", string(raw))
	if res.Code != 200 {
		t.Fatalf("import: %s", res.Body.String())
	}
	for _, endpoint := range []string{"snapshots", "scopes?cluster_id=" + model.ClusterID("test")} {
		res = request("GET", endpoint, "")
		if res.Code != 200 || !strings.Contains(res.Body.String(), "coverage:v1:") || !strings.Contains(res.Body.String(), "images scanned") {
			t.Fatalf("%s: %s", endpoint, res.Body.String())
		}
	}
}
