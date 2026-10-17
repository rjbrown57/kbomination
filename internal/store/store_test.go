package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rjbrown57/kbomination/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func artifact(version string, at time.Time, namespaces ...string) model.Artifact {
	return model.Artifact{Cluster: model.Cluster{Name: "test", Source: "fixture"}, CollectedAt: at, Namespaces: namespaces, TrivyVersion: model.TrivyVersion, KBOM: json.RawMessage(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"dns","name":"coredns","version":%q,"type":"application","properties":[{"name":"unknown:property","value":"preserved"}]}]}`, version))}
}
func TestSnapshots(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	first := artifact("1.11", at)
	id, err := s.Import(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Import(ctx, first)
	if err != nil || again != id {
		t.Fatalf("idempotency: %s %v", again, err)
	}
	for _, a := range []model.Artifact{artifact("1.12", at.Add(time.Hour)), artifact("1.13", at.Add(2*time.Hour), "kube-system")} {
		if _, err = s.Import(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Query(ctx, "SELECT scope, version FROM latest_inventory ORDER BY scope")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 2 || r.Rows[0][1] != "1.12" || r.Rows[1][1] != "1.13" {
		t.Fatalf("latest scope views: %+v", r.Rows)
	}
	r, err = s.Query(ctx, "SELECT count(*) FROM inventory_history")
	if err != nil || fmt.Sprint(r.Rows[0][0]) != "3" {
		t.Fatalf("history: %+v %v", r, err)
	}
	bad := artifact("bad", at)
	bad.KBOM = []byte(`{"bomFormat":"invalid"}`)
	if _, err = s.Import(ctx, bad); err == nil {
		t.Fatal("invalid input accepted")
	}
	r, err = s.Query(ctx, "SELECT count(*) FROM snapshots")
	if err != nil || fmt.Sprint(r.Rows[0][0]) != "3" {
		t.Fatalf("failed import changed snapshots: %+v %v", r, err)
	}
}
func TestReadOnlyQueries(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	allowed := []string{"SELECT 1", "SELECT name, count(*) FROM latest_inventory GROUP BY name", "WITH fleet AS (SELECT * FROM latest_inventory) SELECT count(*) FROM fleet", "SELECT 'hello;world'", "SELECT * FROM range(10001)", "SELECT row_number() OVER () FROM range(3)"}
	for _, q := range allowed {
		t.Run(q, func(t *testing.T) {
			r, err := s.Query(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(q, "10001") && (!r.Truncated || len(r.Rows) != 10000) {
				t.Fatalf("limit not applied: %d", len(r.Rows))
			}
		})
	}
	denied := []string{"DROP TABLE clusters", "SELECT 1; DELETE FROM clusters", "COPY clusters TO '/tmp/leak.csv'", "ATTACH '/tmp/evil.db'", "SET enable_external_access=true", "INSTALL httpfs", "LOAD httpfs", "SELECT nextval('x')", "SELECT setseed(0.1)", "SELECT * FROM read_csv('/etc/passwd')", "SELECT * FROM read_text('/etc/passwd')", "SELECT * FROM 'https://example.com/data.parquet'", "SELECT * FROM profiles", "SELECT * FROM duckdb_settings()", "SELECT query('DELETE FROM clusters')", "SELECT * FROM query_table('profiles')"}
	for _, q := range denied {
		t.Run(q, func(t *testing.T) {
			if _, err := s.Query(ctx, q); err == nil {
				t.Fatalf("unsafe query accepted: %s", q)
			}
		})
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Query(ctx, "SELECT * FROM range(999999999)"); err == nil {
		t.Fatal("cancelled context ignored")
	}
}
func TestReopenAndProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.duckdb")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.SaveProfile(context.Background(), model.Profile{Name: "scheduled", Cron: "0 */6 * * *", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ps, err := s.Profiles(context.Background())
	if err != nil || len(ps) != 1 || ps[0].ID != p.ID {
		t.Fatalf("profiles not retained: %+v %v", ps, err)
	}
}
