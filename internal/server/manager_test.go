package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rjbrown57/kbomination/internal/collect"
	"github.com/rjbrown57/kbomination/internal/model"
	"github.com/rjbrown57/kbomination/internal/store"
)

type clusterCollector struct{ targets []collect.Target }

func (c *clusterCollector) Collect(_ context.Context, _ model.Profile, target collect.Target) (model.Artifact, error) {
	c.targets = append(c.targets, target)
	return model.Artifact{Cluster: target.Cluster, CollectedAt: time.Now().UTC(), KBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)}, nil
}

func TestRunCollectsClusterOnceAcrossContexts(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.WriteFile(config, []byte(`apiVersion: v1
kind: Config
clusters:
- name: production
  cluster:
    server: https://example.invalid
contexts:
- name: admin
  context:
    cluster: production
- name: reader
  context:
    cluster: production
`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(dir, "db.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := NewManager(s)
	defer m.Close()
	collector := &clusterCollector{}
	m.Collector = collector
	id, err := m.Start(model.Profile{Name: "fleet", Kubeconfig: config})
	if err != nil {
		t.Fatal(err)
	}
	m.wg.Wait()
	if len(collector.targets) != 1 || collector.targets[0].Name != "production" || collector.targets[0].Context != "admin" {
		t.Fatalf("wrong targets: %+v", collector.targets)
	}
	rows, err := s.Read(context.Background(), "SELECT cluster_id,cluster_name,status FROM run_results WHERE run_id=?", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 1 || rows.Rows[0][0] != model.ClusterID("production") || rows.Rows[0][1] != "production" || rows.Rows[0][2] != "succeeded" {
		t.Fatalf("wrong run results: %+v", rows.Rows)
	}
	rows, err = s.Read(context.Background(), "SELECT status FROM runs WHERE id=?", id)
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "succeeded" {
		t.Fatalf("run failed: %+v %v", rows.Rows, err)
	}
}
