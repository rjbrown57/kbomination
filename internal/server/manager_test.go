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

type clusterCollector struct {
	targets  []collect.Target
	profiles []model.Profile
}

func (c *clusterCollector) Collect(_ context.Context, p model.Profile, target collect.Target) (model.Artifact, error) {
	c.targets = append(c.targets, target)
	c.profiles = append(c.profiles, p)
	return model.Artifact{CollectionOptions: &p.CollectionOptions, Namespaces: p.Namespaces, Cluster: target.Cluster, CollectedAt: time.Now().UTC(), KBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)}, nil
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

func TestScheduledCollectionOptions(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parallel := 0
	p, err := s.SaveProfile(context.Background(), model.Profile{Name: "scheduled", Enabled: true, Cron: "* * * * *", CollectionOptions: model.CollectionOptions{ScanImages: true, Parallel: &parallel, ExcludeNamespaces: []string{"dev"}, ImageSrc: []string{"remote"}, CacheDir: "/cache"}})
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(s)
	defer m.Close()
	collector := &clusterCollector{}
	m.Collector = collector
	m.Discover = func(got model.Profile) ([]collect.Target, error) {
		if got.ID != p.ID {
			t.Errorf("wrong profile: %s", got.ID)
		}
		return []collect.Target{{Cluster: model.Cluster{ID: model.ClusterID("test"), Name: "test"}, Context: "test"}}, nil
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if err = m.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err = m.Tick(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	m.wg.Wait()
	if len(collector.profiles) != 1 {
		t.Fatalf("collections: %d", len(collector.profiles))
	}
	got := collector.profiles[0].CollectionOptions
	if !got.ScanImages || *got.Parallel != 0 || got.ImageSrc[0] != "remote" || got.CacheDir != "/cache" {
		t.Fatalf("settings lost: %+v", got)
	}
	rows, err := s.Read(context.Background(), "SELECT scope FROM snapshots")
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != model.CollectionScope(p.Namespaces, &p.CollectionOptions) {
		t.Fatalf("wrong snapshot coverage: %+v %v", rows, err)
	}
}
