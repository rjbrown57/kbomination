package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rjbrown57/kbomination/internal/model"
)

func TestCollectionCoveragePersistence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	old := artifact("old", at)
	oldID, err := s.Import(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	options := model.CollectionOptions{ExcludeNamespaces: []string{"z", "dev"}, ScanImages: true, OfflineScan: true}
	newer := artifact("new", at.Add(time.Hour))
	newer.Namespaces = []string{"prod"}
	newer.CollectionOptions = &options
	newID, err := s.Import(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	options.ExcludeNamespaces = []string{"dev", "z", "dev"}
	again, err := s.Import(ctx, newer)
	if err != nil || again != newID {
		t.Fatalf("idempotency: %s %v", again, err)
	}
	rows, err := s.Read(ctx, "SELECT id,scope,collection_options,coverage_description FROM latest_snapshots ORDER BY collected_at")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 2 || rows.Rows[0][0] != oldID || rows.Rows[0][1] != "all" || rows.Rows[0][2] != nil || rows.Rows[1][0] != newID {
		t.Fatalf("coverage replaced history: %+v", rows.Rows)
	}
	if !strings.Contains(fmt.Sprint(rows.Rows[1][2]), `"scan_images":true`) || !strings.Contains(fmt.Sprint(rows.Rows[1][3]), "offline dependency") {
		t.Fatal(rows.Rows[1])
	}
	p, err := s.SaveProfile(ctx, model.Profile{Name: "images", CollectionOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := s.Profiles(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].ID != p.ID || !profiles[0].CollectionOptions.ScanImages {
		t.Fatalf("profile roundtrip: %+v %v", profiles, err)
	}
	// Legacy profiles are normalized on read without requiring a rewrite.
	if err := s.Exec(ctx, "INSERT INTO profiles VALUES (?,?)", "legacy", `{"id":"legacy","name":"legacy"}`); err != nil {
		t.Fatal(err)
	}
	profiles, err = s.Profiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		if p.CollectionOptions.Parallel == nil || *p.CollectionOptions.Parallel != 5 {
			t.Fatal("missing legacy default")
		}
	}
	var backup bytes.Buffer
	if err := s.Export(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	b, _, err := DecodeBackup(bytes.NewReader(backup.Bytes()))
	if err != nil || b.Version != 2 {
		t.Fatalf("backup version: %d %v", b.Version, err)
	}
	restored := testStore(t)
	if _, err := restored.Restore(ctx, bytes.NewReader(backup.Bytes())); err != nil {
		t.Fatal(err)
	}
	rows, err = restored.Read(ctx, "SELECT collection_options,scope,namespaces FROM snapshots WHERE id=?", newID)
	if err != nil || len(rows.Rows) != 1 || (!strings.Contains(fmt.Sprint(rows.Rows[0][0]), `"scan_images":true`) || rows.Rows[0][2] != `["prod"]`) {
		t.Fatalf("restore lost coverage: %+v %v", rows, err)
	}
}

func TestMigrateVersionTwoAndRestoreLegacyBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.duckdb")
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := strings.ReplaceAll(schema, ", collection_options VARCHAR, coverage_description VARCHAR, namespaces VARCHAR", "")
	legacySchema = strings.ReplaceAll(legacySchema, "VALUES (3)", "VALUES (2)")
	if _, err = db.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO clusters(id,name,source,server) VALUES ('cluster','old','',''); INSERT INTO snapshots(id,cluster_id,scope,collected_at,trivy_version,sha256,raw_json) VALUES ('snapshot','cluster','all',current_timestamp,'unknown','digest','{}'); INSERT INTO profiles VALUES ('old','{\"id\":\"old\",\"name\":\"old\"}')"); err != nil {
		t.Fatal(err)
	}
	// Generate the legacy backup while the database still has the original columns.
	oldStore := &Store{DB: db, Path: path}
	var exported bytes.Buffer
	if err := oldStore.Export(context.Background(), &exported); err != nil {
		t.Fatal(err)
	}
	var legacyBackup Backup
	if err := json.Unmarshal(exported.Bytes(), &legacyBackup); err != nil {
		t.Fatal(err)
	}
	legacyBackup.Version = 1
	raw, err := json.Marshal(legacyBackup)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := migrated.Read(context.Background(), "SELECT id,scope,collection_options FROM latest_snapshots")
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "snapshot" || rows.Rows[0][1] != "all" || rows.Rows[0][2] != nil {
		t.Fatalf("migration changed legacy data: %+v %v", rows, err)
	}
	var version int
	if err := migrated.DB.QueryRow("SELECT max(version) FROM schema_version").Scan(&version); err != nil || version != 3 {
		t.Fatalf("version %d: %v", version, err)
	}
	if err = migrated.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if _, err = migrated.Restore(context.Background(), bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	rows, err = migrated.Read(context.Background(), "SELECT id,collection_options FROM snapshots")
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][1] != nil {
		t.Fatalf("legacy restore: %+v %v", rows, err)
	}
	// Future backups must be rejected, even with an otherwise valid checksum.
	legacyBackup.Version = 3
	sum := sha256.Sum256(legacyBackup.Data)
	legacyBackup.SHA256 = hex.EncodeToString(sum[:])
	raw, _ = json.Marshal(legacyBackup)
	if _, _, err = DecodeBackup(bytes.NewReader(raw)); err == nil {
		t.Fatal("future backup accepted")
	}
}
