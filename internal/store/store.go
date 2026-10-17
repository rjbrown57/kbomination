package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/google/uuid"
	"github.com/rjbrown57/kbomination/internal/kbom"
	"github.com/rjbrown57/kbomination/internal/model"
)

//go:embed schema.sql
var schema string

type Store struct {
	DB    *sql.DB
	write sync.Mutex
}

func Open(path string) (*Store, error) {
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	if err = db.Ping(); err != nil {
		return fail(fmt.Errorf("open DuckDB (stop other owners or use --server): %w", err))
	}
	var version int
	err = db.QueryRow("SELECT coalesce(max(version),0) FROM schema_version").Scan(&version)
	if err == nil && version > 1 {
		return fail(fmt.Errorf("database schema %d is newer than supported schema 1", version))
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	if _, err = tx.Exec(schema); err != nil {
		tx.Rollback()
		return fail(err)
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	// The application itself only uses parameterized in-memory data ingestion.
	for _, q := range []string{"SET enable_external_access=false", "SET autoinstall_known_extensions=false", "SET autoload_known_extensions=false", "SET memory_limit='512MB'", "SET threads=2", "SET lock_configuration=true"} {
		if _, err = db.Exec(q); err != nil {
			return fail(err)
		}
	}
	return &Store{DB: db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) Import(ctx context.Context, a model.Artifact) (string, error) {
	if a.Cluster.Name == "" || a.Cluster.Source == "" {
		return "", fmt.Errorf("cluster name and kubeconfig source are required")
	}
	if len(a.KBOM) > model.MaxKBOMBytes {
		return "", fmt.Errorf("KBOM exceeds 64 MiB limit")
	}
	p := model.Profile{Name: "import", Namespaces: a.Namespaces}
	if err := p.Validate(); err != nil {
		return "", err
	}
	a.Namespaces = p.Namespaces
	a.Cluster.ID = model.Key(a.Cluster.Source, a.Cluster.Name)
	if a.CollectedAt.IsZero() {
		return "", fmt.Errorf("collected_at is required")
	}
	parsed, err := kbom.Parse(a.KBOM)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(a.KBOM)
	digest := hex.EncodeToString(hash[:])
	// Re-importing the same artifact is idempotent, but later identical collections remain historical snapshots.
	id := model.Key(a.Cluster.ID, model.Scope(a.Namespaces), a.CollectedAt.UTC().Format(time.RFC3339Nano), digest)
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var exists int
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM snapshots WHERE id=?", id).Scan(&exists)
	if err != nil {
		return "", err
	}
	if exists > 0 {
		return id, nil
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO clusters(id,name,source,server) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET server=excluded.server", a.Cluster.ID, a.Cluster.Name, a.Cluster.Source, a.Cluster.Server)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO snapshots(id,cluster_id,scope,collected_at,trivy_version,sha256,raw_json) VALUES (?,?,?,?,?,?,?)", id, a.Cluster.ID, model.Scope(a.Namespaces), a.CollectedAt, a.TrivyVersion, digest, string(a.KBOM))
	if err != nil {
		return "", err
	}
	componentStmt, err := tx.PrepareContext(ctx, "INSERT INTO components VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return "", err
	}
	defer componentStmt.Close()
	propertyStmt, err := tx.PrepareContext(ctx, "INSERT INTO component_properties VALUES (?,?,?,?)")
	if err != nil {
		return "", err
	}
	defer propertyStmt.Close()
	for _, c := range parsed.Items {
		_, err = componentStmt.ExecContext(ctx, id, c.Ref, nullable(c.Parent), nullable(c.Type), nullable(c.Name), nullable(c.Version), nullable(c.PURL), nullable(string(c.Hashes)), nullable(c.Namespace), nullable(c.Kind), nullable(c.Resource), c.Category)
		if err != nil {
			return "", err
		}
		for _, p := range c.Properties {
			if _, err = propertyStmt.ExecContext(ctx, id, c.Ref, p.Name, p.Value); err != nil {
				return "", err
			}
		}
	}
	for _, d := range parsed.Edges {
		for _, target := range d.DependsOn {
			if _, err = tx.ExecContext(ctx, "INSERT INTO dependencies VALUES (?,?,?)", id, d.Ref, target); err != nil {
				return "", err
			}
		}
	}
	return id, tx.Commit()
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) Profiles(ctx context.Context) ([]model.Profile, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT body FROM profiles ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Profile{}
	for rows.Next() {
		var b string
		var p model.Profile
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) SaveProfile(ctx context.Context, p model.Profile) (model.Profile, error) {
	if err := p.Validate(); err != nil {
		return p, err
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	b, _ := json.Marshal(p)
	s.write.Lock()
	defer s.write.Unlock()
	_, err := s.DB.ExecContext(ctx, "INSERT INTO profiles VALUES (?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", p.ID, string(b))
	return p, err
}
func (s *Store) DeleteProfile(ctx context.Context, id string) error {
	s.write.Lock()
	defer s.write.Unlock()
	_, err := s.DB.ExecContext(ctx, "DELETE FROM profiles WHERE id=?", id)
	return err
}
func (s *Store) Exec(ctx context.Context, q string, args ...any) error {
	s.write.Lock()
	defer s.write.Unlock()
	_, err := s.DB.ExecContext(ctx, q, args...)
	return err
}

type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type Result struct {
	Columns    []Column `json:"columns"`
	Rows       [][]any  `json:"rows"`
	Truncated  bool     `json:"truncated"`
	DurationMS int64    `json:"duration_ms"`
}

func (s *Store) Read(ctx context.Context, q string, args ...any) (Result, error) {
	start := time.Now()
	result := Result{Columns: []Column{}, Rows: [][]any{}}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	cols, err := rows.ColumnTypes()
	if err != nil {
		return result, err
	}
	for _, c := range cols {
		result.Columns = append(result.Columns, Column{c.Name(), c.DatabaseTypeName()})
	}
	for rows.Next() {
		if len(result.Rows) >= 10000 {
			result.Truncated = true
			break
		}
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return result, err
		}
		result.Rows = append(result.Rows, values)
	}
	result.DurationMS = time.Since(start).Milliseconds()
	return result, rows.Err()
}
