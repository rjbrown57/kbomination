package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupVersion = 1

var backupTables = []string{"fleets", "clusters", "cluster_metadata", "component_catalog", "snapshots", "components", "component_properties", "dependencies", "component_catalog_observations", "profiles", "runs", "run_results", "app_settings"}

type backupTable struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}
type backupData struct {
	Tables map[string]backupTable `json:"tables"`
}
type Backup struct {
	Format  string          `json:"format"`
	Version int             `json:"version"`
	SHA256  string          `json:"sha256"`
	Data    json.RawMessage `json:"data"`
}

func (s *Store) Export(ctx context.Context, w io.Writer) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	data := backupData{Tables: map[string]backupTable{}}
	for _, table := range backupTables {
		rows, e := tx.QueryContext(ctx, "SELECT * FROM "+table)
		if e != nil {
			return e
		}
		cols, e := rows.Columns()
		if e != nil {
			rows.Close()
			return e
		}
		item := backupTable{Columns: cols, Rows: [][]any{}}
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if e = rows.Scan(dest...); e != nil {
				rows.Close()
				return e
			}
			item.Rows = append(item.Rows, values)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		rows.Close()
		data.Tables[table] = item
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	return json.NewEncoder(w).Encode(Backup{Format: "kbomination-backup", Version: backupVersion, SHA256: hex.EncodeToString(sum[:]), Data: raw})
}

func DecodeBackup(r io.Reader) (Backup, backupData, error) {
	var b Backup
	var data backupData
	d := json.NewDecoder(io.LimitReader(r, 1<<30))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return b, data, err
	}
	if b.Format != "kbomination-backup" || b.Version != backupVersion {
		return b, data, fmt.Errorf("unsupported backup format or version")
	}
	sum := sha256.Sum256(b.Data)
	if hex.EncodeToString(sum[:]) != b.SHA256 {
		return b, data, fmt.Errorf("backup checksum mismatch")
	}
	dec := json.NewDecoder(strings.NewReader(string(b.Data)))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return b, data, err
	}
	for _, table := range backupTables {
		if _, ok := data.Tables[table]; !ok {
			return b, data, fmt.Errorf("backup is missing table %q", table)
		}
	}
	return b, data, nil
}

func (s *Store) Restore(ctx context.Context, r io.Reader) (map[string]int, error) {
	_, data, err := DecodeBackup(r)
	if err != nil {
		return nil, err
	}
	// Save a durable recovery archive before opening the replacement transaction.
	recovery := s.Path + ".recovery-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	if s.Path != "" {
		f, e := os.OpenFile(recovery, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		e = s.Export(ctx, f)
		closeErr := f.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for i := len(backupTables) - 1; i >= 0; i-- {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+backupTables[i]); err != nil {
			return nil, err
		}
	}
	counts := map[string]int{}
	for _, table := range backupTables {
		item := data.Tables[table]
		if len(item.Columns) == 0 && len(item.Rows) > 0 {
			return nil, fmt.Errorf("backup table %q has rows without columns", table)
		}
		for _, row := range item.Rows {
			if len(row) != len(item.Columns) {
				return nil, fmt.Errorf("backup row has wrong column count in %q", table)
			}
			quoted := make([]string, len(item.Columns))
			placeholders := make([]string, len(item.Columns))
			for i, c := range item.Columns {
				if !validColumnName(c) {
					return nil, fmt.Errorf("invalid column name in backup")
				}
				quoted[i] = "\"" + c + "\""
				placeholders[i] = "?"
			}
			q := "INSERT INTO " + table + " (" + strings.Join(quoted, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")"
			if _, err = tx.ExecContext(ctx, q, row...); err != nil {
				return nil, fmt.Errorf("restore %s: %w", table, err)
			}
			counts[table]++
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE run_results SET status='interrupted',error='Restored backup contained an unfinished run' WHERE status IN ('queued','running')"); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE runs SET status='interrupted',finished_at=current_timestamp WHERE status='running'"); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO app_settings VALUES ('scheduler_paused','true') ON CONFLICT(key) DO UPDATE SET value='true'"); err != nil {
		return nil, err
	}
	return counts, tx.Commit()
}
func validColumnName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}
func (b Backup) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.Data), 0600)
}
