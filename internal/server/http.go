package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rjbrown57/kbomination/internal/collect"
	"github.com/rjbrown57/kbomination/internal/model"
	"github.com/rjbrown57/kbomination/internal/store"
	"github.com/rjbrown57/kbomination/web"
	"sigs.k8s.io/yaml"
)

type API struct {
	Store   *store.Store
	Manager *Manager
	Version string
	Commit  string
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) { send(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]string{"version": a.Version, "commit": a.Commit})
	})
	mux.HandleFunc("POST /api/v1/contexts", func(w http.ResponseWriter, r *http.Request) {
		var p model.Profile
		if !decode(w, r, &p) {
			return
		}
		p.Name = "preview"
		cs, err := collect.Contexts(p)
		respond(w, cs, err)
	})
	mux.HandleFunc("GET /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		ps, err := a.Store.Profiles(r.Context())
		respond(w, ps, err)
	})
	mux.HandleFunc("POST /api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		var p model.Profile
		if !decode(w, r, &p) {
			return
		}
		p, err := a.Store.SaveProfile(r.Context(), p)
		respond(w, p, err)
	})
	mux.HandleFunc("DELETE /api/v1/profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		err := a.Store.DeleteProfile(r.Context(), r.PathValue("id"))
		respond(w, map[string]bool{"deleted": err == nil}, err)
	})
	mux.HandleFunc("POST /api/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProfileID string `json:"profile_id"`
		}
		if !decode(w, r, &req) {
			return
		}
		ps, err := a.Store.Profiles(r.Context())
		if err != nil {
			respond(w, nil, err)
			return
		}
		for _, p := range ps {
			if p.ID == req.ProfileID {
				id, err := a.Manager.Start(p)
				if errors.Is(err, ErrOverlap) {
					sendError(w, 409, err)
					return
				}
				if err != nil {
					respond(w, nil, err)
					return
				}
				send(w, 202, map[string]string{"id": id})
				return
			}
		}
		sendError(w, 404, fmt.Errorf("profile not found"))
	})
	mux.HandleFunc("GET /api/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT * FROM runs ORDER BY started_at DESC LIMIT 100")
	})
	mux.HandleFunc("GET /api/v1/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT * FROM run_results WHERE run_id=? ORDER BY cluster_name", r.PathValue("id"))
	})
	mux.HandleFunc("POST /api/v1/import", func(w http.ResponseWriter, r *http.Request) {
		var artifact model.Artifact
		if !decode(w, r, &artifact) {
			return
		}
		id, err := a.Store.Import(r.Context(), artifact)
		respond(w, map[string]string{"id": id}, err)
	})
	mux.HandleFunc("GET /api/v1/clusters", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT c.*, coalesce(m.labels,'{}') labels,coalesce(m.annotations,'{}') annotations,coalesce(m.notes,'') notes,max(s.collected_at) AS last_collected_at, count(DISTINCT s.id) AS snapshots FROM clusters c LEFT JOIN cluster_metadata m ON m.cluster_id=c.id LEFT JOIN snapshots s ON c.id=s.cluster_id GROUP BY ALL ORDER BY c.name")
	})
	mux.HandleFunc("GET /api/v1/catalog", func(w http.ResponseWriter, r *http.Request) {
		a.catalog(w, r)
	})
	mux.HandleFunc("GET /api/v1/catalog/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT * FROM component_inventory WHERE component_id=?", r.PathValue("id"))
	})
	mux.HandleFunc("GET /api/v1/catalog/{id}/clusters", func(w http.ResponseWriter, r *http.Request) {
		limit, offset, err := pagination(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		name := r.URL.Query().Get("name")
		q := "WITH cluster_matches AS (SELECT DISTINCT cl.id,cl.name FROM component_catalog_observations co JOIN snapshots s ON s.id=co.snapshot_id JOIN clusters cl ON cl.id=s.cluster_id WHERE co.component_id=? AND (?='' OR contains(lower(cl.name),lower(?)))) SELECT id,name,count(*) OVER() AS total_count FROM cluster_matches ORDER BY name LIMIT ? OFFSET ?"
		a.read(w, r, q, r.PathValue("id"), name, name, limit, offset)
	})
	mux.HandleFunc("PUT /api/v1/metadata/{kind}/{id}", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Labels          map[string]string `json:"labels"`
			Annotations     map[string]string `json:"annotations"`
			LabelsYAML      *string           `json:"labels_yaml"`
			AnnotationsYAML *string           `json:"annotations_yaml"`
			Notes           string            `json:"notes"`
		}
		if !decode(w, r, &input) {
			return
		}
		m := store.Metadata{Labels: input.Labels, Annotations: input.Annotations, Notes: input.Notes}
		if input.LabelsYAML != nil {
			if err := yaml.Unmarshal([]byte(*input.LabelsYAML), &m.Labels); err != nil {
				respond(w, nil, fmt.Errorf("invalid labels YAML: %w", err))
				return
			}
		}
		if input.AnnotationsYAML != nil {
			if err := yaml.Unmarshal([]byte(*input.AnnotationsYAML), &m.Annotations); err != nil {
				respond(w, nil, fmt.Errorf("invalid annotations YAML: %w", err))
				return
			}
		}
		err := a.Store.SetMetadata(r.Context(), r.PathValue("kind"), r.PathValue("id"), m)
		respond(w, map[string]bool{"updated": err == nil}, err)
	})
	mux.HandleFunc("GET /api/v1/settings", func(w http.ResponseWriter, r *http.Request) { v, e := a.Store.Settings(r.Context()); respond(w, v, e) })
	mux.HandleFunc("PUT /api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		var v map[string]string
		if !decode(w, r, &v) {
			return
		}
		e := a.Store.SaveSettings(r.Context(), v)
		respond(w, map[string]bool{"saved": e == nil}, e)
	})
	mux.HandleFunc("GET /api/v1/backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="kbomination-backup.json"`)
		if err := a.Store.Export(r.Context(), w); err != nil {
			sendError(w, 500, err)
		}
	})
	mux.HandleFunc("POST /api/v1/backup/preview", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
		_, data, err := store.DecodeBackup(r.Body)
		if err != nil {
			sendError(w, 400, err)
			return
		}
		counts := map[string]int{}
		for table, values := range data.Tables {
			counts[table] = len(values.Rows)
		}
		send(w, 200, map[string]any{"valid": true, "version": 1, "records": counts, "replace_requires_confirmation": true})
	})
	mux.HandleFunc("POST /api/v1/backup/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("confirm") != "true" {
			sendError(w, 400, fmt.Errorf("explicit confirmation is required"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
		var counts map[string]int
		var err error
		if a.Manager != nil {
			counts, err = a.Manager.Restore(r.Context(), r.Body)
		} else {
			counts, err = a.Store.Restore(r.Context(), r.Body)
		}
		if errors.Is(err, ErrOverlap) || errors.Is(err, ErrMaintenance) {
			sendError(w, 409, err)
			return
		}
		respond(w, map[string]any{"restored": err == nil, "records": counts}, err)
	})
	mux.HandleFunc("GET /api/v1/snapshots", func(w http.ResponseWriter, r *http.Request) {
		q := "SELECT id,cluster_id,scope,collected_at,imported_at,trivy_version,sha256 FROM snapshots WHERE 1=1"
		args := []any{}
		for _, key := range []string{"cluster_id", "scope"} {
			if v := r.URL.Query().Get(key); v != "" {
				q += " AND " + key + "=?"
				args = append(args, v)
			}
		}
		limit, offset, err := pagination(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		q += " ORDER BY collected_at DESC LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
		a.read(w, r, q, args...)
	})
	mux.HandleFunc("GET /api/v1/snapshots/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT * FROM snapshots WHERE id=?", r.PathValue("id"))
	})
	mux.HandleFunc("GET /api/v1/components", a.components)
	mux.HandleFunc("GET /api/v1/components/{snapshot}/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		snapshot, ref := r.PathValue("snapshot"), r.PathValue("ref")
		component, e := a.Store.Read(ctx, "SELECT * FROM components WHERE snapshot_id=? AND ref=?", snapshot, ref)
		if e != nil {
			respond(w, nil, e)
			return
		}
		props, e := a.Store.Read(ctx, "SELECT name,value FROM component_properties WHERE snapshot_id=? AND ref=?", snapshot, ref)
		if e != nil {
			respond(w, nil, e)
			return
		}
		deps, e := a.Store.Read(ctx, "SELECT ref,depends_on FROM dependencies WHERE snapshot_id=? AND (ref=? OR depends_on=?)", snapshot, ref, ref)
		respond(w, map[string]any{"component": component, "properties": props, "dependencies": deps}, e)
	})
	mux.HandleFunc("GET /api/v1/schema", func(w http.ResponseWriter, r *http.Request) {
		a.read(w, r, "SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='main' AND table_name NOT IN ('profiles','schema_version') ORDER BY table_name,ordinal_position")
	})
	mux.HandleFunc("POST /api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SQL string `json:"sql"`
		}
		if !decode(w, r, &req) {
			return
		}
		result, err := a.Store.Query(r.Context(), req.SQL)
		respond(w, result, err)
	})
	assets, _ := fs.Sub(web.Assets, "dist")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			sendError(w, 404, fmt.Errorf("API endpoint not found"))
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		if _, err := fs.Stat(assets, "index.html"); err != nil {
			http.Error(w, "Frontend not built. Run mise run build:web, then rebuild/restart the server.", 503)
			return
		}
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
	})
	return localOnly(mux)
}
func (a *API) read(w http.ResponseWriter, r *http.Request, q string, args ...any) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.Store.Read(ctx, q, args...)
	respond(w, result, err)
}
func (a *API) components(w http.ResponseWriter, r *http.Request) {
	view := "latest_inventory"
	if r.URL.Query().Get("snapshot_id") != "" || r.URL.Query().Get("history") == "true" {
		view = "inventory_history"
	}
	q := "SELECT inv.*,co.component_id FROM " + view + " inv LEFT JOIN component_catalog_observations co ON co.snapshot_id=inv.snapshot_id AND co.ref=inv.ref WHERE 1=1"
	args := []any{}
	for _, key := range []string{"cluster_id", "scope", "namespace", "category", "version", "snapshot_id"} {
		if v := r.URL.Query().Get(key); v != "" {
			q += " AND inv." + key + "=?"
			args = append(args, v)
		}
	}
	if v := r.URL.Query().Get("name"); v != "" {
		q += " AND contains(lower(inv.name),lower(?))"
		args = append(args, v)
	}
	limit, offset, err := pagination(r)
	if err != nil {
		respond(w, nil, err)
		return
	}
	q += " ORDER BY inv.cluster_name,inv.collected_at DESC,inv.name,inv.ref LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	a.read(w, r, q, args...)
}
func (a *API) catalog(w http.ResponseWriter, r *http.Request) {
	q := "SELECT * FROM component_inventory WHERE 1=1"
	args := []any{}
	if v := r.URL.Query().Get("name"); v != "" {
		q += " AND contains(lower(name),lower(?))"
		args = append(args, v)
	}
	if v := r.URL.Query().Get("cluster_id"); v != "" {
		q += " AND list_contains(cluster_ids,?)"
		args = append(args, v)
	}
	if v := r.URL.Query().Get("version"); v != "" {
		q += " AND list_contains(versions,?)"
		args = append(args, v)
	}
	if v := r.URL.Query().Get("label"); v != "" {
		q += " AND contains(labels,?)"
		args = append(args, v)
	}
	limit, offset, err := pagination(r)
	if err != nil {
		respond(w, nil, err)
		return
	}
	q += " ORDER BY name,component_id LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	a.read(w, r, q, args...)
}
func pagination(r *http.Request) (int, int, error) {
	limit, offset := 100, 0
	var err error
	if s := r.URL.Query().Get("limit"); s != "" {
		limit, err = strconv.Atoi(s)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit")
		}
	}
	if s := r.URL.Query().Get("offset"); s != "" {
		offset, err = strconv.Atoi(s)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset")
		}
	}
	if limit < 1 || limit > 1000 || offset < 0 {
		return 0, 0, fmt.Errorf("limit must be 1–1000 and offset nonnegative")
	}
	return limit, offset, nil
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, model.MaxKBOMBytes+1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		sendError(w, 400, err)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		sendError(w, 400, fmt.Errorf("expected one JSON object"))
		return false
	}
	return true
}
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func sendError(w http.ResponseWriter, status int, err error) {
	send(w, status, map[string]string{"error": err.Error()})
}
func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		sendError(w, 400, err)
		return
	}
	send(w, 200, v)
}
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			sendError(w, 403, fmt.Errorf("local Host required"))
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || u.Scheme != "http" {
				sendError(w, 403, fmt.Errorf("same-origin request required"))
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			sendError(w, 403, fmt.Errorf("cross-site request denied"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
