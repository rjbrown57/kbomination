package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rjbrown57/kbomination/internal/collect"
	"github.com/rjbrown57/kbomination/internal/model"
	"github.com/rjbrown57/kbomination/internal/server"
	"github.com/rjbrown57/kbomination/internal/store"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func root() *cobra.Command {
	var dbPath string
	var verbosity string
	root := &cobra.Command{Use: "kbomination", Short: "Collect and explore your Kubernetes fleet's KBOMs", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: func(cmd *cobra.Command, _ []string) error { return configureLogger(verbosity) }}
	root.PersistentFlags().StringVar(&dbPath, "db", ".data/kbomination.duckdb", "DuckDB database path")
	root.PersistentFlags().StringVar(&verbosity, "log-level", "info", "Log verbosity: info, debug, or trace")
	p := model.Profile{Name: "CLI collection"}
	contexts := &cobra.Command{Use: "contexts", Short: "List matching kubeconfig contexts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		clusters, err := collect.Contexts(p)
		if err != nil {
			return err
		}
		return printJSON(cmd.OutOrStdout(), clusters)
	}}
	selectionFlags(contexts, &p)
	root.AddCommand(contexts)
	cp := model.Profile{Name: "CLI collection"}
	var ingest bool
	var output, remote string
	collection := &cobra.Command{Use: "collect", Short: "Collect KBOMs and optionally ingest them", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := cp.Validate(); err != nil {
			return err
		}
		clusters, err := collect.Contexts(cp)
		if err != nil {
			return err
		}
		if remote != "" && !ingest {
			return fmt.Errorf("--server requires --ingest")
		}
		var s *store.Store
		if ingest && remote == "" {
			s, err = store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
		}
		runID := time.Now().UTC().Format("20060102T150405Z") + "-" + uuid.NewString()[:8]
		dir := filepath.Join(output, runID)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		manifest := model.Manifest{Version: 1, Entries: make([]model.ManifestEntry, len(clusters))}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 2)
		for i, c := range clusters {
			wg.Add(1)
			go func(i int, c model.Cluster) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				a, e := (collect.Trivy{}).Collect(cmd.Context(), cp, c)
				entry := model.ManifestEntry{Artifact: a, Status: "succeeded"}
				if e == nil {
					clusterDir := filepath.Join(dir, safePathSegment(c.Name)+"-"+c.ID)
					e = os.MkdirAll(clusterDir, 0700)
					if e == nil {
						entry.File = filepath.Join(safePathSegment(c.Name)+"-"+c.ID, time.Now().UTC().Format("20060102T150405Z")+"-"+uuid.NewString()[:8]+".cdx.json")
						e = os.WriteFile(filepath.Join(dir, entry.File), a.KBOM, 0600)
					}
				}
				if e == nil && ingest {
					e = importArtifact(cmd.Context(), s, remote, a)
				}
				entry.KBOM = nil
				if e != nil {
					entry.Status = "failed"
					entry.Error = e.Error()
				}
				manifest.Entries[i] = entry
			}(i, c)
		}
		wg.Wait()
		b, _ := json.MarshalIndent(manifest, "", "  ")
		path := filepath.Join(dir, "manifest.json")
		if err = os.WriteFile(path, b, 0600); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), path)
		for _, entry := range manifest.Entries {
			if entry.Status != "succeeded" {
				return fmt.Errorf("one or more clusters failed; see %s", path)
			}
		}
		return nil
	}}
	selectionFlags(collection, &cp)
	collection.Flags().BoolVar(&ingest, "ingest", false, "Also import successful KBOMs into DuckDB")
	collection.Flags().StringVar(&output, "output", "kboms", "Artifact output directory")
	collection.Flags().StringVar(&remote, "server", "", "Use the running local server for ingestion")
	root.AddCommand(collection)
	var manifestPath, source, clusterName, collected, version, importServer string
	var namespaces []string
	imp := &cobra.Command{Use: "import [kbom.json]", Short: "Import a collection manifest or an existing KBOM", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if (manifestPath == "") == (len(args) == 0) {
			return fmt.Errorf("provide exactly one KBOM path or --manifest")
		}
		var artifacts []model.Artifact
		if manifestPath != "" {
			raw, err := readLimited(manifestPath)
			if err != nil {
				return err
			}
			var m model.Manifest
			if err = json.Unmarshal(raw, &m); err != nil {
				return err
			}
			if m.Version != 1 {
				return fmt.Errorf("unsupported manifest version %d", m.Version)
			}
			for _, entry := range m.Entries {
				if entry.File == "" {
					continue
				}
				if !filepath.IsLocal(entry.File) {
					return fmt.Errorf("manifest file must be a relative path")
				}
				entry.KBOM, err = readLimited(filepath.Join(filepath.Dir(manifestPath), entry.File))
				if err != nil {
					return err
				}
				artifacts = append(artifacts, entry.Artifact)
			}
		} else {
			if source == "" || clusterName == "" || collected == "" {
				return fmt.Errorf("standalone import requires --source, --context and --collected-at (RFC3339)")
			}
			at, err := time.Parse(time.RFC3339Nano, collected)
			if err != nil {
				return err
			}
			raw, err := readLimited(args[0])
			if err != nil {
				return err
			}
			artifacts = append(artifacts, model.Artifact{Cluster: model.Cluster{Name: clusterName, Source: source}, Namespaces: namespaces, CollectedAt: at, TrivyVersion: version, KBOM: raw})
		}
		if len(artifacts) == 0 {
			return fmt.Errorf("manifest contains no KBOM files")
		}
		var s *store.Store
		var err error
		if importServer == "" {
			s, err = store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
		}
		for _, a := range artifacts {
			if err = importArtifact(cmd.Context(), s, importServer, a); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Imported", a.Cluster.Name, model.Scope(a.Namespaces))
		}
		return nil
	}}
	imp.Flags().StringVar(&manifestPath, "manifest", "", "Collection manifest path")
	imp.Flags().StringVar(&source, "source", "", "Original kubeconfig source identity")
	imp.Flags().StringVar(&clusterName, "context", "", "Original context name")
	imp.Flags().StringVar(&collected, "collected-at", "", "Collection timestamp (RFC3339)")
	imp.Flags().StringVar(&version, "trivy-version", "unknown", "Trivy version that generated the KBOM")
	imp.Flags().StringSliceVar(&namespaces, "namespaces", nil, "Selected namespaces; omitted means all")
	imp.Flags().StringVar(&importServer, "server", "", "Use the running local server for ingestion")
	root.AddCommand(imp)
	var listen string
	var allowNonLoopback bool
	serve := &cobra.Command{Use: "serve", Short: "Serve the frontend, API, and scheduler", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateListen(listen, allowNonLoopback); err != nil {
			return err
		}
		s, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()
		manager := server.NewManager(s)
		defer manager.Close()
		if err = manager.Recover(cmd.Context()); err != nil {
			return err
		}
		manager.Schedule()
		h := (&server.API{Store: s, Manager: manager}).Handler()
		srv := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "kbomination listening at http://"+listener.Addr().String())
		done := make(chan error, 1)
		go func() { done <- srv.Serve(listener) }()
		select {
		case err = <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-cmd.Context().Done():
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err = srv.Shutdown(ctx); err != nil {
				_ = srv.Close()
				return err
			}
		}
		return nil
	}}
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "Loopback address to listen on")
	serve.Flags().BoolVar(&allowNonLoopback, "allow-non-loopback", false, "Allow a non-loopback listening IP (for containers; publish ports only on localhost)")
	root.AddCommand(serve)
	return root
}
func configureLogger(level string) error {
	var l zapcore.Level
	switch level {
	case "info":
		l = zapcore.InfoLevel
	case "debug":
		l = zapcore.DebugLevel
	case "trace":
		l = zapcore.Level(-2)
	default:
		return fmt.Errorf("invalid --log-level %q (expected info, debug, or trace)", level)
	}
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(l)
	config.OutputPaths = []string{"stderr"}
	config.ErrorOutputPaths = []string{"stderr"}
	logger, err := config.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)
	return nil
}
func safePathSegment(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if out == "" {
		return "cluster"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}
func validateListen(listen string, allowNonLoopback bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("--listen must use an IP address")
	}
	if !ip.IsLoopback() && !allowNonLoopback {
		return fmt.Errorf("--listen must use a loopback IP address unless --allow-non-loopback is set")
	}
	return nil
}
func selectionFlags(cmd *cobra.Command, p *model.Profile) {
	cmd.Flags().StringVar(&p.Kubeconfig, "kubeconfig", "", "Kubeconfig path (defaults to KUBECONFIG loading rules)")
	cmd.Flags().StringVar(&p.ContextRegex, "context-regex", ".*", "Regex matched against context names")
	cmd.Flags().StringSliceVar(&p.Namespaces, "namespaces", nil, "Selected namespaces; omitted means all")
	cmd.Flags().IntVar(&p.TimeoutSeconds, "timeout", 900, "Per-cluster timeout in seconds")
}
func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, model.MaxKBOMBytes+1))
	if len(b) > model.MaxKBOMBytes {
		return nil, fmt.Errorf("file exceeds 64 MiB")
	}
	return b, err
}
func printJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func importArtifact(ctx context.Context, s *store.Store, remote string, a model.Artifact) error {
	if remote == "" {
		_, err := s.Import(ctx, a)
		return err
	}
	u, err := url.Parse(remote)
	if err != nil {
		return err
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("--server must be a local http URL")
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(remote, "/")+"/api/v1/import", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server import: %s: %s", resp.Status, string(b))
	}
	return nil
}
