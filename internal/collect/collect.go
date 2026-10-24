package collect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rjbrown57/kbomination/internal/model"
	"k8s.io/client-go/tools/clientcmd"
)

// Target pairs a cluster with an access context for this collection only.
type Target struct {
	model.Cluster
	Context string `json:"context"`
}

func Contexts(p model.Profile) ([]Target, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if p.Kubeconfig != "" {
		rules.ExplicitPath = p.Kubeconfig
	}
	cfg, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	paths := rules.GetLoadingPrecedence()
	if rules.ExplicitPath != "" {
		paths = []string{rules.ExplicitPath}
	}
	for i, p := range paths {
		paths[i], err = filepath.Abs(p)
		if err != nil {
			return nil, err
		}
	}
	source := strings.Join(paths, string(os.PathListSeparator))
	re := regexp.MustCompile(p.ContextRegex)
	clusters := []Target{}
	for name, c := range cfg.Contexts {
		if !re.MatchString(name) {
			continue
		}
		cl, ok := cfg.Clusters[c.Cluster]
		if !ok {
			return nil, fmt.Errorf("context %q references a missing cluster", name)
		}
		clusters = append(clusters, Target{
			Cluster: model.Cluster{ID: model.ClusterID(c.Cluster), Name: c.Cluster, Source: source, Server: cl.Server},
			Context: name,
		})
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Name == clusters[j].Name {
			return clusters[i].Context < clusters[j].Context
		}
		return clusters[i].Name < clusters[j].Name
	})
	if len(clusters) == 0 {
		return nil, fmt.Errorf("no kubeconfig contexts match %q", p.ContextRegex)
	}
	return clusters, nil
}

// Clusters selects one target per cluster. If several matching contexts refer
// to the same cluster, choose the first context alphabetically.
func Clusters(p model.Profile) ([]Target, error) {
	targets, err := Contexts(p)
	if err != nil {
		return nil, err
	}
	unique := make([]Target, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		if !seen[target.ID] {
			unique = append(unique, target)
			seen[target.ID] = true
		}
	}
	return unique, nil
}

type Collector interface {
	Collect(context.Context, model.Profile, Target) (model.Artifact, error)
}
type Trivy struct{}

func (Trivy) Collect(ctx context.Context, p model.Profile, c Target) (model.Artifact, error) {
	if err := p.Validate(); err != nil {
		return model.Artifact{}, err
	}
	a := model.Artifact{Cluster: c.Cluster, Namespaces: p.Namespaces, CollectionOptions: &p.CollectionOptions, CollectedAt: time.Now().UTC(), TrivyVersion: model.TrivyVersion}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "kbomination-")
	if err != nil {
		return a, err
	}
	defer os.RemoveAll(dir)
	output := filepath.Join(dir, "kbom.json")
	args := []string{"exec", "trivy@" + model.TrivyVersion, "--", "trivy", "k8s", "--config=", "--format", "cyclonedx", "--disable-node-collector=true", "--scanners", "vuln", "--timeout", fmt.Sprintf("%ds", p.TimeoutSeconds), "--output", output}
	args = append(args, trivyOptions(p.CollectionOptions)...)
	if len(p.Namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(p.Namespaces, ","))
	}
	if c.Context == "" {
		return a, fmt.Errorf("collection target requires an access context")
	}
	args = append(args, "--", c.Context)
	cmd := exec.CommandContext(ctx, "mise", args...)
	// Use the resolved source for both explicit paths and merged KUBECONFIG sources.
	cmd.Env = append(trivyEnvironment(os.Environ()), "KUBECONFIG="+c.Source)
	// Do not persist subprocess stderr: credential plugins may print credentials.
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return a, fmt.Errorf("collection cancelled or timed out: %w", ctx.Err())
		}
		return a, fmt.Errorf("Trivy collection failed (%v); check kubeconfig credentials, connectivity, and list permissions", err)
	}
	f, err := os.Stat(output)
	if err != nil {
		return a, fmt.Errorf("Trivy produced no KBOM: %w", err)
	}
	if f.Size() > model.MaxKBOMBytes {
		return a, fmt.Errorf("KBOM exceeds 64 MiB limit")
	}
	a.KBOM, err = os.ReadFile(output)
	return a, err
}

func trivyOptions(o model.CollectionOptions) []string {
	args := []string{fmt.Sprintf("--skip-images=%t", !o.ScanImages), "--qps", fmt.Sprint(*o.QPS), "--burst", fmt.Sprint(*o.Burst), "--parallel", fmt.Sprint(*o.Parallel), fmt.Sprintf("--skip-db-update=%t", o.SkipDBUpdate), fmt.Sprintf("--skip-java-db-update=%t", o.SkipJavaDBUpdate), fmt.Sprintf("--offline-scan=%t", o.OfflineScan)}
	for _, item := range []struct {
		flag   string
		values []string
	}{
		{"--exclude-namespaces", o.ExcludeNamespaces}, {"--include-kinds", o.IncludeKinds}, {"--exclude-kinds", o.ExcludeKinds},
		{"--image-src", o.ImageSrc}, {"--db-repository", o.DBRepository}, {"--java-db-repository", o.JavaDBRepository},
	} {
		if len(item.values) > 0 {
			args = append(args, item.flag, strings.Join(item.values, ","))
		}
	}
	if o.CacheDir != "" {
		args = append(args, "--cache-dir", o.CacheDir)
	}
	if o.CACert != "" {
		args = append(args, "--cacert", o.CACert)
	}
	return args
}

// Preserve registry credentials and the normal process environment (including
// kubeconfig exec-plugin credentials and proxies), but do not let ambient
// Trivy options silently change the recorded collection coverage.
func trivyEnvironment(env []string) []string {
	out := make([]string, 0, len(env))
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if key == "KUBECONFIG" {
			continue
		}
		if strings.HasPrefix(key, "TRIVY_") {
			switch key {
			case "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "TRIVY_TOKEN", "TRIVY_GITHUB_TOKEN":
			default:
				continue
			}
		}
		out = append(out, value)
	}
	return out
}
