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

func Contexts(p model.Profile) ([]model.Cluster, error) {
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
	clusters := []model.Cluster{}
	for name, c := range cfg.Contexts {
		if !re.MatchString(name) {
			continue
		}
		cl, ok := cfg.Clusters[c.Cluster]
		if !ok {
			return nil, fmt.Errorf("context %q references a missing cluster", name)
		}
		clusters = append(clusters, model.Cluster{
			ID:             model.Key("kubeconfig-cluster", c.Cluster),
			Name:           c.Cluster,
			Context:        name,
			KubeconfigName: c.Cluster,
			Source:         source,
			Server:         cl.Server,
		})
	}
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })
	if len(clusters) == 0 {
		return nil, fmt.Errorf("no kubeconfig contexts match %q", p.ContextRegex)
	}
	return clusters, nil
}

type Collector interface {
	Collect(context.Context, model.Profile, model.Cluster) (model.Artifact, error)
}
type Trivy struct{}

func (Trivy) Collect(ctx context.Context, p model.Profile, c model.Cluster) (model.Artifact, error) {
	a := model.Artifact{Cluster: c, Namespaces: p.Namespaces, CollectedAt: time.Now().UTC(), TrivyVersion: model.TrivyVersion}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "kbomination-")
	if err != nil {
		return a, err
	}
	defer os.RemoveAll(dir)
	output := filepath.Join(dir, "kbom.json")
	args := []string{"exec", "trivy@" + model.TrivyVersion, "--", "trivy", "k8s", "--format", "cyclonedx", "--disable-node-collector", "--skip-images", "--scanners", "vuln", "--timeout", fmt.Sprintf("%ds", p.TimeoutSeconds), "--output", output}
	if len(p.Namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(p.Namespaces, ","))
	}
	contextName := c.Context
	if contextName == "" {
		contextName = c.Name
	}
	args = append(args, "--", contextName)
	cmd := exec.CommandContext(ctx, "mise", args...)
	// Use the resolved source for both explicit paths and merged KUBECONFIG sources.
	cmd.Env = append(os.Environ(), "KUBECONFIG="+c.Source)
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
