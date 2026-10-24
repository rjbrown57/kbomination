package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rjbrown57/kbomination/internal/model"
)

func TestContexts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	config := `apiVersion: v1
kind: Config
clusters:
- name: shared
  cluster:
    server: https://example.invalid
contexts:
- name: prod-a
  context:
    cluster: shared
- name: dev-b
  context:
    cluster: shared
current-context: dev-b
`
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	p := model.Profile{Name: "test", Kubeconfig: path, ContextRegex: "^prod"}
	cs, err := Contexts(p)
	if err != nil || len(cs) != 1 || cs[0].Name != "shared" || cs[0].Context != "prod-a" {
		t.Fatalf("selection: %+v %v", cs, err)
	}
	p.ContextRegex = ".*"
	targets, err := Clusters(p)
	if err != nil || len(targets) != 1 || targets[0].Name != "shared" || targets[0].Context != "dev-b" {
		t.Fatalf("expected one target for shared cluster using the first matching context: %+v %v", targets, err)
	}
	otherPath := filepath.Join(t.TempDir(), "renamed-config")
	if err := os.WriteFile(otherPath, []byte(strings.ReplaceAll(config, "dev-b", "renamed")), 0600); err != nil {
		t.Fatal(err)
	}
	p.Kubeconfig = otherPath
	p.ContextRegex = "^renamed$"
	moved, err := Clusters(p)
	if err != nil || len(moved) != 1 || moved[0].ID != targets[0].ID || moved[0].Context != "renamed" {
		t.Fatalf("source or context changed cluster identity: %+v %v", moved, err)
	}
	for _, re := range []string{"[", "^missing$"} {
		p.ContextRegex = re
		if _, err = Contexts(p); err == nil {
			t.Fatalf("accepted %s", re)
		}
	}
	b, _ := os.ReadFile(path)
	if string(b) != config {
		t.Fatal("kubeconfig modified")
	}
}
func TestTrivyArgumentsAndFailure(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$ARG_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then shift; output="$1"; fi
  shift
done
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$output"
`
	path := filepath.Join(dir, "mise")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ARG_LOG", log)
	p := model.Profile{Name: "test", TimeoutSeconds: 3, Namespaces: []string{"kube-system"}}
	c := Target{Cluster: model.Cluster{Name: "shared", Source: "/tmp/config"}, Context: "context with spaces"}
	a, err := (Trivy{}).Collect(context.Background(), p, c)
	if err != nil || len(a.KBOM) == 0 {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log)
	for _, want := range []string{"trivy@" + model.TrivyVersion, "--disable-node-collector=true", "--skip-images=true", "--config=", "--parallel\n5", "--qps\n5", "--burst\n10", "--include-namespaces\nkube-system", "--\ncontext with spaces"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("missing argument %q: %s", want, args)
		}
	}
	if err = os.WriteFile(path, []byte("#!/bin/sh\necho secret-token >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err = (Trivy{}).Collect(context.Background(), p, c)
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unsafe error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = (Trivy{}).Collect(ctx, p, c); err == nil {
		t.Fatal("cancelled collection succeeded")
	}
}
