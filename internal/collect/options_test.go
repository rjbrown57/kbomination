package collect

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rjbrown57/kbomination/internal/model"
)

func TestTrivyCollectionOptions(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "mise"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ARG_LOG", log)
	o := model.DefaultCollectionOptions()
	qps, burst, parallel := 2.5, 4, 0
	o.QPS = &qps
	o.Burst = &burst
	o.Parallel = &parallel
	o.ExcludeNamespaces = []string{"dev"}
	o.IncludeKinds = []string{"Pod"}
	o.ExcludeKinds = []string{"node"}
	o.ScanImages = true
	o.ImageSrc = []string{"remote", "docker"}
	o.CacheDir = "/cache with spaces"
	o.CACert = "/ca with spaces.pem"
	o.DBRepository = []string{"mirror/first:2", "mirror/second:2"}
	o.JavaDBRepository = []string{"mirror/java:1"}
	o.SkipDBUpdate = true
	o.SkipJavaDBUpdate = true
	o.OfflineScan = true
	p := model.Profile{Name: "test", Namespaces: []string{"prod"}, CollectionOptions: o}
	a, err := (Trivy{}).Collect(context.Background(), p, Target{Cluster: model.Cluster{Name: "test", Source: "/kubeconfig"}, Context: "context with spaces"})
	if err != nil {
		t.Fatal(err)
	}
	if a.CollectionOptions == nil || !a.CollectionOptions.ScanImages || a.CollectionOptions.IncludeKinds[0] != "pod" {
		t.Fatalf("options not recorded: %+v", a)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, want := range []string{"--config=", "--skip-images=false", "--disable-node-collector=true", "--skip-db-update=true", "--skip-java-db-update=true", "--offline-scan=true", "/cache with spaces", "/ca with spaces.pem", "remote,docker", "mirror/first:2,mirror/second:2", "mirror/java:1", "2.5", "4", "0", "pod", "node", "dev", "prod"} {
		if !slices.Contains(args, want) {
			t.Fatalf("missing %q: %v", want, args)
		}
	}
	if args[len(args)-2] != "--" || args[len(args)-1] != "context with spaces" {
		t.Fatal("context not isolated")
	}
}

func TestTrivyEnvironment(t *testing.T) {
	env := []string{"TRIVY_CONFIG=/bad", "TRIVY_SKIP_IMAGES=false", "TRIVY_INCLUDE_NAMESPACES=hidden", "TRIVY_SCANNERS=secret", "TRIVY_CACHE_DIR=/ambient", "KUBECONFIG=/old", "TRIVY_USERNAME=user", "TRIVY_PASSWORD=credential", "TRIVY_REGISTRY_TOKEN=credential", "AWS_PROFILE=cluster", "HTTPS_PROXY=http://proxy", "PATH=/bin"}
	got := trivyEnvironment(env)
	if !slices.Equal(got, env[6:]) {
		t.Fatalf("unexpected filtered environment keys")
	}
}
