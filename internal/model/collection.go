package model

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
)

// CollectionOptions controls Trivy without allowing callers to replace the
// artifact format, output path, or selected kubeconfig context.
type CollectionOptions struct {
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	IncludeKinds      []string `json:"include_kinds,omitempty"`
	ExcludeKinds      []string `json:"exclude_kinds,omitempty"`
	QPS               *float64 `json:"qps,omitempty"`
	Burst             *int     `json:"burst,omitempty"`
	ScanImages        bool     `json:"scan_images"`
	Parallel          *int     `json:"parallel,omitempty"`
	ImageSrc          []string `json:"image_src,omitempty"`
	CacheDir          string   `json:"cache_dir,omitempty"`
	CACert            string   `json:"cacert,omitempty"`
	DBRepository      []string `json:"db_repository,omitempty"`
	JavaDBRepository  []string `json:"java_db_repository,omitempty"`
	SkipDBUpdate      bool     `json:"skip_db_update"`
	SkipJavaDBUpdate  bool     `json:"skip_java_db_update"`
	OfflineScan       bool     `json:"offline_scan"`
}

// Defaults match the pinned Trivy release. Pointers distinguish omitted
// settings from explicit zero (which is meaningful for parallelism).
func DefaultCollectionOptions() CollectionOptions {
	qps, burst, parallel := 5.0, 10, 5
	return CollectionOptions{QPS: &qps, Burst: &burst, Parallel: &parallel,
		ImageSrc:         []string{"docker", "containerd", "podman", "remote"},
		DBRepository:     []string{"mirror.gcr.io/aquasec/trivy-db:2", "ghcr.io/aquasecurity/trivy-db:2"},
		JavaDBRepository: []string{"mirror.gcr.io/aquasec/trivy-java-db:1", "ghcr.io/aquasecurity/trivy-java-db:1"}}
}

func normalizeList(values []string, name string, ordered, lower bool) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			return nil, fmt.Errorf("%s cannot contain empty entries", name)
		}
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	if !ordered {
		slices.Sort(out)
	}
	return out, nil
}

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

func NormalizeNamespaces(values []string) ([]string, error) {
	out, err := normalizeList(values, "namespaces", false, false)
	if err != nil {
		return nil, err
	}
	for _, value := range out {
		if len(value) > 63 || !namespacePattern.MatchString(value) {
			return nil, fmt.Errorf("invalid namespace %q", value)
		}
	}
	return out, nil
}

func (o *CollectionOptions) Normalize(namespaces []string) error {
	defaults := DefaultCollectionOptions()
	if o.QPS == nil {
		o.QPS = defaults.QPS
	}
	if o.Burst == nil {
		o.Burst = defaults.Burst
	}
	if o.Parallel == nil {
		o.Parallel = defaults.Parallel
	}
	if *o.QPS <= 0 || math.IsNaN(*o.QPS) || math.IsInf(*o.QPS, 0) {
		return fmt.Errorf("qps must be positive and finite")
	}
	if *o.Burst <= 0 {
		return fmt.Errorf("burst must be positive")
	}
	if *o.Parallel < 0 {
		return fmt.Errorf("parallel must be nonnegative")
	}
	var err error
	if o.ExcludeNamespaces, err = NormalizeNamespaces(o.ExcludeNamespaces); err != nil {
		return err
	}
	for _, value := range namespaces {
		if slices.Contains(o.ExcludeNamespaces, value) {
			return fmt.Errorf("namespace %q is both included and excluded", value)
		}
	}
	if o.IncludeKinds, err = normalizeList(o.IncludeKinds, "include_kinds", false, true); err != nil {
		return err
	}
	if o.ExcludeKinds, err = normalizeList(o.ExcludeKinds, "exclude_kinds", false, true); err != nil {
		return err
	}
	for _, value := range append(slices.Clone(o.IncludeKinds), o.ExcludeKinds...) {
		if !kindPattern.MatchString(value) {
			return fmt.Errorf("invalid resource kind %q", value)
		}
	}
	for _, value := range o.IncludeKinds {
		if slices.Contains(o.ExcludeKinds, value) {
			return fmt.Errorf("kind %q is both included and excluded", value)
		}
	}
	if len(o.ImageSrc) == 0 {
		o.ImageSrc = defaults.ImageSrc
	}
	if o.ImageSrc, err = normalizeList(o.ImageSrc, "image_src", true, true); err != nil {
		return err
	}
	for _, value := range o.ImageSrc {
		if !slices.Contains(defaults.ImageSrc, value) {
			return fmt.Errorf("unsupported image source %q", value)
		}
	}
	if len(o.DBRepository) == 0 {
		o.DBRepository = defaults.DBRepository
	}
	if len(o.JavaDBRepository) == 0 {
		o.JavaDBRepository = defaults.JavaDBRepository
	}
	if o.DBRepository, err = normalizeList(o.DBRepository, "db_repository", true, false); err != nil {
		return err
	}
	if o.JavaDBRepository, err = normalizeList(o.JavaDBRepository, "java_db_repository", true, false); err != nil {
		return err
	}
	return nil
}

// CollectionScope must receive normalized options. Only coverage-changing
// settings participate; runtime transport and throttling never split history.
func CollectionScope(namespaces []string, o *CollectionOptions) string {
	if o == nil || (len(o.ExcludeNamespaces) == 0 && len(o.IncludeKinds) == 0 && len(o.ExcludeKinds) == 0 && !o.ScanImages) {
		return Scope(namespaces)
	}
	coverage := struct {
		Namespaces        []string `json:"namespaces"`
		ExcludeNamespaces []string `json:"exclude_namespaces"`
		IncludeKinds      []string `json:"include_kinds"`
		ExcludeKinds      []string `json:"exclude_kinds"`
		ScanImages        bool     `json:"scan_images"`
		OfflineScan       bool     `json:"offline_scan"`
	}{namespaces, o.ExcludeNamespaces, o.IncludeKinds, o.ExcludeKinds, o.ScanImages, o.ScanImages && o.OfflineScan}
	raw, _ := json.Marshal(coverage)
	return "coverage:v1:" + Key(string(raw))
}

func CoverageDescription(namespaces []string, o *CollectionOptions) string {
	parts := []string{"All namespaces"}
	if len(namespaces) > 0 {
		parts[0] = "Namespaces: " + strings.Join(namespaces, ", ")
	}
	if o == nil {
		return parts[0] + " · collection settings unrecorded"
	}
	if len(o.ExcludeNamespaces) > 0 {
		parts = append(parts, "excluding namespaces: "+strings.Join(o.ExcludeNamespaces, ", "))
	}
	if len(o.IncludeKinds) > 0 {
		parts = append(parts, "kinds: "+strings.Join(o.IncludeKinds, ", "))
	}
	if len(o.ExcludeKinds) > 0 {
		parts = append(parts, "excluding kinds: "+strings.Join(o.ExcludeKinds, ", "))
	}
	if o.ScanImages {
		parts = append(parts, "images scanned")
		if o.OfflineScan {
			parts = append(parts, "offline dependency identification")
		}
	} else {
		parts = append(parts, "image scanning skipped")
	}
	return strings.Join(parts, " · ")
}
