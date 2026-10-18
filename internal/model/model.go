package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

const TrivyVersion = "0.76.0"
const MaxKBOMBytes = 64 << 20

type Profile struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Kubeconfig     string   `json:"kubeconfig"`
	ContextRegex   string   `json:"context_regex"`
	Namespaces     []string `json:"namespaces"`
	Cron           string   `json:"cron"`
	Enabled        bool     `json:"enabled"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile name is required")
	}
	if p.ContextRegex == "" {
		p.ContextRegex = ".*"
	}
	if _, err := regexp.Compile(p.ContextRegex); err != nil {
		return fmt.Errorf("context regex: %w", err)
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 900
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 86400 {
		return fmt.Errorf("timeout must be between 1 and 86400 seconds")
	}
	ns := []string{}
	for _, n := range p.Namespaces {
		n = strings.TrimSpace(n)
		if n == "" {
			return fmt.Errorf("namespace cannot be empty")
		}
		if len(n) > 63 || !regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(n) {
			return fmt.Errorf("invalid namespace %q", n)
		}
		ns = append(ns, n)
	}
	slices.Sort(ns)
	p.Namespaces = slices.Compact(ns)
	if p.Cron != "" {
		if _, err := ParseSchedule(p.Cron); err != nil {
			return fmt.Errorf("schedule: %w", err)
		}
	}
	if p.Enabled && p.Cron == "" {
		return fmt.Errorf("an enabled schedule requires a cron expression")
	}
	return nil
}

func ParseSchedule(s string) (cron.Schedule, error) {
	return cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(s)
}

func Scope(namespaces []string) string {
	ns := slices.Clone(namespaces)
	slices.Sort(ns)
	ns = slices.Compact(ns)
	if len(ns) == 0 {
		return "all"
	}
	return "namespaces:" + strings.Join(ns, ",")
}

func Key(parts ...string) string {
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Cluster is an inventory identity. Source is provenance only; access contexts
// belong to collection targets, never to cluster identity.
type Cluster struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Server string `json:"server"`
}

func ClusterID(name string) string { return Key("kubeconfig-cluster", name) }

// UnmarshalJSON accepts older collection artifacts at the input boundary.
// Their access context is discarded and an explicit kubeconfig cluster name,
// when present, takes precedence over the old display name.
func (c *Cluster) UnmarshalJSON(data []byte) error {
	type plain Cluster
	var value plain
	input := struct {
		*plain
		Context        string `json:"context"`
		KubeconfigName string `json:"kubeconfig_name"`
	}{plain: &value}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if input.KubeconfigName != "" {
		value.Name = input.KubeconfigName
	}
	*c = Cluster(value)
	return nil
}

type Artifact struct {
	Cluster      Cluster         `json:"cluster"`
	Namespaces   []string        `json:"namespaces"`
	CollectedAt  time.Time       `json:"collected_at"`
	TrivyVersion string          `json:"trivy_version"`
	KBOM         json.RawMessage `json:"kbom"`
}

type ManifestEntry struct {
	Artifact
	File   string `json:"file"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type Manifest struct {
	Version int             `json:"version"`
	Entries []ManifestEntry `json:"entries"`
}
