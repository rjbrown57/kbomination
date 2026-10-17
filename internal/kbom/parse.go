package kbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Component struct {
	Ref        string          `json:"bom-ref"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	PURL       string          `json:"purl"`
	Hashes     json.RawMessage `json:"hashes"`
	Properties []Property      `json:"properties"`
	Components []Component     `json:"components"`
}
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type Document struct {
	Format      string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component *Component `json:"component"`
	} `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}
type Item struct {
	Component
	Parent                              string
	Namespace, Kind, Resource, Category string
}
type Parsed struct {
	Items []Item
	Edges []Dependency
}

func Parse(raw []byte) (Parsed, error) {
	var d Document
	var result Parsed
	if err := json.Unmarshal(raw, &d); err != nil {
		return result, fmt.Errorf("invalid KBOM JSON: %w", err)
	}
	if d.Format != "CycloneDX" || d.SpecVersion == "" {
		return result, fmt.Errorf("expected a CycloneDX JSON document with specVersion")
	}
	seen := map[string]bool{}
	var walk func(Component, string, string) error
	walk = func(c Component, parent, path string) error {
		if c.Ref == "" {
			c.Ref = "generated:" + path
		}
		if seen[c.Ref] {
			return fmt.Errorf("duplicate component bom-ref %q", c.Ref)
		}
		seen[c.Ref] = true
		i := Item{Component: c, Parent: parent, Category: "unknown"}
		for _, p := range c.Properties {
			switch {
			case p.Name == "aquasecurity:trivy:Namespace" || strings.HasSuffix(p.Name, ":K8s:Namespace"):
				i.Namespace = p.Value
			case p.Name == "aquasecurity:trivy:Kind" || strings.HasSuffix(p.Name, ":K8s:Kind") || strings.HasSuffix(p.Name, ":resource:Type"):
				i.Kind = p.Value
			case p.Name == "aquasecurity:trivy:Name" || strings.HasSuffix(p.Name, ":K8s:Name") || strings.HasSuffix(p.Name, ":resource:Name"):
				i.Resource = p.Value
			case p.Name == "aquasecurity:trivy:Class":
				i.Category = p.Value
			}
		}
		if i.Kind != "" {
			switch strings.ToLower(i.Kind) {
			case "node":
				i.Category = "node"
			case "namespace":
				i.Category = "namespace"
			case "pod", "deployment", "daemonset", "statefulset", "job", "cronjob", "replicaset":
				i.Category = "workload"
			default:
				i.Category = "resource"
			}
		} else if c.Type == "container" {
			i.Category = "image"
		}
		if strings.EqualFold(i.Kind, "cluster") {
			i.Category = "cluster"
		}
		if strings.EqualFold(i.Kind, "controlplanecomponents") {
			i.Category = "control-plane"
		}
		i.Components = nil
		result.Items = append(result.Items, i)
		for n, child := range c.Components {
			if err := walk(child, c.Ref, fmt.Sprintf("%s/%d", path, n)); err != nil {
				return err
			}
		}
		return nil
	}
	if d.Metadata.Component != nil {
		if err := walk(*d.Metadata.Component, "", "metadata"); err != nil {
			return result, err
		}
	}
	for n, c := range d.Components {
		if err := walk(c, "", fmt.Sprintf("components/%d", n)); err != nil {
			return result, err
		}
	}
	result.Edges = d.Dependencies
	return result, nil
}
