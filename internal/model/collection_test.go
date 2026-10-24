package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectionOptionsDefaultsAndValidation(t *testing.T) {
	var p Profile
	if err := json.Unmarshal([]byte(`{"name":"old","namespaces":["prod","prod"]}`), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if *p.CollectionOptions.QPS != 5 || *p.CollectionOptions.Burst != 10 || *p.CollectionOptions.Parallel != 5 || p.CollectionOptions.ScanImages {
		t.Fatalf("defaults: %+v", p.CollectionOptions)
	}
	if len(p.Namespaces) != 1 {
		t.Fatal(p.Namespaces)
	}
	for _, raw := range []string{
		`{"qps":0}`, `{"qps":-1}`, `{"burst":0}`, `{"parallel":-1}`,
		`{"exclude_namespaces":[""]}`, `{"exclude_namespaces":["BAD"]}`, `{"exclude_namespaces":["prod"]}`,
		`{"include_kinds":["Pod"],"exclude_kinds":["pod"]}`, `{"include_kinds":[" "]}`, `{"include_kinds":["--output"]}`,
		`{"image_src":["unknown"]}`, `{"db_repository":[""]}`, `{"java_db_repository":[" "]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var o CollectionOptions
			if err := json.Unmarshal([]byte(raw), &o); err != nil {
				t.Fatal(err)
			}
			if err := o.Normalize([]string{"prod"}); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
	var o CollectionOptions
	if err := json.Unmarshal([]byte(`{"parallel":0,"image_src":["remote","docker","remote"],"db_repository":["internal/first:2","internal/second:2"]}`), &o); err != nil {
		t.Fatal(err)
	}
	if err := o.Normalize(nil); err != nil {
		t.Fatal(err)
	}
	if *o.Parallel != 0 || strings.Join(o.ImageSrc, ",") != "remote,docker" || o.DBRepository[0] != "internal/first:2" {
		t.Fatalf("ordering/zero lost: %+v", o)
	}
}

func TestCollectionScope(t *testing.T) {
	normalize := func(o CollectionOptions) CollectionOptions {
		t.Helper()
		if err := o.Normalize(nil); err != nil {
			t.Fatal(err)
		}
		return o
	}
	base := normalize(CollectionOptions{})
	if CollectionScope(nil, &base) != "all" || CollectionScope([]string{"prod"}, &base) != "namespaces:prod" {
		t.Fatal("legacy scopes changed")
	}
	a := normalize(CollectionOptions{IncludeKinds: []string{"Pod", "service", "Pod"}, ExcludeNamespaces: []string{"z", "a"}})
	b := normalize(CollectionOptions{IncludeKinds: []string{"service", "pod"}, ExcludeNamespaces: []string{"a", "z"}})
	if CollectionScope(nil, &a) != CollectionScope(nil, &b) {
		t.Fatal("filter order changed scope")
	}
	b.CacheDir = "/other"
	b.CACert = "/ca"
	qps := 20.0
	b.QPS = &qps
	b.DBRepository = []string{"private/db:2"}
	if CollectionScope(nil, &a) != CollectionScope(nil, &b) {
		t.Fatal("operational settings split scope")
	}
	scopes := map[string]bool{"all": true}
	for _, o := range []CollectionOptions{{ExcludeNamespaces: []string{"prod"}}, {IncludeKinds: []string{"pod"}}, {ExcludeKinds: []string{"node"}}, {ScanImages: true}, {ScanImages: true, OfflineScan: true}} {
		o = normalize(o)
		scope := CollectionScope(nil, &o)
		if scopes[scope] {
			t.Fatalf("coverage collision: %s", scope)
		}
		scopes[scope] = true
		if strings.Contains(CoverageDescription(nil, &o), "unrecorded") {
			t.Fatal("missing description")
		}
	}
	base.OfflineScan = true
	if CollectionScope(nil, &base) != "all" {
		t.Fatal("offline setting without images split scope")
	}
	if !strings.Contains(CoverageDescription(nil, nil), "unrecorded") {
		t.Fatal("legacy coverage should be unknown")
	}
}
