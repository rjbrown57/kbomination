package kbom

import "testing"

func TestNestedAndUnknownProperties(t *testing.T) {
	p, err := Parse([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"cluster","type":"platform","name":"cluster"}},"components":[{"bom-ref":"node","name":"node","properties":[{"name":"vendor:opaque","value":"keep"}],"components":[{"name":"kubelet","version":"1.36"}]}],"dependencies":[{"ref":"cluster","dependsOn":["node"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 3 || p.Items[2].Parent != "node" || p.Items[1].Properties[0].Value != "keep" || p.Items[1].Category != "unknown" {
		t.Fatalf("bad normalization: %+v", p)
	}
}
func TestRejectMalformedAndRepeatedReferences(t *testing.T) {
	for _, raw := range []string{`{`, `{}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"same"},{"bom-ref":"same"}]}`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
