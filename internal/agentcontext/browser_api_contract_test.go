package agentcontext

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func browserAPISchemas(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/agent-context-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document["components"].(map[string]any)["schemas"].(map[string]any)
}

func TestBrowserOpenAPIJSONFields(t *testing.T) {
	schemas := browserAPISchemas(t)
	for name, value := range map[string]any{
		"BrowserScope":              BrowserScope{},
		"BrowserOperation":          BrowserOperation{},
		"BrowserEvent":              BrowserEvent{},
		"BrowserReceiptObservation": BrowserReceiptObservation{},
		"BrowserReceipt":            BrowserReceipt{},
		"BrowserReceiptSourceRef":   BrowserReceiptSourceRef{},
		"BrowserBridgePlacement":    BrowserBridgePlacement{},
		"BrowserBridgeIdentity":     BrowserBridgeIdentity{},
	} {
		t.Run(name, func(t *testing.T) {
			schema, ok := schemas[name].(map[string]any)
			if !ok {
				t.Fatalf("missing schema %s", name)
			}
			properties := schema["properties"].(map[string]any)
			required := schema["required"].([]any)
			typ := reflect.TypeOf(value)
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				tag := strings.Split(field.Tag.Get("json"), ",")
				property, exists := properties[tag[0]].(map[string]any)
				if !exists || slices.Contains(required, any(tag[0])) == slices.Contains(tag, "omitempty") {
					t.Errorf("schema field or requiredness differs from JSON tag %q", field.Tag.Get("json"))
				}
				if !exists || slices.Contains(tag, "omitempty") {
					continue
				}
				if kind := field.Type.Kind(); kind == reflect.Pointer || kind == reflect.Map || kind == reflect.Slice {
					types, _ := property["type"].([]any)
					if !slices.Contains(types, any("null")) {
						t.Errorf("%s must accept JSON null", tag[0])
					}
				}
			}
			if len(properties) != typ.NumField() {
				t.Errorf("%d schema properties for %d JSON fields", len(properties), typ.NumField())
			}
		})
	}
}

func TestBrowserOpenAPIReceiptSemantics(t *testing.T) {
	schemas := browserAPISchemas(t)
	property := func(schema, name string) map[string]any {
		t.Helper()
		s, ok := schemas[schema].(map[string]any)
		if !ok {
			t.Fatalf("missing schema %s", schema)
		}
		return s["properties"].(map[string]any)[name].(map[string]any)
	}
	for _, kind := range []string{"action_accept", "action_result"} {
		if !slices.Contains(property("BrowserEvent", "kind")["enum"].([]any), any(kind)) {
			t.Errorf("missing event kind %s", kind)
		}
	}
	if property("BrowserReceipt", "schema_version")["const"] != BrowserReceiptVersion {
		t.Error("receipt schema version differs from the wire format")
	}
	if !reflect.DeepEqual(property("BrowserReceiptObservation", "authentication")["enum"], []any{"unverified"}) {
		t.Error("a source receipt must not grant receiver trust")
	}
	if !reflect.DeepEqual(property("BrowserOperation", "result_operation")["enum"], []any{"execute", "read"}) {
		t.Error("result queries must remain distinct from execution")
	}
}
