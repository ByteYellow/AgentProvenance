package daemon

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Localized specs must keep paths, required fields, enums and references intact.
func TestOpenAPILocalizationPreservesContract(t *testing.T) {
	var contracts []map[string]any
	for _, path := range []string{"../../docs/openapi.yaml", "../../docs/zh-CN/openapi.yaml"} {
		contract := resolvedOpenAPIContract(t, path)
		for endpoint, raw := range contract["paths"].(map[string]any) {
			operation := raw.(map[string]any)["get"].(map[string]any)
			for status, response := range operation["responses"].(map[string]any) {
				for key := range response.(map[string]any) {
					switch key {
					case "$ref", "description", "headers", "content", "links":
					default:
						if !strings.HasPrefix(key, "x-") {
							t.Errorf("%s %s %s: unexpected response key %q", path, endpoint, status, key)
						}
					}
				}
			}
		}
		stripOpenAPIDisplayText(contract)
		contracts = append(contracts, contract)
	}
	if !reflect.DeepEqual(contracts[0], contracts[1]) {
		t.Fatal("Chinese OpenAPI changes fields other than display text")
	}
}

// Resolve file-relative references in their own document before comparing the
// localized contracts. This also rejects missing schemas and broken pointers.
func resolvedOpenAPIContract(t *testing.T, path string) map[string]any {
	t.Helper()
	documents := map[string]map[string]any{}
	load := func(path string) map[string]any {
		path = filepath.Clean(path)
		if doc, ok := documents[path]; ok {
			return doc
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		documents[path] = doc
		return doc
	}
	var resolve func(any, string, int) any
	resolve = func(value any, path string, depth int) any {
		if depth > 64 {
			t.Fatalf("%s: recursive or excessively deep OpenAPI reference", path)
		}
		switch value := value.(type) {
		case map[string]any:
			result := map[string]any{}
			if ref, ok := value["$ref"].(string); ok {
				file, pointer, hasPointer := strings.Cut(ref, "#")
				if strings.Contains(file, ":") || !hasPointer || !strings.HasPrefix(pointer, "/") {
					t.Fatalf("%s: unsupported OpenAPI reference %q", path, ref)
				}
				target := path
				if file != "" {
					target = filepath.Join(filepath.Dir(path), file)
				}
				var found any = load(target)
				for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
					key := strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
					object, ok := found.(map[string]any)
					if !ok {
						t.Fatalf("%s: invalid OpenAPI reference %q at %q", path, ref, key)
					}
					found, ok = object[key]
					if !ok {
						t.Fatalf("%s: missing OpenAPI reference %q", path, ref)
					}
				}
				resolved, ok := resolve(found, target, depth+1).(map[string]any)
				if !ok {
					t.Fatalf("%s: non-object OpenAPI reference %q", path, ref)
				}
				for key, child := range resolved {
					result[key] = child
				}
			}
			for key, child := range value {
				if key != "$ref" {
					result[key] = resolve(child, path, depth+1)
				}
			}
			return result
		case []any:
			result := make([]any, len(value))
			for i, child := range value {
				result[i] = resolve(child, path, depth+1)
			}
			return result
		default:
			return value
		}
	}
	return resolve(load(path), path, 0).(map[string]any)
}

func stripOpenAPIDisplayText(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if _, text := child.(string); text && (key == "title" || key == "description" || key == "summary") {
				delete(value, key)
				continue
			}
			stripOpenAPIDisplayText(child)
		}
	case []any:
		for _, child := range value {
			stripOpenAPIDisplayText(child)
		}
	}
}
