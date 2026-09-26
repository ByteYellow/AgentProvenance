package daemon

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Localized specs must keep paths, required fields, enums and references intact.
func TestOpenAPILocalizationPreservesContract(t *testing.T) {
	var contracts []map[string]any
	for _, path := range []string{"../../docs/openapi.yaml", "../../docs/zh-CN/openapi.yaml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var contract map[string]any
		if err := yaml.Unmarshal(data, &contract); err != nil {
			t.Fatal(err)
		}
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
