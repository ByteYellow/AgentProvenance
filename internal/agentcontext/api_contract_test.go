package agentcontext

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestContextOpenAPIHasResolvableReferences(t *testing.T) {
	data, err := os.ReadFile("../../docs/agent-context-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != "3.1.0" {
		t.Fatal("context API must support the documented nullable count unions")
	}
	refs := 0
	var visit func(any)
	visit = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			if ref, ok := node["$ref"].(string); ok {
				if !strings.HasPrefix(ref, "#/") {
					t.Fatalf("context API contract is not self-contained: %s", ref)
				}
				var target any = document
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
					parent, _ := target.(map[string]any)
					var exists bool
					target, exists = parent[part]
					if !exists {
						t.Fatalf("unresolved API reference: %s", ref)
					}
				}
				refs++
			}
			for _, child := range node {
				visit(child)
			}
		case []any:
			for _, child := range node {
				visit(child)
			}
		}
	}
	visit(document)
	if refs == 0 {
		t.Fatal("context API schemas were not inspected")
	}
}
