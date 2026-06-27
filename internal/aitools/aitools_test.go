package aitools

import (
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestCatalogAndProviderShapes(t *testing.T) {
	if len(Catalog()) < 5 {
		t.Fatalf("catalog too small: %d", len(Catalog()))
	}
	for _, tool := range Catalog() {
		if tool.Name == "" || tool.Description == "" || tool.InputSchema == nil || tool.Run == nil {
			t.Fatalf("incomplete tool: %+v", tool.Name)
		}
	}
	a := AnthropicTools()
	if len(a) != len(Catalog()) || a[0]["input_schema"] == nil {
		t.Fatalf("anthropic shape wrong: %+v", a[0])
	}
	o := OpenAITools()
	if o[0]["type"] != "function" || o[0]["function"] == nil {
		t.Fatalf("openai shape wrong: %+v", o[0])
	}
}

func TestEvaluateActionGate(t *testing.T) {
	// metadata IP -> quarantine; benign exec -> allow. No DB needed.
	q, err := Dispatch(nil, "evaluate_action", map[string]any{"event_type": "network_connect", "dst_ip": "169.254.169.254"})
	if err != nil {
		t.Fatal(err)
	}
	m := q.(map[string]any)
	if m["decision"] != "quarantine" || m["allow"] != false {
		t.Fatalf("metadata IP should quarantine, got %+v", m)
	}
	a, _ := Dispatch(nil, "evaluate_action", map[string]any{"event_type": "execve", "command": "ls -la"})
	if a.(map[string]any)["allow"] != true {
		t.Fatalf("benign exec should allow, got %+v", a)
	}
	// secret path in a proposed command -> kill.
	s, _ := Dispatch(nil, "evaluate_action", map[string]any{"event_type": "file_write", "path": "/home/agent/.aws/credentials"})
	if s.(map[string]any)["decision"] != "kill" {
		t.Fatalf("credentials path should kill, got %+v", s)
	}
}

func TestDispatchReadToolAgainstStore(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// verify_run on an empty run should still return a structured result.
	if _, err := Dispatch(db, "verify_run", map[string]any{"run": "nope"}); err != nil {
		t.Fatalf("verify_run dispatch: %v", err)
	}
	if _, err := Dispatch(db, "get_signals", map[string]any{"run": "nope"}); err != nil {
		t.Fatalf("get_signals dispatch: %v", err)
	}
	if _, err := Dispatch(db, "no_such_tool", nil); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}
