package aitools

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func openTestStore(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

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

func TestContextWriteToolsAssertWithinTrustBoundary(t *testing.T) {
	db := openTestStore(t)

	// record_tool_call anchors an app-asserted call and returns its id.
	rec, err := Dispatch(db, "record_tool_call", map[string]any{"run": "run-1", "command": "curl https://api.example.com"})
	if err != nil {
		t.Fatalf("record_tool_call: %v", err)
	}
	recMap := rec.(map[string]any)
	toolCall, _ := recMap["tool_call"].(string)
	if toolCall == "" {
		t.Fatalf("record_tool_call returned no tool_call id: %+v", recMap)
	}
	if recMap["status"] != assertedStatus {
		t.Errorf("status = %v, want %q so consumers can tell it from a gate/kernel call", recMap["status"], assertedStatus)
	}

	// bind_scope links the asserted call to an observable process scope.
	out, err := Dispatch(db, "bind_scope", map[string]any{
		"run":          "run-1",
		"tool_call":    toolCall,
		"pid":          float64(4242), // JSON numbers arrive as float64
		"container_id": "agentprov-abc",
		// A caller trying to forge trusted provenance: must be overridden.
		"binding_source": "kernel",
	})
	if err != nil {
		t.Fatalf("bind_scope: %v", err)
	}
	if out.(map[string]any)["binding_source"] != aiBindingSource {
		t.Fatalf("bind_scope must force source to %q, got %+v", aiBindingSource, out)
	}

	// The persisted binding must carry the honest ai_asserted source (not the
	// caller's "kernel"), with the observable identifiers preserved for join.
	bindings, err := correlation.ListBindings(db, correlation.BindingFilter{RunID: "run-1", ToolCallID: toolCall})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("want 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.BindingSource != aiBindingSource {
		t.Errorf("persisted binding_source = %q, want %q (no masquerading as control plane/kernel)", b.BindingSource, aiBindingSource)
	}
	if b.PID != 4242 || b.ContainerID != "agentprov-abc" {
		t.Errorf("observable identifiers not preserved: %+v", b)
	}

	// Required-arg guards.
	if _, err := Dispatch(db, "bind_scope", map[string]any{"run": "run-1"}); err == nil {
		t.Error("bind_scope should require tool_call")
	}
	if _, err := Dispatch(db, "record_tool_call", map[string]any{"run": "run-1"}); err == nil {
		t.Error("record_tool_call should require command")
	}

	// The orphan anchor must not break the read/verify surface.
	if _, err := Dispatch(db, "verify_run", map[string]any{"run": "run-1"}); err != nil {
		t.Errorf("verify_run broke on app-asserted tool_call: %v", err)
	}
	if _, err := Dispatch(db, "get_timeline", map[string]any{"run": "run-1"}); err != nil {
		t.Errorf("get_timeline broke on app-asserted tool_call: %v", err)
	}
}
