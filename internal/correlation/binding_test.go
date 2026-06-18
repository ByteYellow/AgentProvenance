package correlation

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestListBindingsFiltersToolCallScope(t *testing.T) {
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

	started := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-1",
		SessionID:     "session-1",
		AttemptID:     "attempt-1",
		ToolCallID:    "tool-1",
		ProcessID:     "process-1",
		ContainerID:   "container-1",
		CgroupID:      "cgroup-1",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-2",
		SessionID:     "session-2",
		AttemptID:     "attempt-2",
		ToolCallID:    "tool-2",
		ProcessID:     "process-2",
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	bindings, err := ListBindings(db, BindingFilter{RunID: "run-1", ToolCallID: "tool-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	binding := bindings[0]
	if binding.RunID != "run-1" || binding.ToolCallID != "tool-1" || binding.PID != 4242 {
		t.Fatalf("unexpected binding: %+v", binding)
	}
}
