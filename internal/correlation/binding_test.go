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

func TestResolveHonorsExplicitRunID(t *testing.T) {
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

	started := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID:         "run-a",
		SessionID:     "session-a",
		AttemptID:     "attempt-a",
		ToolCallID:    "tool-a",
		ProcessID:     "process-a",
		ContainerID:   "shared-container",
		CgroupID:      "shared-cgroup",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	match, ok, err := Resolve(db, RawIdentity{
		RunID:       "run-b",
		ContainerID: "shared-container",
		CgroupID:    "shared-cgroup",
		PID:         4242,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("explicit run-b should not resolve run-a binding: %+v", match)
	}
	match, ok, err = Resolve(db, RawIdentity{
		ContainerID: "shared-container",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-a" {
		t.Fatalf("runless lookup should still resolve by container: ok=%t match=%+v", ok, match)
	}
}

// TestStaleOpenBindingDoesNotOverMatch characterizes the dropped-CloseBinding
// failure mode: CloseBinding is best-effort everywhere, so a binding can be left
// open (ended_at = "") indefinitely. Without the MaxOpenBindingAge guard such a
// binding would match every future event for its cgroup/pid forever. An event
// observed long after the open binding started must NOT bind to it.
func TestStaleOpenBindingDoesNotOverMatch(t *testing.T) {
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

	// An open binding (no EndedAt) started well beyond MaxOpenBindingAge ago,
	// simulating a binding whose close was dropped.
	stale := time.Now().Add(-MaxOpenBindingAge - time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := RecordBinding(db, Binding{
		RunID: "run-stale", CgroupID: "cgroup-shared", PID: 1000,
		StartedAt: stale, BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// An event observed now must fall through to unresolved, not bind to the
	// stale open context.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-shared", Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("stale open binding over-matched an event observed beyond MaxOpenBindingAge")
	}

	// A fresh open binding for a different cgroup must still resolve at now.
	if _, err := RecordBinding(db, Binding{
		RunID: "run-fresh", CgroupID: "cgroup-fresh", PID: 2000,
		StartedAt: now, BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	match, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-fresh", Timestamp: now})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.RunID != "run-fresh" {
		t.Fatalf("fresh open binding failed to resolve: ok=%v match=%+v", ok, match)
	}
}

// TestClosedBindingWindowStillResolves confirms the refactor preserved the
// closed-interval time-window behavior: an event inside [started, ended] binds,
// one after ended does not.
func TestClosedBindingWindowStillResolves(t *testing.T) {
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

	start := time.Now().Add(-10 * time.Minute)
	end := time.Now().Add(-5 * time.Minute)
	if _, err := RecordBinding(db, Binding{
		RunID: "run-closed", CgroupID: "cgroup-closed", PID: 3000,
		StartedAt:     start.UTC().Format(time.RFC3339Nano),
		EndedAt:       end.UTC().Format(time.RFC3339Nano),
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	inside := start.Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)
	if _, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-closed", Timestamp: inside}); err != nil || !ok {
		t.Fatalf("event inside closed window should resolve: ok=%v err=%v", ok, err)
	}

	after := time.Now().UTC().Format(time.RFC3339Nano)
	if _, ok, err := Resolve(db, RawIdentity{CgroupID: "cgroup-closed", Timestamp: after}); err != nil || ok {
		t.Fatalf("event after closed window must not resolve: ok=%v err=%v", ok, err)
	}
}
