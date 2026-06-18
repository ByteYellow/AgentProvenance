package record

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestRecordRunCreatesZeroSDKProvenance(t *testing.T) {
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

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := (Service{DB: db, Paths: paths}).Run(Request{
		RunID:   "run-record-test",
		Name:    "record-test",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py && echo note > note.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "passed" || result.ExitCode != 0 {
		t.Fatalf("record result = %+v, want passed exit 0", result)
	}
	if result.AttemptID == "" || result.ToolCallID == "" || result.ProcessID == "" || result.BaseSnapshotID == "" {
		t.Fatalf("record result missing graph ids: %+v", result)
	}
	changed := strings.Join(result.ChangedFiles, ",")
	if !strings.Contains(changed, "app.py") || !strings.Contains(changed, "note.txt") {
		t.Fatalf("changed files = %v, want app.py and note.txt", result.ChangedFiles)
	}

	events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: "run-record-test", Type: "file_write"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("file_write events = %d, want >= 2", len(events))
	}
	for _, event := range events {
		if event.ToolCallID != result.ToolCallID || event.ProcessID != result.ProcessID {
			t.Fatalf("event not correlated to record context: %+v", event)
		}
		if event.PPID == 0 || event.TGID == 0 {
			t.Fatalf("event missing process tree identity: %+v", event)
		}
	}

	var trace bytes.Buffer
	if err := provenance.TraceRun(db, "run-record-test", &trace); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"runtime_process_parent", "runtime_event_file", "workspace_file/app.py", result.ToolCallID, result.ProcessID} {
		if !strings.Contains(trace.String(), want) {
			t.Fatalf("trace missing %q:\n%s", want, trace.String())
		}
	}

	var explain bytes.Buffer
	if err := provenance.Explain(db, provenance.ExplainOptions{RunID: "run-record-test", File: "app.py"}, &explain); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"target=file", "state_diff:", "state_blame:", "runtime_file_events:", "modified_by_attempt", "file_write"} {
		if !strings.Contains(explain.String(), want) {
			t.Fatalf("explain missing %q:\n%s", want, explain.String())
		}
	}
}
