package telemetry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestSpoolEnqueueAndProcessFalcoBatch(t *testing.T) {
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

	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-spool",
		SessionID:     "session-spool",
		AttemptID:     "attempt-spool",
		ToolCallID:    "tool-spool",
		ProcessID:     "process-spool",
		ContainerID:   "container-spool",
		PID:           4242,
		StartedAt:     "2026-01-01T00:00:00Z",
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	source := filepath.Join(root, "falco.jsonl")
	raw := `{"time":"2026-01-01T00:00:01Z","rule":"Terminal shell in container","priority":"Notice","output_fields":{"evt.type":"execve","proc.pid":4242,"proc.ppid":4000,"container.id":"container-spool","proc.cmdline":"sh -lc pytest -q"}}` + "\n" +
		`{"time":"2026-01-01T00:00:02Z","rule":"Metadata service access","priority":"Critical","output_fields":{"evt.type":"connect","proc.pid":4242,"proc.ppid":4000,"container.id":"container-spool","fd.rip":"169.254.169.254:80"}}` + "\n"
	if err := os.WriteFile(source, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	service := SpoolService{DB: db, Paths: paths}
	batch, err := service.Enqueue(SpoolEnqueueRequest{Format: "falco", RunID: "run-spool", SourcePath: source, PolicyEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if batch.ID == "" || batch.Status != "queued" || batch.SpoolPath == "" || batch.FileSHA256 == "" || batch.SizeBytes == 0 {
		t.Fatalf("unexpected queued batch: %+v", batch)
	}
	if _, err := os.Stat(batch.SpoolPath); err != nil {
		t.Fatal(err)
	}
	events, err := ListEventsFiltered(db, Filter{RunID: "run-spool"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("enqueue should not ingest events synchronously: %+v", events)
	}

	result, err := service.Process(10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Processed != 1 || result.Failed != 0 {
		t.Fatalf("unexpected process result: %+v", result)
	}
	events, err = ListEventsFiltered(db, Filter{RunID: "run-spool"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events after process = %d, want 2", len(events))
	}
	risks, err := securitymodel.ListRiskSignals(db, "run-spool")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RecommendedAction != "quarantine" {
		t.Fatalf("unexpected risk signals: %+v", risks)
	}
	queued, err := service.List("run-spool")
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].Status != "processed" || queued[0].IngestedCount != 2 || queued[0].IngestBatchID == "" {
		t.Fatalf("unexpected spool row after process: %+v", queued)
	}
}
