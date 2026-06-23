package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestIngestJSONLMapsSubstrateEvents(t *testing.T) {
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

	started := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-jsonl",
		SessionID:     "session-jsonl",
		AttemptID:     "attempt-jsonl",
		ToolCallID:    "tool-jsonl",
		ProcessID:     "process-jsonl",
		ContainerID:   "container-jsonl",
		CgroupID:      "cgroup-jsonl",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "events.jsonl")
	raw := "" +
		`{"process_exec":{"process":{"pid":4242,"binary":"/bin/sh","arguments":"-lc pytest -q","docker":"container-jsonl"}}}` + "\n" +
		`{"output_fields":{"evt.type":"connect","proc.pid":4242,"proc.ppid":4000,"container.id":"container-jsonl","fd.rip":"api.example.com:443"}}` + "\n" +
		`{"source":"loongcollector","event_type":"file_write","pid":4242,"path":"artifact.txt","cgroup_id":"cgroup-jsonl"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := IngestJSONL(db, JSONLIngestOptions{Format: "auto", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Read != 3 || result.Ingested != 3 || result.Failed != 0 || result.Skipped != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.BatchID == "" || result.FileSHA256 == "" || result.EventIDsSHA256 == "" {
		t.Fatalf("missing batch evidence fields: %+v", result)
	}
	if len(result.Rows) != 3 || result.ReceiverSummary.Resolved != 3 || result.ReceiverSummary.Unresolved != 0 {
		t.Fatalf("unexpected row receiver summary: rows=%+v summary=%+v", result.Rows, result.ReceiverSummary)
	}
	for _, format := range []string{"tetragon", "falco", "loongcollector"} {
		if result.ReceiverSummary.DetectedFormats[format] != 1 {
			t.Fatalf("detected format %s count = %d summary=%+v", format, result.ReceiverSummary.DetectedFormats[format], result.ReceiverSummary)
		}
	}
	for _, row := range result.Rows {
		if row.Status != "ingested" || row.EventID == "" || row.CorrelationMethod == "" || len(row.IdentityKeys) == 0 {
			t.Fatalf("row missing ingest evidence: %+v", row)
		}
	}
	var batchRunID, eventIDsJSON string
	var batchIngested int
	if err := db.QueryRow(`SELECT run_id, ingested_count, event_ids_json FROM telemetry_batches WHERE id = ?`, result.BatchID).Scan(&batchRunID, &batchIngested, &eventIDsJSON); err != nil {
		t.Fatal(err)
	}
	if batchRunID != "run-jsonl" || batchIngested != 3 || eventIDsJSON == "" {
		t.Fatalf("unexpected batch row: run=%s ingested=%d event_ids=%s", batchRunID, batchIngested, eventIDsJSON)
	}

	for _, typ := range []string{"execve", "network_connect", "file_write"} {
		events, err := ListEventsFiltered(db, Filter{RunID: "run-jsonl", Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("type %s events=%d, want 1", typ, len(events))
		}
		if events[0].ToolCallID != "tool-jsonl" || events[0].ProcessID != "process-jsonl" {
			t.Fatalf("event %s not correlated: %+v", typ, events[0])
		}
		if err := ValidateStoredPayload(events[0].EventType, events[0].Payload); err != nil {
			t.Fatalf("stored payload for %s is invalid: %v payload=%s", typ, err, events[0].Payload)
		}
	}
}

func TestIngestFalcoMapsRiskEventsAndCorrelates(t *testing.T) {
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
		RunID:         "run-falco",
		SessionID:     "session-falco",
		AttemptID:     "attempt-falco",
		ToolCallID:    "tool-falco",
		ProcessID:     "process-falco",
		ContainerID:   "container-falco",
		CgroupID:      "cgroup-falco",
		PID:           4242,
		StartedAt:     "2026-01-01T00:00:00Z",
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}

	raw := strings.NewReader(strings.Join([]string{
		`{"time":"2026-01-01T00:00:01Z","rule":"Terminal shell in container","priority":"Notice","output_fields":{"evt.type":"execve","proc.pid":4242,"proc.ppid":4000,"container.id":"container-falco","proc.cmdline":"sh -lc pytest -q"}}`,
		`{"time":"2026-01-01T00:00:02Z","rule":"Metadata service access","priority":"Critical","output_fields":{"evt.type":"connect","proc.pid":4242,"proc.ppid":4000,"container.id":"container-falco","fd.rip":"169.254.169.254:80"}}`,
		`{"time":"2026-01-01T00:00:03Z","rule":"Private network access","priority":"Warning","output_fields":{"evt.type":"connect","proc.pid":4242,"proc.ppid":4000,"container.id":"container-falco","fd.rip":"10.0.0.5:443"}}`,
		`{"time":"2026-01-01T00:00:04Z","rule":"Secret file read","priority":"Critical","output_fields":{"evt.type":"openat","proc.pid":4242,"proc.ppid":4000,"container.id":"container-falco","fd.name":"/workspace/.env","evt.arg.flags":"O_RDONLY"}}`,
	}, "\n") + "\n")

	result, err := IngestFalco(db, FalcoIngestOptions{Path: "falco-stdout", RunID: ""}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Read != 4 || result.Ingested != 4 || result.Failed != 0 {
		t.Fatalf("unexpected falco result: %+v", result)
	}
	if result.ReceiverSummary.DetectedFormats["falco"] != 4 || result.ReceiverSummary.Resolved != 4 {
		t.Fatalf("unexpected falco receiver summary: %+v", result.ReceiverSummary)
	}
	for _, row := range result.Rows {
		if row.DetectedFormat != "falco" || row.Status != "ingested" || row.CorrelationMethod == "" {
			t.Fatalf("unexpected falco row result: %+v", row)
		}
	}
	for _, typ := range []string{"execve", "metadata_ip", "private_cidr", "secret_path"} {
		events, err := ListEventsFiltered(db, Filter{RunID: "run-falco", Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("type %s events=%d, want 1", typ, len(events))
		}
		if events[0].ToolCallID != "tool-falco" || events[0].ProcessID != "process-falco" {
			t.Fatalf("falco %s event not correlated: %+v", typ, events[0])
		}
		if events[0].Source != "falco_jsonl" {
			t.Fatalf("falco source = %s", events[0].Source)
		}
	}

	persisted := 0
	for _, eventID := range result.EventIDs {
		if _, ok, err := securitymodel.EvaluateRuntimeEvent(db, eventID); err != nil {
			t.Fatal(err)
		} else if ok {
			persisted++
		}
	}
	if persisted != 3 {
		t.Fatalf("persisted policy decisions = %d, want 3", persisted)
	}
	risks, err := securitymodel.ListRiskSignals(db, "run-falco")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 3 {
		t.Fatalf("risk signals = %d, want 3", len(risks))
	}
	responses, err := securitymodel.ListResponseActions(db, "run-falco")
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 3 {
		t.Fatalf("response actions = %d, want 3", len(responses))
	}
	for _, response := range responses {
		if response.TargetType == "" || response.TargetID == "" || response.ActionType == "" {
			t.Fatalf("response action missing target/action: %+v", response)
		}
	}
}

func TestIngestJSONLReportsBadRows(t *testing.T) {
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

	path := filepath.Join(root, "bad.jsonl")
	raw := "" +
		`not-json` + "\n" +
		`{"event_type":"file_write","path":"../escape"}` + "\n" +
		`{"event_type":"unknown"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := IngestJSONL(db, JSONLIngestOptions{Format: "loongcollector", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Read != 3 || result.Ingested != 0 || result.Failed != 2 || result.Skipped != 1 {
		t.Fatalf("unexpected bad-row result: %+v", result)
	}
	if result.BatchID == "" || result.FileSHA256 == "" || result.EventIDsSHA256 == "" {
		t.Fatalf("missing bad-row batch evidence fields: %+v", result)
	}
	if len(result.Rows) != 3 || result.ReceiverSummary.Failed != 2 || result.ReceiverSummary.Skipped != 1 {
		t.Fatalf("unexpected bad-row receiver evidence: rows=%+v summary=%+v", result.Rows, result.ReceiverSummary)
	}
}
