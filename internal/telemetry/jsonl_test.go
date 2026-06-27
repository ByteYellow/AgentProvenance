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
	report, err := BuildCorrelationReport(db, CorrelationReportOptions{RunID: "run-jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "agentprovenance.telemetry_correlations/v1" || report.ResultSetID == "" || report.PageHash == "" || report.Count != 3 {
		t.Fatalf("unexpected correlation report: %+v", report)
	}
	for _, item := range report.Items {
		if item.Match.Status != "resolved" || item.ResolvedContext.ToolCallID != "tool-jsonl" || item.ResolvedContext.ProcessID != "process-jsonl" {
			t.Fatalf("unexpected correlation item: %+v", item)
		}
		if item.Match.BindingID == "" || len(item.Match.MatchedKeys) == 0 || item.Binding == nil {
			t.Fatalf("correlation item missing binding evidence: %+v", item)
		}
	}
	eventReport, err := BuildCorrelationReport(db, CorrelationReportOptions{EventID: report.Items[0].Event.ID})
	if err != nil {
		t.Fatal(err)
	}
	if eventReport.Count != 1 || eventReport.Items[0].Event.ID != report.Items[0].Event.ID {
		t.Fatalf("unexpected single-event correlation report: %+v", eventReport)
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

func TestIngestNativeSensorRiskEventsAndCorrelates(t *testing.T) {
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
		RunID:         "run-native",
		SessionID:     "session-native",
		AttemptID:     "attempt-native",
		ToolCallID:    "tool-native",
		ProcessID:     "process-native",
		ContainerID:   "container-native",
		CgroupID:      "cgroup-native",
		PID:           4242,
		StartedAt:     "2000-01-01T00:00:00.000000000Z",
		BindingSource: "external_telemetry",
	}); err != nil {
		t.Fatal(err)
	}

	// These lines mimic exactly what cmd/agentprov-sensor writes one-per-line on
	// Linux (internal/sensor normalize()): flat objects, source="agentprov_ebpf".
	path := filepath.Join(root, "native.jsonl")
	raw := "" +
		`{"source":"agentprov_ebpf","pid":4242,"tgid":4242,"ppid":4000,"cgroup_id":"cgroup-native","container_id":"container-native","timestamp":"2026-01-01T00:00:01Z","comm":"sh","event_type":"execve","path":"/bin/sh"}` + "\n" +
		`{"source":"agentprov_ebpf","pid":4242,"tgid":4242,"ppid":4000,"cgroup_id":"cgroup-native","container_id":"container-native","timestamp":"2026-01-01T00:00:02Z","comm":"wget","event_type":"network_connect","dst_ip":"169.254.169.254","dst_port":80}` + "\n" +
		`{"source":"agentprov_ebpf","pid":4242,"tgid":4242,"ppid":4000,"cgroup_id":"cgroup-native","container_id":"container-native","timestamp":"2026-01-01T00:00:03Z","comm":"curl","event_type":"network_connect","dst_ip":"10.0.0.5","dst_port":443}` + "\n" +
		// The sensor write-filters openat in-kernel, so this is a write, and the
		// path is the real absolute host path the kernel reports. A write to a
		// credentials path is caught by the policy engine's path rule.
		`{"source":"agentprov_ebpf","pid":4242,"tgid":4242,"ppid":4000,"cgroup_id":"cgroup-native","container_id":"container-native","timestamp":"2026-01-01T00:00:04Z","comm":"sh","event_type":"file_open","path":"/home/agent/.aws/credentials"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := IngestJSONL(db, JSONLIngestOptions{Format: "auto", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Read != 4 || result.Ingested != 4 || result.Failed != 0 || result.Skipped != 0 {
		t.Fatalf("unexpected native result: %+v", result)
	}
	if result.ReceiverSummary.DetectedFormats["native"] != 4 || result.ReceiverSummary.Resolved != 4 {
		t.Fatalf("unexpected native receiver summary: %+v", result.ReceiverSummary)
	}
	for _, row := range result.Rows {
		if row.DetectedFormat != "native" || row.Status != "ingested" || row.CorrelationMethod == "" {
			t.Fatalf("unexpected native row result: %+v", row)
		}
	}
	for _, typ := range []string{"execve", "metadata_ip", "private_cidr", "file_write"} {
		events, err := ListEventsFiltered(db, Filter{RunID: "run-native", Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("type %s events=%d, want 1", typ, len(events))
		}
		if events[0].ToolCallID != "tool-native" || events[0].ProcessID != "process-native" {
			t.Fatalf("native %s event not correlated: %+v", typ, events[0])
		}
		if events[0].Source != "agentprov_ebpf" {
			t.Fatalf("native source = %s, want agentprov_ebpf", events[0].Source)
		}
		if err := ValidateStoredPayload(events[0].EventType, events[0].Payload); err != nil {
			t.Fatalf("stored payload for %s is invalid: %v payload=%s", typ, err, events[0].Payload)
		}
	}

	// The whole point of the loop: own kernel events -> automatic risk signals.
	persisted := 0
	for _, eventID := range result.EventIDs {
		if _, ok, err := securitymodel.EvaluateRuntimeEvent(db, eventID); err != nil {
			t.Fatal(err)
		} else if ok {
			persisted++
		}
	}
	if persisted != 3 {
		t.Fatalf("native policy decisions = %d, want 3 (metadata_ip + private_cidr + credential write)", persisted)
	}
	risks, err := securitymodel.ListRiskSignals(db, "run-native")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 3 {
		t.Fatalf("native risk signals = %d, want 3", len(risks))
	}
}

func TestIngestJSONLReaderMatchesFileHash(t *testing.T) {
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

	// Same bytes a sensor would pipe; no binding, so events stay unresolved but
	// still ingest. The reader path (stdin pipe) must hash identically to the
	// equivalent saved file.
	bytesIn := `{"source":"agentprov_ebpf","pid":7,"event_type":"execve","path":"/bin/true"}` + "\n"
	path := filepath.Join(root, "piped.jsonl")
	if err := os.WriteFile(path, []byte(bytesIn), 0o644); err != nil {
		t.Fatal(err)
	}

	fromFile, err := IngestJSONL(db, JSONLIngestOptions{Format: "native", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	fromReader, err := IngestJSONLReader(db, JSONLIngestOptions{Format: "native", Path: "-"}, strings.NewReader(bytesIn))
	if err != nil {
		t.Fatal(err)
	}
	if fromFile.Ingested != 1 || fromReader.Ingested != 1 {
		t.Fatalf("ingested file=%d reader=%d, want 1 each", fromFile.Ingested, fromReader.Ingested)
	}
	if fromFile.FileSHA256 == "" || fromFile.FileSHA256 != fromReader.FileSHA256 {
		t.Fatalf("file hash %q != reader hash %q", fromFile.FileSHA256, fromReader.FileSHA256)
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

func TestNativeLLMIntentCausesSyscallEdge(t *testing.T) {
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
		RunID: "run-llm", SessionID: "s", AttemptID: "a", ToolCallID: "tc", ProcessID: "p",
		ContainerID: "c-llm", StartedAt: "2000-01-01T00:00:00.000000000Z", BindingSource: "external_telemetry",
	}); err != nil {
		t.Fatal(err)
	}

	// An LLM response (tls_read) observed in the scope, then an exec it caused.
	path := filepath.Join(root, "llm.jsonl")
	raw := "" +
		`{"source":"agentprov_ebpf","pid":900,"container_id":"c-llm","event_type":"tls_read","data":"HTTP/1.1 200 OK\r\n\r\n{\"tool\":\"bash\",\"cmd\":\"id\"}","length":120}` + "\n" +
		`{"source":"agentprov_ebpf","pid":900,"container_id":"c-llm","event_type":"execve","path":"/bin/id","command":"id"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := IngestJSONL(db, JSONLIngestOptions{Format: "native", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ingested != 2 {
		t.Fatalf("ingested=%d, want 2 (%+v)", result.Ingested, result.Errors)
	}

	// The tls_read preview must be hashed, not stored whole.
	reads, err := ListEventsFiltered(db, Filter{RunID: "run-llm", Type: "tls_read"})
	if err != nil || len(reads) != 1 {
		t.Fatalf("tls_read events=%d err=%v", len(reads), err)
	}
	if !strings.Contains(reads[0].Payload, "preview_sha256") {
		t.Fatalf("tls_read payload missing preview_sha256: %s", reads[0].Payload)
	}

	// The causal edge: llm response -> the exec it caused.
	var from, to string
	if err := db.QueryRow(`SELECT from_id, to_id FROM graph_edges WHERE edge_type = 'llm_intent_caused' AND run_id = 'run-llm'`).Scan(&from, &to); err != nil {
		t.Fatalf("expected an llm_intent_caused edge: %v", err)
	}
	if !strings.HasPrefix(from, "runtime_event/") || !strings.HasPrefix(to, "runtime_event/") {
		t.Fatalf("unexpected edge nodes from=%s to=%s", from, to)
	}
	if from == to {
		t.Fatal("intent edge must link two distinct events")
	}
}
