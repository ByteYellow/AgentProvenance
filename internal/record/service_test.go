package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
		RunID:            "run-record-test",
		Name:             "record-test",
		Workdir:          workdir,
		Command:          []string{"sh", "-lc", "(sleep 0.2) & printf 'value = 2\\n' > app.py && echo note > note.txt && wait"},
		SampleIntervalMS: 10,
		PostRootGraceMS:  300,
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
	if result.RootPID == 0 || result.CWD != workdir || result.StartedAt == "" || result.EndedAt == "" {
		t.Fatalf("record result missing zero-SDK scope fields: %+v", result)
	}
	if len(result.Observed) == 0 {
		t.Fatalf("record result missing observed descendants: %+v", result)
	}
	if result.OrphanPolicy != "observe_only" || result.PostRootGraceMS == 0 {
		t.Fatalf("record result missing orphan policy: %+v", result)
	}
	if result.SampleIntervalMS != 10 || result.PostRootGraceMS != 300 {
		t.Fatalf("record result missing configured sampling windows: %+v", result)
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
	observedEvents, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: "run-record-test", Type: "process_observed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(observedEvents) == 0 {
		t.Fatalf("missing process_observed telemetry")
	}
	for _, event := range observedEvents {
		if event.RawEventID == "" || event.CorrelationMethod != "zero_sdk_process_tree" || event.CorrelationConfidence != 0.9 {
			t.Fatalf("process_observed missing raw/correlation metadata: %+v", event)
		}
		if event.ContainerID == "" || event.CgroupID == "" || event.PID == 0 || event.TGID == 0 || event.PPID == 0 {
			t.Fatalf("process_observed missing runtime identity: %+v", event)
		}
		explained := telemetry.ExplainEventRecord(event)
		if explained.Receiver != "record_process_sample" || explained.SourceFormat != "normalized" || explained.SchemaStatus != "valid" {
			t.Fatalf("process_observed explanation = %+v for event %+v", explained, event)
		}
	}
	childPID := result.Observed[0].PID
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RawEventID: "raw-child-record-test",
		PID:        childPID,
		Timestamp:  result.Observed[0].LastSeen,
		Source:     "zero_sdk_test",
		EventType:  "execve",
		Payload:    `{"argv":["observed-child"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	childEvents, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: "run-record-test", Type: "execve"})
	if err != nil {
		t.Fatal(err)
	}
	foundChild := false
	for _, event := range childEvents {
		if event.RawEventID != "raw-child-record-test" {
			continue
		}
		foundChild = true
		if event.ToolCallID != result.ToolCallID || event.ProcessID != result.ProcessID || event.CorrelationMethod != "pid_time_window:pid+time" {
			t.Fatalf("child telemetry not correlated through descendant binding: %+v result=%+v", event, result)
		}
	}
	if !foundChild {
		t.Fatalf("missing child telemetry event in %+v", childEvents)
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

	materialized, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-record-test")
	if err != nil {
		t.Fatal(err)
	}
	if materialized.ObjectCount == 0 {
		t.Fatalf("materialized object count = 0")
	}
	var objectPath, parentHashes string
	if err := db.QueryRow(`SELECT path, parent_hashes FROM provenance_objects
		WHERE run_id = ? AND object_type = 'record_manifest' AND source_id = ?`,
		"run-record-test", "run-record-test").Scan(&objectPath, &parentHashes); err != nil {
		t.Fatal(err)
	}
	if parentHashes == "" {
		t.Fatalf("record_manifest object has no parent hashes")
	}
	rawObject, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	var object struct {
		Type    string `json:"type"`
		Payload struct {
			Manifest provenance.RecordManifest `json:"manifest"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(rawObject, &object); err != nil {
		t.Fatal(err)
	}
	if object.Type != "record_manifest" {
		t.Fatalf("object type = %q, want record_manifest", object.Type)
	}
	if object.Payload.Manifest.SchemaVersion != "agentprovenance.record/v1" ||
		object.Payload.Manifest.ToolCallID != result.ToolCallID ||
		object.Payload.Manifest.RootPID != result.RootPID ||
		object.Payload.Manifest.ChangedFileCount != len(result.ChangedFiles) ||
		object.Payload.Manifest.ProcessTreeCount < 2 ||
		len(object.Payload.Manifest.ObservedProcesses) == 0 ||
		object.Payload.Manifest.OrphanPolicy != "observe_only" ||
		object.Payload.Manifest.PostRootGraceMS == 0 {
		t.Fatalf("unexpected record manifest: %+v result=%+v", object.Payload.Manifest, result)
	}
	verify, err := provenance.Verify(db, "run-record-test")
	if err != nil {
		t.Fatal(err)
	}
	if verify.ErrorCount != 0 {
		t.Fatalf("verify errors=%d issues=%+v", verify.ErrorCount, verify.Issues)
	}
}

func TestRecordMarksOrphanDescendantDuringGraceWindow(t *testing.T) {
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
	marker := filepath.Join(workdir, "orphan-marker")
	result, err := (Service{DB: db, Paths: paths}).Run(Request{
		RunID:   "run-record-orphan-test",
		Name:    "record-orphan-test",
		Workdir: workdir,
		Command: []string{"python3", "-c", `import subprocess, time; subprocess.Popen(["sleep", "0.8"]); time.sleep(0.08); open("orphan-marker", "w").write("started\n")`},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupObservedProcesses(result.Observed)
	foundOutlived := false
	for _, proc := range result.Observed {
		if proc.OutlivedRoot {
			foundOutlived = true
			break
		}
	}
	if !foundOutlived {
		t.Fatalf("expected outlived root descendant: %+v", result.Observed)
	}
	if result.OrphanPolicy != "observe_only" || result.PostRootGraceMS == 0 {
		t.Fatalf("missing orphan policy metadata: %+v", result)
	}
	if _, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-record-orphan-test"); err != nil {
		t.Fatal(err)
	}
	manifest, err := provenance.BuildRecordManifest(db, "run-record-orphan-test")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OrphanPolicy != "observe_only" || manifest.PostRootGraceMS == 0 {
		t.Fatalf("manifest missing orphan metadata: %+v", manifest)
	}
	foundOutlived = false
	for _, proc := range manifest.ObservedProcesses {
		if proc.OutlivedRoot {
			foundOutlived = true
			break
		}
	}
	if !foundOutlived {
		t.Fatalf("manifest missing outlived root descendant: %+v", manifest.ObservedProcesses)
	}
	var decisionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND rule_id = 'zero_sdk_orphan_observe_only' AND decision = 'audit'`,
		"run-record-orphan-test").Scan(&decisionCount); err != nil {
		t.Fatal(err)
	}
	if decisionCount == 0 {
		t.Fatalf("missing orphan lifecycle policy decision")
	}
	var evidenceCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence_events WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision'`,
		"run-record-orphan-test").Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount == 0 {
		t.Fatalf("missing orphan lifecycle evidence")
	}
	verify, err := provenance.Verify(db, "run-record-orphan-test")
	if err != nil {
		t.Fatal(err)
	}
	if verify.ErrorCount != 0 {
		t.Fatalf("verify errors=%d issues=%+v", verify.ErrorCount, verify.Issues)
	}
	timeline, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: "run-record-orphan-test", Type: "process_observed"})
	if err != nil {
		t.Fatal(err)
	}
	foundTimelineOutlived := false
	for _, event := range timeline.Events {
		if event.Source != "record_process_sample" || event.Type != "process_observed" {
			continue
		}
		if event.Evidence["scope_boundary"] != "root_pid_descendants+cwd+time_window" ||
			event.Evidence["correlation_source"] != "zero_sdk_record_process_tree" ||
			event.Evidence["schema_status"] != "valid" {
			t.Fatalf("process observation timeline missing zero-sdk evidence: %+v", event)
		}
		if outlived, ok := event.Evidence["outlived_root"].(bool); ok && outlived {
			foundTimelineOutlived = true
		}
	}
	if !foundTimelineOutlived {
		t.Fatalf("timeline missing outlived process observation: %+v", timeline.Events)
	}
	_ = os.Remove(marker)
}

func cleanupObservedProcesses(procs []ObservedProcess) {
	for _, proc := range procs {
		if proc.PID > 0 {
			_ = exec.Command("kill", "-TERM", fmt.Sprintf("%d", proc.PID)).Run()
		}
	}
}

func TestRecordStartFailureReturnsFailedManifest(t *testing.T) {
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

	result, err := (Service{DB: db, Paths: paths}).Run(Request{
		RunID:   "run-record-start-failure",
		Name:    "record-start-failure",
		Workdir: workdir,
		Command: []string{"./definitely-not-a-real-agentprov-command"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.ExitCode != 125 || result.FailureReason == "" {
		t.Fatalf("start failure result = %+v, want failed exit 125 with reason", result)
	}
	if result.AttemptID == "" || result.ToolCallID == "" || result.ProcessID == "" || result.StartedAt == "" || result.EndedAt == "" {
		t.Fatalf("start failure missing graph/time fields: %+v", result)
	}
	if _, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-record-start-failure"); err != nil {
		t.Fatal(err)
	}
	var manifestType string
	if err := db.QueryRow(`SELECT object_type FROM provenance_objects WHERE run_id = ? AND object_type = 'record_manifest'`,
		"run-record-start-failure").Scan(&manifestType); err != nil {
		t.Fatal(err)
	}
	verify, err := provenance.Verify(db, "run-record-start-failure")
	if err != nil {
		t.Fatal(err)
	}
	if verify.ErrorCount != 0 {
		t.Fatalf("verify errors=%d issues=%+v", verify.ErrorCount, verify.Issues)
	}
}
