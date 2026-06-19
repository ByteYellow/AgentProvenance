package provenance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestExplainFileJSONManifest(t *testing.T) {
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
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-explain-json",
		Name:    "explain-json",
		Workdir: workdir,
		Command: []string{"python3", "-c", `import subprocess, time; subprocess.Popen(["sleep", "0.8"]); time.sleep(0.08); open("app.py", "w").write("value = 2\n")`},
	})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Explain(db, ExplainOptions{RunID: "run-explain-json", File: "app.py", WithJSON: true}, &out); err != nil {
		t.Fatal(err)
	}
	var manifest ExplainManifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid explain json: %v\n%s", err, out.String())
	}
	if manifest.SchemaVersion != "agentprovenance.explain/v1" {
		t.Fatalf("schema_version = %q", manifest.SchemaVersion)
	}
	if manifest.Target.Type != "file" || manifest.Target.Run != "run-explain-json" || manifest.Target.File != "app.py" {
		t.Fatalf("unexpected target: %+v", manifest.Target)
	}
	if manifest.FileDiff == nil || manifest.FileDiff.SchemaVersion != "agentprovenance.diff/v1" {
		t.Fatalf("missing diff manifest: %+v", manifest.FileDiff)
	}
	if manifest.FileBlame == nil || manifest.FileBlame.SchemaVersion != "agentprovenance.blame/v1" {
		t.Fatalf("missing blame manifest: %+v", manifest.FileBlame)
	}
	if len(manifest.RuntimeEvents) == 0 || manifest.RuntimeEvents[0].ToolCallID != result.ToolCallID || manifest.RuntimeEvents[0].ProcessID != result.ProcessID {
		t.Fatalf("runtime events not correlated to record context: %+v", manifest.RuntimeEvents)
	}
	if len(manifest.Upstream) == 0 {
		t.Fatalf("expected upstream edges for file explain")
	}
	if len(manifest.ReplayRefs) == 0 {
		t.Fatalf("expected replay refs for file explain")
	}
	if len(manifest.ProcessObs) == 0 {
		t.Fatalf("expected process observations in file explain")
	}
	hasOutlivedRoot := false
	for _, obs := range manifest.ProcessObs {
		if obs.OutlivedRoot {
			hasOutlivedRoot = true
			if obs.Boundary != "root_pid_descendants+cwd+time_window" || obs.OrphanPolicy != "observe_only" {
				t.Fatalf("unexpected process observation boundary/policy: %+v", obs)
			}
			if obs.SourceEventID == "" || obs.ProcessID != result.ProcessID || obs.ToolCallID != result.ToolCallID {
				t.Fatalf("process observation missing context refs: %+v", obs)
			}
			if len(obs.EvidenceIDs) == 0 || len(obs.PolicyDecisionIDs) == 0 {
				t.Fatalf("outlived process missing orphan lifecycle refs: %+v", obs)
			}
		}
	}
	if !hasOutlivedRoot {
		t.Fatalf("expected outlived root process observation: %+v", manifest.ProcessObs)
	}
	edgeTypes := map[string]bool{}
	for _, edge := range manifest.RuntimeEdges {
		edgeTypes[edge.EdgeType] = true
	}
	for _, want := range []string{"runtime_event_file", "runtime_process_file", "runtime_tool_call_file", "runtime_attempt_file"} {
		if !edgeTypes[want] {
			t.Fatalf("missing runtime edge %s in %+v", want, manifest.RuntimeEdges)
		}
	}
}

func TestExplainJSONV02EvidenceObjectsRisks(t *testing.T) {
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
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-explain-v02",
		Name:    "explain-v02",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at, processed_at)
		VALUES ('evidence-explain-v02', ?, ?, ?, ?, ?, ?, 'tool_call_finished', 'normal', '{"ok":true}', 'processed', ?, ?)`,
		result.RunID, result.RolloutID, result.AttemptID, result.SessionID, result.ToolCallID, result.BaseSnapshotID, now, now); err != nil {
		t.Fatal(err)
	}
	eventID := ""
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id = ? AND event_type = 'file_write' LIMIT 1`, result.RunID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-explain-v02', ?, ?, ?, 'test-rule', 'audit', 'test risk', ?)`,
		eventID, result.RunID, result.SessionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := effects.RecordEffect(db, effects.CreateInput{
		RunID:      result.RunID,
		RolloutID:  result.RolloutID,
		AttemptID:  result.AttemptID,
		SessionID:  result.SessionID,
		ToolCallID: result.ToolCallID,
		ProcessID:  result.ProcessID,
		EffectType: "api_call",
		Target:     "api.example.com",
		Mode:       "dry-run",
		Decision:   "audit",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (ObjectStore{DB: db, Paths: paths}).MaterializeRun(result.RunID); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Target.Type != "file" || manifest.Target.Run != result.RunID {
		t.Fatalf("unexpected target: %+v", manifest.Target)
	}
	if len(manifest.Upstream) == 0 {
		t.Fatalf("expected upstream edges: %+v", manifest)
	}
	hasEvidence := false
	for _, evidence := range manifest.Evidence {
		if evidence.ID == "evidence-explain-v02" {
			hasEvidence = true
		}
	}
	if !hasEvidence {
		t.Fatalf("expected evidence in explain manifest: %+v", manifest.Evidence)
	}
	if len(manifest.Objects) == 0 {
		t.Fatalf("expected content-addressed objects in explain manifest")
	}
	hasRecordManifest := false
	for _, object := range manifest.Objects {
		if object.Type == "record_manifest" {
			hasRecordManifest = true
		}
	}
	if !hasRecordManifest {
		t.Fatalf("expected record_manifest object ref: %+v", manifest.Objects)
	}
	if len(manifest.Risks) == 0 || manifest.Risks[0].Decision != "audit" {
		t.Fatalf("expected risk decision in explain manifest: %+v", manifest.Risks)
	}
	refs := map[string]bool{}
	for _, ref := range manifest.ReplayRefs {
		refs[ref.Kind] = true
	}
	for _, want := range []string{"attempt", "tool_call", "process", "event", "snapshot"} {
		if !refs[want] {
			t.Fatalf("missing replay ref %s in %+v", want, manifest.ReplayRefs)
		}
	}
}

func TestExplainJSONV02AllTargets(t *testing.T) {
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
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-explain-targets",
		Name:    "explain-targets",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py && echo artifact > artifact.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifactRef := filepath.Join(workdir, "artifact.txt")
	if _, err := db.Exec(`UPDATE fork_attempts SET artifact_result = ? WHERE id = ?`, artifactRef, result.AttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE tool_calls SET result_ref = ? WHERE id = ?`, artifactRef, result.ToolCallID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-attempt-artifact-targets', ?, ?, ?, ?, 'attempt_artifact', 'test', ?)`,
		result.RunID, result.RolloutID, result.AttemptID, artifactRef, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-tool-artifact-targets', ?, ?, ?, ?, 'tool_call_artifact', 'test', ?)`,
		result.RunID, result.RolloutID, result.ToolCallID, artifactRef, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at, processed_at)
		VALUES ('evidence-targets', ?, ?, ?, ?, ?, ?, 'target_explain', 'normal', '{"ok":true}', 'processed', ?, ?)`,
		result.RunID, result.RolloutID, result.AttemptID, result.SessionID, result.ToolCallID, result.BaseSnapshotID, now, now); err != nil {
		t.Fatal(err)
	}
	eventID := ""
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id = ? AND event_type = 'file_write' LIMIT 1`, result.RunID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-targets', ?, ?, ?, 'target-rule', 'audit', 'target risk', ?)`,
		eventID, result.RunID, result.SessionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := (ObjectStore{DB: db, Paths: paths}).MaterializeRun(result.RunID); err != nil {
		t.Fatal(err)
	}

	targets := []ExplainOptions{
		{Attempt: result.AttemptID},
		{ToolCall: result.ToolCallID},
		{Process: result.ProcessID},
		{Event: eventID},
		{Risk: "policy-targets"},
		{Artifact: artifactRef},
	}
	for _, opts := range targets {
		manifest, err := BuildExplain(db, opts)
		if err != nil {
			t.Fatalf("BuildExplain(%+v): %v", opts, err)
		}
		if manifest.Target.Run != result.RunID {
			t.Fatalf("target %+v run=%q, want %q", manifest.Target, manifest.Target.Run, result.RunID)
		}
		if len(manifest.ReplayRefs) == 0 {
			t.Fatalf("target %+v missing replay refs", manifest.Target)
		}
		if len(manifest.Objects) == 0 {
			t.Fatalf("target %+v missing object refs", manifest.Target)
		}
		hasEvidence := false
		for _, evidence := range manifest.Evidence {
			if evidence.ID == "evidence-targets" {
				hasEvidence = true
			}
		}
		if !hasEvidence {
			t.Fatalf("target %+v missing shared evidence: %+v", manifest.Target, manifest.Evidence)
		}
		if len(manifest.RuntimeEvents) == 0 {
			t.Fatalf("target %+v missing runtime events", manifest.Target)
		}
		if len(manifest.CausalityPath) == 0 {
			t.Fatalf("target %+v missing causality path", manifest.Target)
		}
		if manifest.Target.Type == "artifact" && len(manifest.Upstream) == 0 {
			t.Fatalf("artifact target missing provenance upstream edges: %+v", manifest)
		}
		if (manifest.Target.Type == "event" || manifest.Target.Type == "risk") && len(manifest.Risks) == 0 {
			t.Fatalf("event target missing risk decision: %+v", manifest)
		}
		if manifest.Target.Type == "risk" && manifest.Risks[0].ID != "policy-targets" {
			t.Fatalf("risk target returned wrong decision: %+v", manifest.Risks)
		}
	}
}

func TestExplainEventIncludesTelemetryAdapterDetails(t *testing.T) {
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
		RunID:         "run-explain-jsonl",
		SessionID:     "session-jsonl",
		AttemptID:     "attempt-jsonl",
		ToolCallID:    "tool-jsonl",
		ProcessID:     "process-jsonl",
		ContainerID:   "container-jsonl",
		PID:           4242,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "events.jsonl")
	raw := `{"process_exec":{"process":{"pid":4242,"binary":"/bin/sh","arguments":"-lc pytest -q","docker":"container-jsonl"}}}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "tetragon", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ingested != 1 || len(result.EventIDs) != 1 {
		t.Fatalf("unexpected ingest result: %+v", result)
	}
	if _, err := (ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-explain-jsonl"); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildExplain(db, ExplainOptions{Event: result.EventIDs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.RuntimeEvents) != 1 {
		t.Fatalf("expected one runtime event: %+v", manifest.RuntimeEvents)
	}
	event := manifest.RuntimeEvents[0]
	if event.Telemetry == nil {
		t.Fatalf("missing telemetry explanation: %+v", event)
	}
	if event.Telemetry.Receiver != "tetragon" || event.Telemetry.SourceFormat != "jsonl" {
		t.Fatalf("unexpected telemetry receiver/source: %+v", event.Telemetry)
	}
	if event.Telemetry.NormalizedEventType != "execve" || event.Telemetry.SchemaStatus != "valid" {
		t.Fatalf("unexpected normalized schema: %+v", event.Telemetry)
	}
	if event.Telemetry.CorrelationStatus != "resolved" || event.ToolCallID != "tool-jsonl" || event.ProcessID != "process-jsonl" {
		t.Fatalf("unexpected correlation details event=%+v telemetry=%+v", event, event.Telemetry)
	}
	if !containsString(event.Telemetry.IdentityKeys, "container_id") || !containsString(event.Telemetry.IdentityKeys, "pid") {
		t.Fatalf("missing identity keys: %+v", event.Telemetry.IdentityKeys)
	}
	if len(manifest.TelemetryBatches) != 1 {
		t.Fatalf("expected one telemetry batch: %+v", manifest.TelemetryBatches)
	}
	batch := manifest.TelemetryBatches[0]
	if batch.ID != result.BatchID || batch.FileSHA256 != result.FileSHA256 || batch.EventIDsSHA256 != result.EventIDsSHA256 {
		t.Fatalf("unexpected telemetry batch: %+v result=%+v", batch, result)
	}
	if !containsString(batch.EventIDs, result.EventIDs[0]) {
		t.Fatalf("telemetry batch missing event id: %+v", batch)
	}
	foundBatchObject := false
	for _, object := range manifest.Objects {
		if object.Type == "telemetry_batch" && object.SourceID == result.BatchID {
			foundBatchObject = true
			if object.ParentHashes == "" {
				t.Fatalf("telemetry batch object missing event parent hash: %+v", object)
			}
		}
	}
	if !foundBatchObject {
		t.Fatalf("explain objects missing telemetry batch object: %+v", manifest.Objects)
	}
}

func TestExplainCausalityPathDepthAndLimit(t *testing.T) {
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
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-explain-depth",
		Name:    "explain-depth",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	chain := []struct {
		id   string
		from string
		to   string
	}{
		{"edge-depth-1", "workspace_file/app.py", "node-depth-1"},
		{"edge-depth-2", "node-depth-1", "node-depth-2"},
		{"edge-depth-3", "node-depth-2", "node-depth-3"},
		{"edge-depth-4", "node-depth-3", "node-depth-4"},
	}
	for _, edge := range chain {
		if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, ?, 'test_depth_edge', 'test', ?)`,
			edge.id, result.RunID, result.RolloutID, edge.from, edge.to, now); err != nil {
			t.Fatal(err)
		}
	}

	shallow, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py", Depth: 1, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if shallow.Query.Depth != 1 || shallow.Query.Limit != 100 {
		t.Fatalf("unexpected shallow query metadata: %+v", shallow.Query)
	}
	if containsExplainEdge(shallow.CausalityPath, "node-depth-3") {
		t.Fatalf("depth=1 reached remote node: %+v", shallow.CausalityPath)
	}

	deep, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py", Depth: 4, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !containsExplainEdge(deep.CausalityPath, "node-depth-4") {
		t.Fatalf("depth=4 did not reach remote node: %+v", deep.CausalityPath)
	}
	if deep.Query.Truncated {
		t.Fatalf("deep query should not be truncated: %+v", deep.Query)
	}
	if deep.Query.EdgeCount != len(deep.CausalityPath) || deep.Query.NodeCount < 5 {
		t.Fatalf("unexpected deep query metadata: %+v path=%+v", deep.Query, deep.CausalityPath)
	}

	limited, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py", Depth: 4, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !limited.Query.Truncated || !limited.Query.FrontierHit {
		t.Fatalf("limit=2 should truncate traversal: %+v", limited.Query)
	}
	if limited.Query.ResultSetID == "" || limited.Query.PageHash == "" {
		t.Fatalf("limited query missing integrity metadata: %+v", limited.Query)
	}
	if limited.Query.NextCursor == "" {
		t.Fatalf("limit=2 should emit next cursor: %+v", limited.Query)
	}
	if limited.Query.NextCursor == "2" {
		t.Fatalf("explain cursor should be opaque: %q", limited.Query.NextCursor)
	}
	if len(limited.CausalityPath) != 2 || limited.Query.EdgeCount != 2 {
		t.Fatalf("limit=2 returned unexpected path: query=%+v path=%+v", limited.Query, limited.CausalityPath)
	}
	page2, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py", Depth: 4, Limit: 2, Cursor: limited.Query.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Query.Cursor != limited.Query.NextCursor {
		t.Fatalf("page2 cursor = %q, want %q", page2.Query.Cursor, limited.Query.NextCursor)
	}
	if page2.Query.ResultSetID != limited.Query.ResultSetID {
		t.Fatalf("paged explain result_set_id changed: page1=%s page2=%s", limited.Query.ResultSetID, page2.Query.ResultSetID)
	}
	if page2.Query.PageHash == "" || page2.Query.PageHash == limited.Query.PageHash {
		t.Fatalf("paged explain page_hash should be present and different: page1=%s page2=%s", limited.Query.PageHash, page2.Query.PageHash)
	}
	if len(page2.CausalityPath) == 0 {
		t.Fatalf("page2 should continue traversal: %+v", page2.Query)
	}
	if page2.CausalityPath[0] == limited.CausalityPath[0] || page2.CausalityPath[0] == limited.CausalityPath[1] {
		t.Fatalf("page2 repeated page1 edge: page1=%+v page2=%+v", limited.CausalityPath, page2.CausalityPath)
	}
	if _, err := BuildExplain(db, ExplainOptions{RunID: result.RunID, File: "app.py", Depth: 4, Limit: 2, Cursor: "2"}); err == nil {
		t.Fatalf("old-style explain cursor should be rejected")
	}
}

func containsExplainEdge(edges []ExplainGraphEdge, node string) bool {
	for _, edge := range edges {
		if edge.FromID == node || edge.ToID == node {
			return true
		}
	}
	return false
}

func TestPhase1JSONSchemaVersions(t *testing.T) {
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
	if _, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-schema",
		Name:    "schema",
		Workdir: workdir,
		Command: []string{"sh", "-lc", "printf 'value = 2\\n' > app.py"},
	}); err != nil {
		t.Fatal(err)
	}

	replay, err := BuildReplayRun(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	verify, err := Verify(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	trajectories, err := BuildTrajectoriesRun(db, "run-schema")
	if err != nil {
		t.Fatal(err)
	}
	diff, err := BuildDiffFile(db, "run-schema", "app.py")
	if err != nil {
		t.Fatal(err)
	}
	blame, err := BuildBlameFile(db, "run-schema", "app.py")
	if err != nil {
		t.Fatal(err)
	}
	explain, err := BuildExplain(db, ExplainOptions{RunID: "run-schema", File: "app.py"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{
		"replay":       replay.SchemaVersion,
		"verify":       verify.SchemaVersion,
		"trajectories": trajectories.SchemaVersion,
		"diff":         diff.SchemaVersion,
		"blame":        blame.SchemaVersion,
		"explain":      explain.SchemaVersion,
	}
	want := map[string]string{
		"replay":       "agentprovenance.replay/v1",
		"verify":       "agentprovenance.verify/v1",
		"trajectories": "agentprovenance.trajectories/v1",
		"diff":         "agentprovenance.diff/v1",
		"blame":        "agentprovenance.blame/v1",
		"explain":      "agentprovenance.explain/v1",
	}
	for key, wantVersion := range want {
		if got[key] != wantVersion {
			t.Fatalf("%s schema = %q, want %q", key, got[key], wantVersion)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
