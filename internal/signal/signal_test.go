package signal

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBuildRunReportEmitsEvaluatorSignals(t *testing.T) {
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

	base := filepath.Join(root, "base")
	workspace := filepath.Join(root, "attempt")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "app.py"), []byte("print('old')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "app.py"), []byte("print('new')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(paths.Artifacts, "result.patch")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execSQL(t, db, `INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES ('snap-signal', 'ready', 'ready', 'test', ?, 'hash', 1, 32, 'ready', ?)`, base, now)
	execSQL(t, db, `INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-signal', 'run-signal', 'snap-signal', 'completed', 1, 'attempt-signal', '', 'clean', ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, is_winner, artifact_result, score, cost_estimate, created_at)
		VALUES ('attempt-signal', 'rollout-signal', 'tool-signal', 'snap-signal', ?, 1, 'fix', 'pytest -q', 'passed', 'clean', 1, ?, 5, 0.01, ?)`, workspace, artifact, now)
	execSQL(t, db, `INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-signal', 'run-signal', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-signal', 'lease-signal', 'run-signal', ?, 'stopped', ?, ?)`, workspace, now, now)
	execSQL(t, db, `INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at, started_at, ended_at)
		VALUES ('tool-signal', 'run-signal', 'rollout-signal', 'attempt-signal', 'session-signal', 'pytest -q', 'passed', 0, ?, ?, ?, ?)`, artifact, now, now, now)
	execSQL(t, db, `INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-signal', 'session-signal', 'tool-signal', 'pytest -q', 'exited', 0, ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-signal', 'run-signal', 'session-signal', 'tool-signal', 'process-signal', 'native_runtime', 'execve', '{"argv":["pytest","-q"]}', ?, 'provided_context', 1)`, now)

	report, err := BuildRunReport(db, "run-signal")
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "agentprovenance.eval_signals/v1" || report.DecisionOwner != "external_evaluator" || report.SignalCount == 0 {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.ResultSetID == "" || report.PageHash == "" {
		t.Fatalf("missing integrity hashes: %+v", report)
	}
	seen := map[string]EvalSignal{}
	for _, item := range report.Signals {
		seen[item.Name] = item
	}
	for _, name := range []string{"state.file_change_volume", "artifact.presence", "dataset.filter_label"} {
		if _, ok := seen[name]; !ok {
			t.Fatalf("missing signal %s in %+v", name, report.Signals)
		}
	}
	if seen["artifact.presence"].Label != "artifact_present" || seen["dataset.filter_label"].Label != "candidate" {
		t.Fatalf("unexpected signal labels: %+v", seen)
	}
}

func TestImportSignalsValidatesExternalSignals(t *testing.T) {
	report, err := ImportSignals("run-import", "pytest-evaluator", []EvalSignal{
		{
			Name:   "external.quality",
			Kind:   KindQualitySignal,
			Score:  0.8,
			Reason: "external evaluator provided a score",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Engine != "pytest-evaluator" || report.DecisionOwner != "external_evaluator" || report.SignalCount != 1 {
		t.Fatalf("unexpected imported report: %+v", report)
	}
	if report.Signals[0].RunID != "run-import" || report.Signals[0].ID != "signal-001" {
		t.Fatalf("signal metadata not normalized: %+v", report.Signals[0])
	}

	if _, err := ImportSignals("run-import", "", []EvalSignal{{Name: "bad", Kind: Kind("unknown"), Reason: "bad"}}); err == nil {
		t.Fatal("expected invalid kind to fail")
	}
	if _, err := ImportSignals("run-import", "", []EvalSignal{{Name: "bad", Kind: KindPenalty}}); err == nil {
		t.Fatal("expected missing reason to fail")
	}
	if _, err := ImportSignals("run-import", "", []EvalSignal{{Name: "bad", Kind: KindPenalty, RunID: "other", Reason: "bad"}}); err == nil {
		t.Fatal("expected run_id mismatch to fail")
	}
}

func TestImportBatchReportsSummarizesManyRuns(t *testing.T) {
	report, err := ImportBatchReports("python-sdk", []EvalReport{
		{
			RunID: "run-a",
			Signals: []EvalSignal{{
				Name:   "reward.a",
				Kind:   KindRewardFeature,
				Score:  1,
				Reason: "accepted",
			}},
		},
		{
			RunID: "run-b",
			Signals: []EvalSignal{{
				Name:   "penalty.b",
				Kind:   KindPenalty,
				Score:  -1,
				Reason: "rejected",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "agentprovenance.eval_signal_batch_import/v1" || report.Engine != "python-sdk" {
		t.Fatalf("unexpected batch report header: %+v", report)
	}
	if report.ReportCount != 2 || report.RunCount != 2 || report.SignalCount != 2 || report.Failed != 0 {
		t.Fatalf("unexpected batch counts: %+v", report)
	}
	if report.ResultSetID == "" || report.PageHash == "" {
		t.Fatalf("missing batch integrity hashes: %+v", report)
	}
	if report.Runs[0].Signals[0].RunID != "run-a" || report.Runs[1].Signals[0].RunID != "run-b" {
		t.Fatalf("signals were not normalized per run: %+v", report.Runs)
	}

	withError, err := ImportBatchReports("python-sdk", []EvalReport{
		{RunID: "run-ok", Signals: []EvalSignal{{Name: "ok", Kind: KindQualitySignal, Reason: "ok"}}},
		{RunID: "run-bad", Signals: []EvalSignal{{Name: "bad", Kind: Kind("bad"), Reason: "bad"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if withError.Failed != 1 || len(withError.Errors) != 1 || withError.SignalCount != 1 {
		t.Fatalf("expected partial batch import error: %+v", withError)
	}
}

func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
