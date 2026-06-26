package signal

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// TestPersistEvalSignalsLandsOnUnifiedModel verifies the Quality pillar is now a
// first-class citizen of the unified signal store (not Python/JSONL only).
func TestPersistEvalSignalsLandsOnUnifiedModel(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	evals := []EvalSignal{
		{ID: "signal-001", Name: "task_success", Kind: KindRewardFeature, RunID: "run-q", ToolCallID: "tc-1", Score: 0.9, Label: "pass", Reason: "tests green"},
		{ID: "signal-002", Name: "risk_penalty", Kind: KindPenalty, RunID: "run-q", Score: -0.5, Reason: "blocked egress"},
	}
	n, err := PersistEvalSignals(db, "pytest-eval", evals)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("persisted %d, want 2", n)
	}

	got, err := signals.Query(db, signals.Filter{RunID: "run-q", Dimension: signals.Quality})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("quality signals = %d, want 2", len(got))
	}
	byType := map[string]signals.Signal{}
	for _, s := range got {
		byType[s.Type] = s
		if s.Dimension != signals.Quality {
			t.Fatalf("dimension = %s, want quality", s.Dimension)
		}
		if s.ProducedBy != "evaluator:pytest-eval" {
			t.Fatalf("produced_by = %q", s.ProducedBy)
		}
		if s.SourceTable != "eval_signals" {
			t.Fatalf("source_table = %q, want eval_signals", s.SourceTable)
		}
	}
	if byType["task_success"].GraphRefKind != "tool_call" || byType["task_success"].GraphRefID != "tc-1" {
		t.Fatalf("reward graph ref wrong: %+v", byType["task_success"])
	}
	if byType["task_success"].Value != 0.9 {
		t.Fatalf("reward value = %g, want 0.9", byType["task_success"].Value)
	}
	if byType["task_success"].Label != "pass" {
		t.Fatalf("quality label = %q, want pass (label, not severity)", byType["task_success"].Label)
	}
	if byType["task_success"].Severity != "" {
		t.Fatalf("quality signal should not set severity, got %q", byType["task_success"].Severity)
	}
	if byType["risk_penalty"].GraphRefKind != "run" {
		t.Fatalf("penalty graph ref should fall back to run: %+v", byType["risk_penalty"])
	}

	// Idempotent re-import.
	n2, err := PersistEvalSignals(db, "pytest-eval", evals)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("re-import persisted %d, want 0 (idempotent)", n2)
	}
}
