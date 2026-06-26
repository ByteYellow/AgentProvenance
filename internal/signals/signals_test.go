package signals

import (
	"database/sql"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"

	_ "modernc.org/sqlite"
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRecordAndQueryRoundtrip(t *testing.T) {
	db := newDB(t)
	id, err := Record(db, Signal{
		Dimension: Security, Type: "ssrf_attempt", RunID: "run1", ProcessID: "proc1",
		GraphRefKind: "process", GraphRefID: "proc1", Severity: "high", RecommendedAction: "deny",
		ProducedBy: "security.policy",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id == "" {
		t.Fatal("Record returned empty id")
	}
	got, err := Query(db, Filter{RunID: "run1", Dimension: Security})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d signals, want 1", len(got))
	}
	s := got[0]
	if s.Type != "ssrf_attempt" || s.Severity != "high" || s.ProcessID != "proc1" {
		t.Fatalf("unexpected signal: %+v", s)
	}
	if s.Confidence != 1 {
		t.Fatalf("confidence defaulted to %g, want 1", s.Confidence)
	}
	if s.EvidenceRefs != "[]" || s.Payload != "{}" {
		t.Fatalf("JSON defaults wrong: refs=%q payload=%q", s.EvidenceRefs, s.Payload)
	}
}

func TestRecordRejectsInvalidDimension(t *testing.T) {
	db := newDB(t)
	if _, err := Record(db, Signal{Dimension: "bogus", Type: "x", RunID: "r"}); err == nil {
		t.Fatal("expected error for invalid dimension, got nil")
	}
	if _, err := Record(db, Signal{Dimension: Security, Type: "  ", RunID: "r"}); err == nil {
		t.Fatal("expected error for empty type, got nil")
	}
}

func TestQueryFiltersByDimension(t *testing.T) {
	db := newDB(t)
	mustRecord(t, db, Signal{Dimension: Security, Type: "a", RunID: "r"})
	mustRecord(t, db, Signal{Dimension: Quality, Type: "b", RunID: "r"})
	mustRecord(t, db, Signal{Dimension: Cost, Type: "c", RunID: "r"})

	all, err := Query(db, Filter{RunID: "r"})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d, want 3", len(all))
	}
	quality, err := Query(db, Filter{RunID: "r", Dimension: Quality})
	if err != nil {
		t.Fatalf("Query quality: %v", err)
	}
	if len(quality) != 1 || quality[0].Type != "b" {
		t.Fatalf("quality filter wrong: %+v", quality)
	}
}

// TestProjectionIsIdempotent is the keystone guarantee: projecting the legacy
// silos into the unified model can run repeatedly (backfill / periodic sync)
// without creating duplicates.
func TestProjectionIsIdempotent(t *testing.T) {
	db := newDB(t)
	seedLegacySilos(t, db)

	first, err := Backfill(db)
	if err != nil {
		t.Fatalf("Backfill 1: %v", err)
	}
	if first != 3 {
		t.Fatalf("first backfill projected %d rows, want 3", first)
	}

	// Second run must project nothing new (idempotent on source_table+source_id).
	second, err := Backfill(db)
	if err != nil {
		t.Fatalf("Backfill 2: %v", err)
	}
	if second != 0 {
		t.Fatalf("second backfill projected %d rows, want 0 (idempotent)", second)
	}

	counts, err := Counts(db, "run1")
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts[Security] != 2 { // risk_signal + baseline_deviation
		t.Fatalf("security count = %d, want 2", counts[Security])
	}
	if counts[Cost] != 1 {
		t.Fatalf("cost count = %d, want 1", counts[Cost])
	}
}

func TestProjectedSignalsCarrySourceProvenance(t *testing.T) {
	db := newDB(t)
	seedLegacySilos(t, db)
	if _, err := Backfill(db); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	got, err := Query(db, Filter{RunID: "run1", Dimension: Cost})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d cost signals, want 1", len(got))
	}
	if got[0].SourceTable != "cost_samples" || got[0].SourceID != "cost1" {
		t.Fatalf("missing source provenance: %+v", got[0])
	}
	if got[0].Value != 12.5 || got[0].Reference != "active_cpu_seconds" {
		t.Fatalf("cost value/reference wrong: %+v", got[0])
	}
}

func mustRecord(t *testing.T, db *sql.DB, s Signal) {
	t.Helper()
	if _, err := Record(db, s); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func seedLegacySilos(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO risk_signals
		(id, run_id, session_id, tool_call_id, process_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk1', 'run1', 'sess1', 'tc1', 'proc1', 'ssrf_attempt', 'high', 'metadata IP', 'deny', datetime('now'))`); err != nil {
		t.Fatalf("seed risk_signals: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO baseline_deviations
		(id, run_id, deviation_type, status, expected_value, observed_value, recommended_action, created_at)
		VALUES ('dev1', 'run1', 'process_count', 'anomalous', 2, 9, 'audit', datetime('now'))`); err != nil {
		t.Fatalf("seed baseline_deviations: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO cost_samples
		(id, run_id, session_id, active_cpu_seconds, wall_seconds, created_at)
		VALUES ('cost1', 'run1', 'sess1', 12.5, 30, datetime('now'))`); err != nil {
		t.Fatalf("seed cost_samples: %v", err)
	}
}
