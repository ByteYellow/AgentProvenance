package effects

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRecordAndListExternalEffect(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	record, err := RecordEffect(db, CreateInput{
		RunID:           "run-1",
		AttemptID:       "attempt-1",
		ToolCallID:      "tool-1",
		ProcessID:       "proc-1",
		EffectType:      "api_call",
		Target:          "api.example.com/v1/tickets",
		Mode:            "dry-run",
		Decision:        "audit",
		CompensationRef: "ticket-compensate",
		Payload:         `{"redacted":true}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == "" {
		t.Fatal("expected generated effect id")
	}

	records, err := List(db, Filter{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Target != "api.example.com/v1/tickets" {
		t.Fatalf("unexpected target: %s", records[0].Target)
	}
	if records[0].Mode != "dry-run" || records[0].Decision != "audit" {
		t.Fatalf("unexpected gate result: mode=%s decision=%s", records[0].Mode, records[0].Decision)
	}
}

func TestRecordExternalEffectRejectsRollbackLikeMode(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = RecordEffect(db, CreateInput{
		RunID:      "run-1",
		EffectType: "api_call",
		Target:     "api.example.com",
		Mode:       "rollback",
		Decision:   "audit",
	})
	if err == nil {
		t.Fatal("expected rollback mode to be rejected")
	}
}
