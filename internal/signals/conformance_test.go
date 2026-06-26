package signals

import (
	"encoding/json"
	"testing"
)

func validSignal() Signal {
	return Signal{
		ID: "sig-1", Dimension: Security, Type: "policy_violation",
		GraphRefKind: "process", GraphRefID: "p1", RunID: "run-1",
		Confidence: 1, EvidenceRefs: "[]", Payload: "{}", ProducedBy: "security.policy",
		CreatedAt: "2026-06-26T00:00:00Z",
	}
}

func TestValidateSignalAcceptsValid(t *testing.T) {
	if err := ValidateSignal(validSignal()); err != nil {
		t.Fatalf("valid signal rejected: %v", err)
	}
}

func TestValidateSignalRejects(t *testing.T) {
	cases := map[string]func(*Signal){
		"bad dimension":   func(s *Signal) { s.Dimension = "bogus" },
		"empty type":      func(s *Signal) { s.Type = "" },
		"confidence high": func(s *Signal) { s.Confidence = 2 },
		"confidence neg":  func(s *Signal) { s.Confidence = -0.1 },
		"missing graph":   func(s *Signal) { s.GraphRefKind = ""; s.GraphRefID = "" },
		"half source":     func(s *Signal) { s.SourceTable = "risk_signals"; s.SourceID = "" },
		"bad refs":        func(s *Signal) { s.EvidenceRefs = "not-json" },
		"bad payload":     func(s *Signal) { s.Payload = "[1,2]" }, // array, not object
	}
	for name, mutate := range cases {
		s := validSignal()
		mutate(&s)
		if err := ValidateSignal(s); err == nil {
			t.Fatalf("%s: expected validation error, got nil", name)
		}
	}
}

func TestValidateSetConsistency(t *testing.T) {
	good := SignalSet{
		SchemaVersion: SchemaVersion, RunID: "run-1", Count: 1,
		Counts:  map[string]int{"security": 1},
		Signals: []Signal{validSignal()},
	}
	if err := ValidateSet(good); err != nil {
		t.Fatalf("good set rejected: %v", err)
	}

	badCount := good
	badCount.Count = 5
	if err := ValidateSet(badCount); err == nil {
		t.Fatal("count mismatch not caught")
	}

	badCounts := good
	badCounts.Counts = map[string]int{"security": 99}
	if err := ValidateSet(badCounts); err == nil {
		t.Fatal("counts mismatch not caught")
	}

	badVersion := good
	badVersion.SchemaVersion = "agentprovenance.signals/v999"
	if err := ValidateSet(badVersion); err == nil {
		t.Fatal("schema version mismatch not caught")
	}
}

// TestExportRoundTripsThroughValidator is the contract self-consistency check:
// our own Export output must validate against our own conformance validator.
func TestExportRoundTripsThroughValidator(t *testing.T) {
	db := newDB(t)
	mustRecord(t, db, Signal{Dimension: Security, Type: "a", RunID: "run-rt", GraphRefKind: "run", GraphRefID: "run-rt"})
	mustRecord(t, db, Signal{Dimension: Quality, Type: "b", RunID: "run-rt", GraphRefKind: "run", GraphRefID: "run-rt", Label: "pass"})

	set, err := Export(db, "run-rt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateWireBytes(raw)
	if err != nil {
		t.Fatalf("own Export failed conformance: %v", err)
	}
	if got.Count != 2 {
		t.Fatalf("round-trip count = %d, want 2", got.Count)
	}
}

func TestValidateWireBytesRejectsUnknownField(t *testing.T) {
	raw := []byte(`{"schema_version":"` + SchemaVersion + `","run_id":"r","count":0,"counts":{},"signals":[],"bogus":true}`)
	if _, err := ValidateWireBytes(raw); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
}
