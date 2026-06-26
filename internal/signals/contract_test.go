package signals

import (
	"encoding/json"
	"sort"
	"testing"
)

// TestSignalSetWireContract locks the agentprovenance.signals/v1 wire format.
// External collectors, evaluators, and auditors build against these exact keys;
// a change here is a contract break and must come with a SchemaVersion bump and
// a documented migration.
func TestSignalSetWireContract(t *testing.T) {
	db := newDB(t)
	if _, err := Record(db, Signal{
		Dimension: Security, Type: "policy_violation", RunID: "run-c", ProcessID: "p1",
		GraphRefKind: "process", GraphRefID: "p1", Severity: "high", RecommendedAction: "deny",
		ProducedBy: "security.policy",
	}); err != nil {
		t.Fatal(err)
	}
	set, err := Export(db, "run-c")
	if err != nil {
		t.Fatal(err)
	}
	if set.SchemaVersion != "agentprovenance.signals/v1" {
		t.Fatalf("schema version drift: %q", set.SchemaVersion)
	}

	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "SignalSet", generic, []string{"schema_version", "run_id", "count", "counts", "signals"})

	var sigs []map[string]json.RawMessage
	if err := json.Unmarshal(generic["signals"], &sigs); err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	// Always-present signal keys (omitempty fields like session_id may be absent;
	// the ones below are the stable backbone of the contract).
	for _, k := range []string{"id", "dimension", "type", "graph_ref_kind", "graph_ref_id", "run_id", "value", "confidence", "produced_by", "evidence_refs", "payload", "created_at"} {
		if _, ok := sigs[0][k]; !ok {
			t.Fatalf("contract signal missing required key %q; present: %v", k, keysOf(sigs[0]))
		}
	}
}

func assertKeys(t *testing.T, what string, m map[string]json.RawMessage, want []string) {
	t.Helper()
	got := keysOf(m)
	gotSet := map[string]bool{}
	for _, k := range got {
		gotSet[k] = true
	}
	for _, k := range want {
		if !gotSet[k] {
			t.Fatalf("%s contract missing key %q; present: %v", what, k, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%s contract key set changed: got %v want %v", what, got, want)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
