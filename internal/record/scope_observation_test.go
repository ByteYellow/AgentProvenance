package record

import (
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestRecordCompletionStoresScopeObservation(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	r, err := (Service{DB: db, Paths: paths}).Run(Request{RunID: "scope-observed",
		Command: []string{"printf", "done"}, DisableSnapshot: true, PostRootGraceMS: 1,
		Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM events WHERE id=?`, r.EndEventID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var event struct {
		Observation *struct {
			ScopeKind  string `json:"scope_kind"`
			CgroupID   string `json:"cgroup_id"`
			ObservedAt string `json:"observed_at"`
			Empty      *bool  `json:"empty"`
		} `json:"scope_observation"`
	}
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatal(err)
	}
	o := event.Observation
	if o == nil || o.CgroupID != r.Scope.CgroupID || o.ScopeKind != r.Scope.ScopeKind {
		t.Fatalf("completion lacks owned-scope observation: %s", payload)
	}
	if _, err := time.Parse(time.RFC3339Nano, o.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if o.ScopeKind == "cgroup" && (o.Empty == nil || !*o.Empty) {
		t.Fatalf("finished command scope not observed empty: %+v", o)
	}
	if o.ScopeKind == "logical_process_scope" && o.Empty != nil {
		t.Fatalf("logical scope reported kernel population: %+v", o)
	}
}
