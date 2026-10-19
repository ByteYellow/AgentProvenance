package correlation

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func resolutionDB(t *testing.T, bindings ...Binding) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, binding := range bindings {
		if _, err := RecordBinding(db, binding); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestResolveSharedScopeDoesNotChooseTool(t *testing.T) {
	for _, kind := range []string{"cgroup", "container"} {
		for _, count := range []int{1, 2} {
			t.Run(kind+strconv.Itoa(count), func(t *testing.T) {
				bindings := []Binding{
					{ID: "alice", RunID: "run", SessionID: "session", ToolCallID: "tool-alice", ProcessID: "proc-alice", PID: 10, CgroupID: "cg", ContainerID: "ctr", StartedAt: "2026-10-17T00:00:00Z"},
					{ID: "bob", RunID: "run", SessionID: "session", ToolCallID: "tool-bob", ProcessID: "proc-bob", PID: 20, CgroupID: "cg", ContainerID: "ctr", StartedAt: "2026-10-17T00:00:01Z"},
				}
				db := resolutionDB(t, bindings[:count]...)
				raw := RawIdentity{PID: 30, Timestamp: "2026-10-17T00:00:02Z"}
				if kind == "cgroup" {
					raw.CgroupID = "cg"
				} else {
					raw.ContainerID = "ctr"
				}
				match, ok, err := Resolve(db, raw)
				if err != nil || !ok || match.RunID != "run" || match.SessionID != "session" {
					t.Fatalf("scope = %+v, ok=%v err=%v", match, ok, err)
				}
				if match.ToolCallID != "" || match.ProcessID != "" || match.PID != 0 || match.RootPID != 0 {
					t.Fatalf("scope lookup borrowed a process/tool identity: %+v", match)
				}
				payload := EventPayloadWithCorrelation(`{"path":"/tmp/a"}`, match, ok)
				if !strings.Contains(payload, `"scope_only":true`) {
					t.Fatalf("missing scope-only evidence: %s", payload)
				}
				if count == 2 && (match.ID != "" || !strings.Contains(payload, `"candidate_binding_ids":["alice","bob"]`)) {
					t.Fatalf("overlap chose a binding: %+v %s", match, payload)
				}
			})
		}
	}
}

func TestResolveAmbiguousRunsDoNotFallBack(t *testing.T) {
	db := resolutionDB(t,
		Binding{ID: "a", RunID: "run-a", ToolCallID: "tool-a", CgroupID: "cg", ContainerID: "ctr", StartedAt: "2026-10-17T00:00:00Z"},
		Binding{ID: "b", RunID: "run-b", ToolCallID: "tool-b", CgroupID: "cg", StartedAt: "2026-10-17T00:00:01Z"},
	)
	match, ok, err := Resolve(db, RawIdentity{CgroupID: "cg", ContainerID: "ctr", Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || ok || match.RunID != "" || match.ToolCallID != "" {
		t.Fatalf("conflicting runs were resolved: %+v ok=%v err=%v", match, ok, err)
	}
	payload := EventPayloadWithCorrelation(`{}`, match, ok)
	if !json.Valid([]byte(payload)) || !strings.Contains(payload, `"ambiguous":true`) || !strings.Contains(payload, `"candidate_binding_ids":["a","b"]`) {
		t.Fatalf("lost ambiguity evidence: %s", payload)
	}
}

func TestResolvePIDDisambiguatesWithinObservedScope(t *testing.T) {
	db := resolutionDB(t,
		Binding{ID: "a", RunID: "run", ToolCallID: "tool-a", ProcessID: "proc-a", PID: 10, CgroupID: "cg", ContainerID: "ctr", StartedAt: "2026-10-17T00:00:00Z"},
		Binding{ID: "b", RunID: "run", ToolCallID: "tool-b", ProcessID: "proc-b", PID: 20, CgroupID: "cg", ContainerID: "ctr", StartedAt: "2026-10-17T00:00:01Z"},
		Binding{ID: "other-host", RunID: "other-run", ToolCallID: "other-tool", PID: 10, CgroupID: "other-cg", ContainerID: "other-ctr", StartedAt: "2026-10-17T00:00:01Z"},
		Binding{ID: "unscoped", RunID: "unknown-run", ToolCallID: "unknown-tool", PID: 10, StartedAt: "2026-10-17T00:00:01Z"},
	)
	match, ok, err := Resolve(db, RawIdentity{CgroupID: "cg", ContainerID: "ctr", PID: 10, Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || !ok || match.ID != "a" || match.ToolCallID != "tool-a" || !strings.HasPrefix(match.Method, "pid_time_window:") {
		t.Fatalf("exact process was lost or crossed scope: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestResolvePIDReportsOnlyMatchedScopeKeys(t *testing.T) {
	db := resolutionDB(t, Binding{ID: "a", RunID: "run", ToolCallID: "tool", PID: 10, ContainerID: "ctr", StartedAt: "2026-10-17T00:00:00Z"})
	match, ok, err := Resolve(db, RawIdentity{PID: 10, CgroupID: "cg", ContainerID: "ctr", Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || !ok || match.Method != "pid_time_window:pid+time+container_id" {
		t.Fatalf("reported a scope key absent from the binding: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestResolveCandidateDiagnosticsAreBoundedWithoutIgnoringConflicts(t *testing.T) {
	var bindings []Binding
	for i := 0; i <= maxCandidateBindingIDs; i++ {
		bindings = append(bindings, Binding{ID: "a-" + strconv.Itoa(i), RunID: "run", ToolCallID: "tool", CgroupID: "cg", StartedAt: "2026-10-17T00:00:00Z"})
	}
	bindings = append(bindings, Binding{ID: "zz-conflict", RunID: "other-run", CgroupID: "cg", StartedAt: "2026-10-17T00:00:01Z"})
	db := resolutionDB(t, bindings...)
	match, ok, err := Resolve(db, RawIdentity{CgroupID: "cg", Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || ok || !match.Ambiguous || match.CandidateCount != len(bindings) || len(match.CandidateBindingIDs) != maxCandidateBindingIDs {
		t.Fatalf("truncated diagnostics changed resolution: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestResolveEquivalentBindingsUseDeterministicConservativeMatch(t *testing.T) {
	db := resolutionDB(t,
		Binding{ID: "b", RunID: "run", ToolCallID: "tool", ProcessID: "proc", PID: 10, Confidence: 0.5, StartedAt: "2026-10-17T00:00:01Z"},
		Binding{ID: "a", RunID: "run", ToolCallID: "tool", ProcessID: "proc", PID: 10, Confidence: 1, StartedAt: "2026-10-17T00:00:01Z"},
	)
	match, ok, err := Resolve(db, RawIdentity{PID: 10, Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || !ok || match.Ambiguous || match.ID != "a" || match.ToolCallID != "tool" || match.Confidence != 0.5 {
		t.Fatalf("equivalent binding resolution: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestResolveConflictingProcessBindingsRetainsCommonScope(t *testing.T) {
	db := resolutionDB(t,
		Binding{ID: "a", RunID: "run", SessionID: "session-a", ToolCallID: "tool-a", ProcessID: "proc", PID: 10, StartedAt: "2026-10-17T00:00:00Z"},
		Binding{ID: "b", RunID: "run", SessionID: "session-b", ToolCallID: "tool-b", ProcessID: "proc", PID: 10, StartedAt: "2026-10-17T00:00:01Z"},
	)
	for _, raw := range []RawIdentity{{PID: 10}, {ProcessID: "proc"}} {
		raw.Timestamp = "2026-10-17T00:00:02Z"
		match, ok, err := Resolve(db, raw)
		if err != nil || !ok || match.RunID != "run" || match.SessionID != "" || match.ToolCallID != "" || match.ProcessID != "" || match.ID != "" {
			t.Fatalf("conflicting process attribution: %+v ok=%v err=%v", match, ok, err)
		}
	}
}

func TestResolveProcessIDRespectsBindingWindow(t *testing.T) {
	db := resolutionDB(t, Binding{ID: "a", RunID: "run", ProcessID: "proc", StartedAt: "2026-10-17T00:00:01Z", EndedAt: "2026-10-17T00:00:02Z"})
	for _, at := range []string{"2026-10-17T00:00:00Z", "2026-10-17T00:00:03Z"} {
		match, ok, err := Resolve(db, RawIdentity{ProcessID: "proc", Timestamp: at})
		if err != nil || ok {
			t.Fatalf("out-of-window process match: %+v ok=%v err=%v", match, ok, err)
		}
	}
}

func TestResolveExplicitProcessDoesNotFallBackToReusedPID(t *testing.T) {
	db := resolutionDB(t,
		Binding{ID: "old", RunID: "run", ProcessID: "old-process", ToolCallID: "old-tool", PID: 10, StartedAt: "2026-10-17T00:00:00Z", EndedAt: "2026-10-17T00:00:01Z"},
		Binding{ID: "new", RunID: "run", ProcessID: "new-process", ToolCallID: "new-tool", PID: 10, StartedAt: "2026-10-17T00:00:01Z"},
	)
	match, ok, err := Resolve(db, RawIdentity{ProcessID: "old-process", PID: 10, Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || ok {
		t.Fatalf("explicit process was replaced by PID reuse: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestResolveRootPIDDoesNotBorrowChildTool(t *testing.T) {
	db := resolutionDB(t, Binding{ID: "child", RunID: "run", ProcessID: "child", ToolCallID: "tool-child", PID: 20, RootPID: 10, StartedAt: "2026-10-17T00:00:00Z"})
	match, ok, err := Resolve(db, RawIdentity{PID: 10, Timestamp: "2026-10-17T00:00:02Z"})
	if err != nil || ok {
		t.Fatalf("parent inherited child identity: %+v ok=%v err=%v", match, ok, err)
	}
}

func TestObserveProcessInstanceDoesNotUpgradeScopeOrFreezeAmbiguity(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		db := resolutionDB(t, Binding{ID: "a", RunID: "run", ToolCallID: "tool-a", ProcessID: "proc-a", CgroupID: "cg", StartedAt: "2026-10-17T00:00:00Z"})
		if ambiguous {
			if _, err := RecordBinding(db, Binding{ID: "b", RunID: "other-run", ToolCallID: "tool-b", CgroupID: "cg", StartedAt: "2026-10-17T00:00:01Z"}); err != nil {
				t.Fatal(err)
			}
		}
		raw := RawIdentity{ProcessInstanceID: "12345678-1234-1234-1234-123456789abc:30:100", PID: 30, CgroupID: "cg", Timestamp: "2026-10-17T00:00:02Z"}
		if err := ObserveProcessInstance(db, raw); err != nil {
			t.Fatal(err)
		}
		binding, ok, err := GetBinding(db, processBindingID(raw.ProcessInstanceID, raw.HostID))
		if err != nil || ok == ambiguous || binding.ToolCallID != "" || binding.ProcessID != "" {
			t.Fatalf("native anchor upgraded or froze attribution: %+v ok=%v err=%v", binding, ok, err)
		}
	}
}
