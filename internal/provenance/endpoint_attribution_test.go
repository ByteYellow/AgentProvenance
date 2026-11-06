package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"
)

func endpointAttributionFixture(t *testing.T, path string, meta map[string]any) (ObjectStore, *sql.DB, string) {
	t.Helper()
	st, db := intentTestStore(t)
	db.SetMaxOpenConns(1)
	dump := t.TempDir()
	meta["seq"], meta["kind"], meta["path"], meta["host"] = 1, "req", "/storage", "sink.example"
	meta["canary_hits"] = []string{"UNIQUE-FIXTURE-CANARY"}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"files": []any{map[string]any{"path": path, "content": "UNIQUE-FIXTURE-CANARY"}}})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dump, "01.meta.json"), string(raw))
	mustWrite(t, filepath.Join(dump, "01.body.bin"), string(body))
	return st, db, dump
}

func endpointRecordedAssociation(t *testing.T, db *sql.DB) endpointAssociation {
	t.Helper()
	a := endpointAssociationJSON(t, db)
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var result endpointAssociation
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func addEndpointNetwork(t *testing.T, db *sql.DB, id, run, kind, host, at string) {
	t.Helper()
	b, err := json.Marshal(map[string]string{"dst_host": host})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events(id,run_id,session_id,process_id,tool_call_id,source,event_type,payload,created_at)
		VALUES (?,?,'send-session','send-process','send-tool','sensor',?,?,?)`, id, run, kind, string(b), at); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointSourceVersionAndTimeCandidates(t *testing.T) {
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("UNIQUE-FIXTURE-CANARY")))
	for _, tc := range []struct{ name, read, capture, version, want, basis string }{
		{"exact_version", "2026-11-06T00:00:01Z", "2026-11-06T00:00:03Z", hash, "candidate", "content_sha256_match"},
		{"old_version", "2026-11-06T00:00:01Z", "2026-11-06T00:00:03Z", "sha256:different", "unknown", ""},
		{"coarse_overlap", "2026-11-06T00:00:03Z", "2026-11-06T00:00:03.050Z", hash, "candidate", "time_precision_overlap"},
		{"same_time", "2026-11-06T00:00:03.050Z", "2026-11-06T00:00:03.050Z", hash, "candidate", "time_precision_overlap"},
		{"missing_time", "2026-11-06T00:00:01Z", "", hash, "candidate", "time_unknown"},
		{"different_zones", "2026-11-06T08:00:01+08:00", "2026-11-06T00:00:03Z", hash, "candidate", "read_before_capture"},
		{"later_read", "2026-11-06T00:00:04Z", "2026-11-06T00:00:03.050Z", hash, "unknown", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, db, dump := endpointAttributionFixture(t, "/work/secret", map[string]any{"observed_at": tc.capture})
			p, _ := json.Marshal(map[string]string{"path": "/work/secret", "content_sha256": tc.version})
			addEndpointRead(t, db, "read", tc.read, string(p))
			if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
				t.Fatal(err)
			}
			a := endpointRecordedAssociation(t, db)
			if a.SourceReads.Status != tc.want || a.ContentMatch.Status != "matched" || a.Execution.Status != "unknown" {
				t.Fatalf("independent evidence stages: %+v", a)
			}
			if tc.basis != "" && (len(a.SourceReads.Candidates) != 1 || !slices.Contains(a.SourceReads.Candidates[0].Basis, tc.basis)) {
				t.Fatalf("candidate basis: %+v", a.SourceReads)
			}
		})
	}
}

func TestEndpointExecutionRequiresPerCaptureReference(t *testing.T) {
	for _, tc := range []struct{ name, run, kind, host, at, want string }{
		{"exact", "intent-test", "network_connect", "sink.example", "2026-11-06T00:00:02Z", "bound"},
		{"other_run", "different-run", "network_connect", "sink.example", "2026-11-06T00:00:02Z", "unknown"},
		{"wrong_kind", "intent-test", "execve", "sink.example", "2026-11-06T00:00:02Z", "conflicting"},
		{"different_host", "intent-test", "network_connect", "other.example", "2026-11-06T00:00:02Z", "conflicting"},
		{"later_operation", "intent-test", "network_connect", "sink.example", "2026-11-06T00:00:04Z", "conflicting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, db, dump := endpointAttributionFixture(t, "/work/secret", map[string]any{"observed_at": "2026-11-06T00:00:03.000Z", "runtime_event_id": "runtime_event/send"})
			addEndpointNetwork(t, db, "send", tc.run, tc.kind, tc.host, tc.at)
			if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
				t.Fatal(err)
			}
			a := endpointRecordedAssociation(t, db)
			if a.Execution.Status != tc.want || a.SourceReads.Status != "unknown" || a.ContentMatch.Status != "matched" {
				t.Fatalf("wrong per-capture attribution: %+v", a)
			}
			if tc.want == "bound" {
				if a.Execution.ProcessID != "send-process" || a.Execution.ToolCallID != "send-tool" || a.Execution.SessionID != "send-session" {
					t.Fatalf("lost explicit execution identity: %+v", a.Execution)
				}
			} else if a.Execution.ProcessID != "" || a.Execution.ToolCallID != "" || a.Execution.SessionID != "" {
				t.Fatalf("unresolved execution acquired identity: %+v", a.Execution)
			}
		})
	}
}

func TestEndpointExplicitCrossProcessSourceLink(t *testing.T) {
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("UNIQUE-FIXTURE-CANARY")))
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprint(linked), func(t *testing.T) {
			meta := map[string]any{"observed_at": "2026-11-06T00:00:03Z", "runtime_event_id": "send"}
			if linked {
				meta["source_read_events"] = []string{"runtime_event/read"}
			}
			st, db, dump := endpointAttributionFixture(t, "/work/secret", meta)
			p, _ := json.Marshal(map[string]string{"path": "/work/secret", "content_sha256": hash})
			addEndpointRead(t, db, "read", "2026-11-06T00:00:01Z", string(p))
			addEndpointNetwork(t, db, "send", "intent-test", "network_connect", "sink.example", "2026-11-06T00:00:02Z")
			if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
				t.Fatal(err)
			}
			a := endpointRecordedAssociation(t, db)
			want, kind := "candidate", "candidate_sensitive_data_flow"
			if linked {
				want, kind = "linked", "confirmed_sensitive_data_flow"
			}
			if a.Execution.Status != "bound" || a.SourceReads.Status != want || len(a.SourceReads.Candidates) != 1 || a.SourceReads.Candidates[0].ProcessID != "read-process" || a.Execution.ProcessID != "send-process" {
				t.Fatalf("source/execution identity conflated: %+v", a)
			}
			if linked && !slices.Contains(a.SourceReads.Candidates[0].EvidenceRefs, "runtime_event/send") {
				t.Fatal("linked flow lost execution support")
			}
			edges, err := graphLensEdges(db, "intent-test")
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, edge := range edges {
				if edge.EdgeType == kind {
					found++
					if !edge.Derived || edge.DerivationRule != endpointAssociationRule || edge.Confidence != nil || edge.Data["association_status"] != want || !slices.Contains(edge.EvidenceRefs, "runtime_event/read") {
						t.Fatalf("graph altered evidence semantics: %+v", edge)
					}
				}
			}
			if found != 1 {
				t.Fatalf("expected one %s, got %d", kind, found)
			}
			nodes, events, err := graphLensNodes(db, "intent-test")
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range events {
				if ev.Source == "endpoint_capture" {
					if nodes[ev.NodeID].Data["endpoint_association"] == nil {
						t.Fatal("graph node lost association stages")
					}
					if _, _, rule, _ := taintFlowScope(events["runtime_event/read"], ev, true); rule != "" {
						t.Fatalf("generic fallback overrode capture attribution: %s", rule)
					}
				}
			}
		})
	}
}

func TestEndpointLateReadAndDuplicateIngestion(t *testing.T) {
	st, db, dump := endpointAttributionFixture(t, "/work/secret", map[string]any{"observed_at": "2026-11-06T00:00:03Z"})
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatal(err)
	}
	before := endpointRecordedAssociation(t, db)
	if before.SourceReads.Status != "unknown" || before.ContentMatch.Status != "matched" {
		t.Fatalf("missing read erased content evidence: %+v", before)
	}
	for _, id := range []string{"second", "first"} {
		addEndpointRead(t, db, id, "2026-11-06T00:00:01Z", `{"path":"/work/secret"}`)
	}
	for i := 0; i < 2; i++ {
		if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
			t.Fatal(err)
		}
		a := endpointRecordedAssociation(t, db)
		if a.SourceReads.Status != "ambiguous" || len(a.SourceReads.Candidates) != 2 || a.SourceReads.Candidates[0].EventID != "first" || a.Execution.Status != "unknown" {
			t.Fatalf("late candidates depended on ingestion order: %+v", a)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type='candidate_sensitive_data_flow'`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("duplicate candidate edges: %d %v", count, err)
		}
	}
}

func TestEndpointEmptyMarkersAndRepeatedPaths(t *testing.T) {
	_, db := intentTestStore(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	body := []byte(`{"files":[{"path":"/work/secret","content":"PUBLIC-CANARY"},{"path":"/work/secret","content":"PUBLIC-CANARY"}]}`)
	a, err := buildEndpointAssociation(tx, "intent-test", endpointMeta{CanaryHits: []string{""}}, body, nil, "2026-11-06T00:00:03Z")
	if err != nil || a.ContentMatch.Status != "not_matched" {
		t.Fatalf("empty marker became content evidence: %+v %v", a, err)
	}
	if c := classifyEndpointPayload("/storage", body, []string{""}, false); c.Sensitive {
		t.Fatalf("empty marker classified as sensitive: %+v", c)
	}
	c := classifyEndpointPayload("/storage", body, []string{"PUBLIC-CANARY"}, false)
	if !c.Sensitive || !reflect.DeepEqual(c.CanaryPaths, []string{"/work/secret"}) {
		t.Fatalf("repeated file entries duplicated a path relation: %+v", c)
	}
}

func TestEndpointMissingPathPreservesUnresolvedReferences(t *testing.T) {
	_, db := intentTestStore(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	m := endpointMeta{CanaryHits: []string{"PUBLIC-CANARY"}, SourceReadEvents: []string{"", "runtime_event/", "runtime_event/read", "read"}}
	a, err := buildEndpointAssociation(tx, "intent-test", m, []byte("PUBLIC-CANARY"), nil, "2026-11-06T00:00:03Z")
	if err != nil || a.ContentMatch.Status != "matched" || a.SourceReads.Status != "path_unavailable" ||
		!reflect.DeepEqual(a.SourceReads.UnresolvedReferences, []string{"runtime_event/read"}) || len(a.SourceReads.Candidates) != 0 {
		t.Fatalf("missing path erased or promoted the capture reference: %+v %v", a, err)
	}
}

func addEndpointRead(t *testing.T, db *sql.DB, id, at, payload string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events(id,run_id,session_id,process_id,tool_call_id,source,event_type,payload,created_at)
		VALUES (?,'intent-test','read-session','read-process','read-tool','sensor','secret_path',?,?)`, id, payload, at); err != nil {
		t.Fatal(err)
	}
}

func endpointAssociationJSON(t *testing.T, db *sql.DB) map[string]any {
	t.Helper()
	var raw string
	if err := db.QueryRow(`SELECT payload FROM events WHERE run_id='intent-test' AND source='endpoint_capture'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	a, ok := payload["endpoint_association"].(map[string]any)
	if !ok {
		t.Fatalf("missing three-stage endpoint association: %s", raw)
	}
	return a
}

func TestEndpointCaptureDoesNotBorrowReadExecution(t *testing.T) {
	st, db, dump := endpointAttributionFixture(t, "/work/secret", map[string]any{})
	addEndpointRead(t, db, "read", "2026-11-06T00:00:01Z", `{"path":"/work/secret"}`)
	if _, err := db.Exec(`INSERT INTO tool_calls(id,run_id,agent_id,command,status,created_at) VALUES ('unrelated-first','intent-test','other','echo ok','completed','2026-11-06T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatal(err)
	}
	var session, process, tool string
	if err := db.QueryRow(`SELECT session_id,process_id,tool_call_id FROM events WHERE source='endpoint_capture'`).Scan(&session, &process, &tool); err != nil {
		t.Fatal(err)
	}
	if session != "" || process != "" || tool != "" {
		t.Fatalf("capture borrowed unrelated execution: %q %q %q", session, process, tool)
	}
	var confirmed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type='confirmed_sensitive_data_flow'`).Scan(&confirmed); err != nil {
		t.Fatal(err)
	}
	if confirmed != 0 {
		t.Fatalf("path-only match became confirmed flow: %d", confirmed)
	}
	a := endpointAssociationJSON(t, db)
	if a["content_match"].(map[string]any)["status"] != "matched" || a["execution"].(map[string]any)["status"] != "unknown" {
		t.Fatalf("lost content fact or fabricated execution: %+v", a)
	}
}

func TestEndpointSourceCandidatesRequireExactPathAndCaptureOrder(t *testing.T) {
	st, db, dump := endpointAttributionFixture(t, "secret_%", map[string]any{"observed_at": "2026-11-06T00:00:03.000000000Z", "working_directory": "/work"})
	for _, read := range []struct{ id, at, payload string }{
		{"first", "2026-11-06T00:00:01Z", `{"path":"/work/secret_%"}`},
		{"second", "2026-11-06T00:00:02Z", `{"payload":{"path":"./secret_%","cwd":"/work"}}`},
		{"wildcard", "2026-11-06T00:00:02Z", `{"path":"/work/secret_XYZ"}`},
		{"suffix", "2026-11-06T00:00:02Z", `{"path":"/work/secret_%.backup"}`},
		{"text", "2026-11-06T00:00:02Z", `{"path":"/work/readme","note":"secret_%"}`},
		{"future", "2026-11-06T00:00:04Z", `{"path":"/work/secret_%"}`},
	} {
		addEndpointRead(t, db, read.id, read.at, read.payload)
	}
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatal(err)
	}
	a := endpointAssociationJSON(t, db)
	source := a["source_reads"].(map[string]any)
	var got []string
	for _, v := range source["candidates"].([]any) {
		got = append(got, v.(map[string]any)["event_id"].(string))
	}
	sort.Strings(got)
	if source["status"] != "ambiguous" || !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("wrong read candidates: %+v", source)
	}
	var confirmed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type='confirmed_sensitive_data_flow'`).Scan(&confirmed); err != nil {
		t.Fatal(err)
	}
	if confirmed != 0 {
		t.Fatalf("ambiguous reads became confirmed: %d", confirmed)
	}
}
