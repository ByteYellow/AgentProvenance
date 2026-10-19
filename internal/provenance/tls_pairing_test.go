package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func tlsTestIdentity(t *testing.T, payload, connection, typ string) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		t.Fatal(err)
	}
	http := map[string]any{"connection_id": fmt.Sprintf("tls-v1:%x", sha256.Sum256([]byte(connection))),
		"protocol": "http/1.1", "headers_decoded": true}
	if typ == "tls_write" {
		http["method"] = "POST"
	} else {
		http["status"] = 200
	}
	body["http"] = http
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func tlsTestEvent(id, typ, connection, protocol string, stream uint32, second int) tlsEvent {
	e := tlsEvent{id: id, etype: typ, pid: 100, scope: llmScope{source: "agentprov_ebpf", origin: "origin:node-a", cgroup: "cg-a"},
		at: time.Date(2026, 1, 1, 0, 0, second, 0, time.UTC),
		http: tlsHTTPIdentity{ConnectionID: fmt.Sprintf("tls-v1:%x", sha256.Sum256([]byte(connection))), Protocol: protocol,
			StreamID: stream, HeadersDecoded: true}}
	if typ == "tls_write" {
		e.http.Method = "POST"
	} else {
		e.http.Status = 200
	}
	return e
}

func TestTLSPairingInterleavedConnectionsAndStreams(t *testing.T) {
	events := []tlsEvent{
		tlsTestEvent("a-req", "tls_write", "a", "http/1.1", 0, 1),
		tlsTestEvent("b-req", "tls_write", "b", "http/1.1", 0, 2),
		tlsTestEvent("a-resp", "tls_read", "a", "http/1.1", 0, 3),
		tlsTestEvent("b-resp", "tls_read", "b", "http/1.1", 0, 4),
		tlsTestEvent("h2-req-1", "tls_write", "h2", "h2", 1, 1),
		tlsTestEvent("h2-req-3", "tls_write", "h2", "h2", 3, 2),
		tlsTestEvent("h2-resp-3", "tls_read", "h2", "h2", 3, 3),
		tlsTestEvent("h2-resp-1", "tls_read", "h2", "h2", 1, 4),
	}
	want := map[string]string{"a-req": "a-resp", "b-req": "b-resp", "h2-req-1": "h2-resp-1", "h2-req-3": "h2-resp-3"}
	for order := 0; order < 2; order++ {
		pairs, reports := pairTLSMessages(events, false)
		got := map[string]string{}
		for _, p := range pairs {
			req, resp := events[p.request].id, events[p.response].id
			got[req] = resp
			if reports[req].PeerEventID != resp || reports[resp].PeerEventID != req || reports[req].Rule != tlsPairRule {
				t.Fatalf("pair diagnostics: %+v", reports)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pairs=%v, want %v", got, want)
		}
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
	}
}

func TestTLSPairingRejectsInsufficientAndConflictingIdentity(t *testing.T) {
	for _, tt := range []struct {
		name, protocol, status, reason string
		change                         func(*tlsEvent)
	}{
		{"legacy identity", "http/1.1", "unknown", "missing_connection_identity", func(e *tlsEvent) { e.http.ConnectionID = "" }},
		{"invalid identity", "http/1.1", "unknown", "missing_connection_identity", func(e *tlsEvent) { e.http.ConnectionID = "tls-v1:" + strings.Repeat("z", 64) }},
		{"new lifetime", "http/1.1", "unknown", "peer_not_observed", func(e *tlsEvent) {
			e.http.ConnectionID = fmt.Sprintf("tls-v1:%x", sha256.Sum256([]byte("new-epoch")))
		}},
		{"different node", "h2", "unknown", "capture_scope_conflict", func(e *tlsEvent) { e.scope.origin = "origin:node-b" }},
		{"missing origin", "h2", "unknown", "capture_scope_conflict", func(e *tlsEvent) { e.scope.origin = "" }},
		{"different cgroup", "h2", "unknown", "capture_scope_conflict", func(e *tlsEvent) { e.scope.cgroup = "cg-b" }},
		{"different pid", "h2", "unknown", "capture_scope_conflict", func(e *tlsEvent) { e.pid++ }},
		{"different source", "h2", "unknown", "peer_not_observed", func(e *tlsEvent) { e.scope.source = "other" }},
		{"invalid time", "h2", "unknown", "invalid_capture_time", func(e *tlsEvent) { e.at = time.Time{} }},
		{"earlier response", "h2", "unknown", "response_precedes_request", func(e *tlsEvent) { e.at = e.at.Add(-10 * time.Second) }},
		{"no h2 stream", "h2", "unknown", "missing_stream_identity", func(e *tlsEvent) { e.http.StreamID = 0 }},
		{"invalid h2 stream", "h2", "unknown", "missing_stream_identity", func(e *tlsEvent) { e.http.StreamID = 0x80000000 }},
		{"different protocol", "h2", "unknown", "protocol_conflict", func(e *tlsEvent) { e.http.Protocol = "http/1.1" }},
		{"partial response", "http/1.1", "unknown", "incomplete_http_message", func(e *tlsEvent) { e.truncated = true }},
		{"undecoded headers", "h2", "unknown", "incomplete_http_message", func(e *tlsEvent) { e.http.HeadersDecoded = false }},
		{"upgrade", "http/1.1", "unknown", "incomplete_http_message", func(e *tlsEvent) { e.http.Status = 101 }},
		{"equal h1 time", "http/1.1", "ambiguous", "http1_sequence_not_unique", func(e *tlsEvent) { e.at = e.at.Add(-time.Second) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := []tlsEvent{tlsTestEvent("req", "tls_write", "c", tt.protocol, 1, 1), tlsTestEvent("resp", "tls_read", "c", tt.protocol, 1, 2)}
			tt.change(&events[1])
			pairs, reports := pairTLSMessages(events, false)
			if len(pairs) != 0 || reports["resp"].Status != tt.status || reports["resp"].Reason != tt.reason {
				t.Fatalf("pairs=%v reports=%+v", pairs, reports)
			}
		})
	}
}

func TestTLSPairingHTTP1SerialAndAmbiguity(t *testing.T) {
	base := []tlsEvent{tlsTestEvent("q1", "tls_write", "c", "http/1.1", 0, 1), tlsTestEvent("r1", "tls_read", "c", "http/1.1", 0, 2),
		tlsTestEvent("q2", "tls_write", "c", "http/1.1", 0, 3), tlsTestEvent("r2", "tls_read", "c", "http/1.1", 0, 4)}
	for _, tt := range []struct {
		name   string
		change func([]tlsEvent) []tlsEvent
		want   int
	}{
		{"keepalive", func(e []tlsEvent) []tlsEvent { return e }, 2},
		{"pending request", func(e []tlsEvent) []tlsEvent { return e[:3] }, 1},
		{"pipelined", func(e []tlsEvent) []tlsEvent { e[2].at = e[0].at.Add(time.Millisecond); return e }, 0},
		{"missing middle response", func(e []tlsEvent) []tlsEvent { return append(e[:1], e[2:]...) }, 0},
		{"missing middle request", func(e []tlsEvent) []tlsEvent { return append(e[:2], e[3]) }, 0},
		{"late duplicate", func(e []tlsEvent) []tlsEvent { d := e[1]; d.id = "duplicate"; return append(e, d) }, 0},
		{"partial middle", func(e []tlsEvent) []tlsEvent { e[1].truncated = true; return e }, 0},
		{"100 continue", func(e []tlsEvent) []tlsEvent {
			info := e[1]
			info.id = "continue"
			info.http.Status = 100
			info.at = info.at.Add(-time.Millisecond)
			return append(e, info)
		}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			events := tt.change(append([]tlsEvent(nil), base...))
			pairs, reports := pairTLSMessages(events, false)
			if len(pairs) != tt.want {
				t.Fatalf("pairs=%v reports=%+v", pairs, reports)
			}
			for _, p := range pairs {
				if reports[events[p.request].id].Confidence != 0.8 || reports[events[p.request].id].Method != "http1_serial" {
					t.Fatal(reports)
				}
			}
		})
	}
}

func TestTLSPairingHTTP2DuplicateIsStreamLocal(t *testing.T) {
	events := []tlsEvent{tlsTestEvent("q1", "tls_write", "c", "h2", 1, 1), tlsTestEvent("r1", "tls_read", "c", "h2", 1, 2),
		tlsTestEvent("q3", "tls_write", "c", "h2", 3, 1), tlsTestEvent("r3", "tls_read", "c", "h2", 3, 2),
		tlsTestEvent("r1-duplicate", "tls_read", "c", "h2", 1, 3)}
	pairs, reports := pairTLSMessages(events, false)
	if len(pairs) != 1 || events[pairs[0].request].id != "q3" || reports["q1"].Status != "ambiguous" {
		t.Fatalf("%v %+v", pairs, reports)
	}
}

func insertTLSTestEvent(t *testing.T, db *sql.DB, e tlsEvent) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"node_name": "node-a", "http": e.http, "truncated": e.truncated, "content": `{"model":"test","messages":[]}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events(id,run_id,event_type,created_at,payload,source,cgroup_id,pid) VALUES (?,'intent-test',?,?,?,?,?,?)`,
		e.id, e.etype, e.at.Format(time.RFC3339Nano), string(payload), e.scope.source, e.scope.cgroup, e.pid); err != nil {
		t.Fatal(err)
	}
}

func TestTLSReanalysisRemovesStalePairsAndPreservesOtherSources(t *testing.T) {
	st, db := intentTestStore(t)
	// An unrelated endpoint capture must survive TLS materialization.
	obj, err := st.PutExternalObject(ExternalObjectInput{Type: "llm_message", SourceID: "endpoint/req-1", RunID: "intent-test", Payload: map[string]any{"content": "endpoint evidence"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := insertLLMEdge(db, "intent-test", "llm_call/ep-1", obj.Hash, edgeLLMRequest, "", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	for _, e := range []tlsEvent{tlsTestEvent("q", "tls_write", "c", "h2", 1, 1), tlsTestEvent("r", "tls_read", "c", "h2", 1, 2)} {
		insertTLSTestEvent(t, db, e)
	}
	if n, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	insertTLSTestEvent(t, db, tlsTestEvent("late-duplicate", "tls_read", "c", "h2", 1, 2))
	if n, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM graph_edges WHERE edge_type='llm_call'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stale pairs=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM graph_edges WHERE from_id='llm_call/ep-1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("endpoint edge=%d %v", n, err)
	}
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE source_id='llm_response/r'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	meta := llmMessageMeta(path)
	if meta.Correlation == nil || meta.Correlation.Status != "ambiguous" {
		t.Fatalf("%+v", meta)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "multiple_stream_candidates") {
		t.Fatalf("%s %v", raw, err)
	}
}

func TestTLSPairingSavedCoverageGap(t *testing.T) {
	for _, tt := range []struct{ name, issue, counter string }{
		{"reported loss", "node_loss_during_capture", ""},
		{"counter loss", "", "kernel_dropped_events"},
		{"reassembly loss", "", "tls_reassembly_dropped_streams"},
		{"pending at seal", "node_backlog_at_seal", ""},
		{"clean capture", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, db := intentTestStore(t)
			db.SetMaxOpenConns(1)
			if _, err := st.PutExternalObject(ExternalObjectInput{Type: "runtime_capture", SourceID: "runtime_capture/intent-test", RunID: "intent-test", Payload: map[string]any{
				"schema_version": "agentprovenance.runtime_capture/v1", "run_id": "intent-test", "issues": []string{tt.issue}, "node_counter_delta": map[string]int64{tt.counter: 2},
			}}); err != nil {
				t.Fatal(err)
			}
			for _, protocol := range []string{"http/1.1", "h2"} {
				insertTLSTestEvent(t, db, tlsTestEvent(protocol+"q", "tls_write", protocol, protocol, 1, 1))
				insertTLSTestEvent(t, db, tlsTestEvent(protocol+"r", "tls_read", protocol, protocol, 1, 2))
			}
			want := 1
			if tt.name == "clean capture" {
				want = 2
			}
			if n, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil || n != want {
				t.Fatalf("%d %v, want %d", n, err, want)
			}
			var path string
			if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE source_id='llm_request/http/1.1q'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			if want == 1 && llmMessageMeta(path).Correlation.Reason != "capture_gap_during_run" {
				t.Fatalf("%+v", llmMessageMeta(path))
			}
		})
	}
}

func TestTLSLegacyAndMetadataOnlyCapture(t *testing.T) {
	for _, bodySaved := range []bool{false, true} {
		t.Run(fmt.Sprint(bodySaved), func(t *testing.T) {
			st, db := intentTestStore(t)
			for _, e := range []tlsEvent{tlsTestEvent("q", "tls_write", "c", "h2", 1, 1), tlsTestEvent("r", "tls_read", "c", "h2", 1, 2)} {
				insertTLSTestEvent(t, db, e)
			}
			if !bodySaved {
				if _, err := db.Exec(`UPDATE events SET payload=json_remove(payload,'$.content')`); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil || n != 1 {
				t.Fatalf("%d %v", n, err)
			}
			// Recreate a legacy capture without connection identity. Its old edge
			// cannot restore pairing, even though the bodies and PIDs still agree.
			if _, err := db.Exec(`UPDATE events SET payload=json_remove(payload,'$.http.connection_id')`); err != nil {
				t.Fatal(err)
			}
			var before string
			if err := db.QueryRow(`SELECT payload FROM events WHERE id='q'`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if n, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil || n != 0 {
				t.Fatalf("%d %v", n, err)
			}
			var after, path string
			if err := db.QueryRow(`SELECT payload FROM events WHERE id='q'`).Scan(&after); err != nil || before != after {
				t.Fatalf("raw evidence changed: %v", err)
			}
			if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE source_id='llm_request/q'`).Scan(&path); err != nil {
				t.Fatal(err)
			}
			if llmMessageMeta(path).Correlation.Reason != "missing_connection_identity" {
				t.Fatalf("%+v", llmMessageMeta(path))
			}
			var saved struct {
				Payload struct {
					Saved bool `json:"content_saved"`
				} `json:"payload"`
			}
			raw, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Payload.Saved != bodySaved {
				t.Fatalf("content retention=%+v err=%v", saved, err)
			}
		})
	}
}

func TestTLSCaptureReportFailureRetainsPreviousAnalysis(t *testing.T) {
	st, db := intentTestStore(t)
	for _, e := range []tlsEvent{tlsTestEvent("q", "tls_write", "c", "http/1.1", 0, 1), tlsTestEvent("r", "tls_read", "c", "http/1.1", 0, 2)} {
		insertTLSTestEvent(t, db, e)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	before := intentDerivedSnapshot(t, db)
	if _, err := st.PutExternalObject(ExternalObjectInput{Type: "runtime_capture", SourceID: "runtime_capture/intent-test", RunID: "intent-test", Payload: map[string]any{"run_id": "wrong-run"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err == nil {
		t.Fatal("invalid coverage report was ignored")
	}
	if after := intentDerivedSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("failed analysis modified old graph")
	}
}
