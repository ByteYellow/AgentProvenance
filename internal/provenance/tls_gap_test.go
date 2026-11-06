package provenance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestTLSGapRuleUpgradeRetainsHistoricalEdges(t *testing.T) {
	_, db := intentTestStore(t)
	for _, version := range []int{1, 2, 3} {
		id := fmt.Sprintf("tls-pair-v%d-http1_serial-example", version)
		if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at)
			VALUES (?,'intent-test','runtime_event/request','runtime_event/response','llm_call','2026-01-01T00:00:01Z')`, id); err != nil {
			t.Fatal(err)
		}
	}
	edges, err := graphLensEdges(db, "intent-test")
	if err != nil || len(edges) != 3 {
		t.Fatalf("historical edges missing: %+v %v", edges, err)
	}
	for i, edge := range edges {
		if !edge.Derived || edge.DerivationRule != fmt.Sprintf("agentprov.tls_connection_exchange/v%d", i+1) ||
			edge.Confidence == nil || *edge.Confidence != 0.8 || len(edge.EvidenceRefs) != 2 {
			t.Fatalf("historical interpretation changed: %+v", edge)
		}
	}
}

func TestTLSGapCannotBecomeModelIntent(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := ObjectStore{DB: db, Paths: paths}
	const run = "tls-gap"
	const content = `{"model":"m","content":[{"type":"tool_use","name":"bash","input":{"command":"cat private-file"}}]}`
	for _, typ := range []string{"tls_write", "tls_read"} {
		payload, err := json.Marshal(map[string]any{"content": content, "node_name": "node-a",
			"capture": map[string]any{"rule": "agentprov.tls_reassembly/v2", "state": "incomplete", "reason": "hpack_decode_failed", "data_kind": "http_body"}})
		if err != nil {
			t.Fatal(err)
		}
		at := "2026-01-01T00:00:01Z"
		if typ == "tls_read" {
			at = "2026-01-01T00:00:02Z"
		}
		p := tlsTestIdentity(t, string(payload), "a", typ)
		if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,payload,created_at,cgroup_id,pid)
			VALUES (?,?,'agentprov_ebpf',?,?,?,'cg-a',100)`, typ, run, typ, p, at); err != nil {
			t.Fatal(err)
		}
	}
	n, err := MaterializeLLMCalls(st, db, run)
	if err != nil || n != 0 {
		t.Fatalf("incomplete capture formed an LLM pair: n=%d err=%v", n, err)
	}
	rows, err := db.Query(`SELECT path FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			t.Fatal(err)
		}
		if meta := llmMessageMeta(path); meta.Command != "" || meta.Prompt != "" || len(meta.ToolCalls) != 0 {
			t.Fatalf("graph presentation reinterpreted incomplete bytes as intent: %+v", meta)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var obj struct {
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		sem, _ := obj.Payload["semantics"].(map[string]any)
		if len(sem) != 0 || obj.Payload["model"] != "" || obj.Payload["capture"] == nil || obj.Payload["content"] != content {
			t.Fatalf("incomplete content lost its gap or acquired intent: %+v", obj)
		}
		count++
	}
	if err := rows.Err(); err != nil || count != 2 {
		t.Fatalf("raw evidence missing: count=%d err=%v", count, err)
	}
}
