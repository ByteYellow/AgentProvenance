package provenance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestGraphLensDataFlowDerivesSecretToNetworkEdge(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)

	manifest, err := BuildGraphLens(db, GraphLensOptions{
		RunID:    "run-lens",
		Lens:     "data-flow-taint",
		Overlays: []string{"risk", "trust"},
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != graphLensSchemaVersion {
		t.Fatalf("schema=%s", manifest.SchemaVersion)
	}
	if manifest.Lens != "data-flow-taint" {
		t.Fatalf("lens=%s", manifest.Lens)
	}
	if len(manifest.DerivedEdges) != 1 {
		t.Fatalf("derived edges=%d, want 1: %+v", len(manifest.DerivedEdges), manifest.DerivedEdges)
	}
	edge := manifest.DerivedEdges[0]
	if edge.EdgeType != "possible_sensitive_data_flow_summary" {
		t.Fatalf("derived edge type=%s", edge.EdgeType)
	}
	if edge.FromID != "proc-lens" || edge.ToID == "" {
		t.Fatalf("derived edge path=%s -> %s", edge.FromID, edge.ToID)
	}
	if edge.DerivationRule != "dataflow.same_process.secret_to_network.aggregate.v1" || edge.Confidence < 0.8 {
		t.Fatalf("derived metadata not strong enough: %+v", edge)
	}
	if got := intFromEdgeData(edge, "source_count"); got != 1 {
		t.Fatalf("source_count=%d, want 1: %+v", got, edge.Data)
	}
	if got := intFromEdgeData(edge, "sink_count"); got != 1 {
		t.Fatalf("sink_count=%d, want 1: %+v", got, edge.Data)
	}
}

func TestGraphLensRawDetailKeepsIndividualDataFlowEdges(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)

	manifest, err := BuildGraphLens(db, GraphLensOptions{
		RunID:  "run-lens",
		Lens:   "data-flow-taint",
		Detail: "raw",
		Limit:  100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.DerivedEdges) != 1 {
		t.Fatalf("derived edges=%d, want 1: %+v", len(manifest.DerivedEdges), manifest.DerivedEdges)
	}
	edge := manifest.DerivedEdges[0]
	if edge.EdgeType != "possible_sensitive_data_flow" {
		t.Fatalf("derived edge type=%s", edge.EdgeType)
	}
	if edge.FromID != "runtime_event/evt-secret" || edge.ToID != "runtime_event/evt-egress" {
		t.Fatalf("raw derived edge path=%s -> %s", edge.FromID, edge.ToID)
	}
}

func TestGraphLensSummaryOmitsLowValueRuntimeNoise(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)
	insertLensEvent(t, db, "evt-exit", "process_exit", `{"exit_code":0}`, now)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-proc-exit', 'run-lens', 'proc-lens', 'runtime_event/evt-exit', 'runtime_process_event', 'evt-exit', ?)`, now); err != nil {
		t.Fatal(err)
	}

	summary, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "process", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if lensHasNode(summary, "runtime_event/evt-exit", "runtime_event") {
		t.Fatalf("summary lens should omit low-value process_exit: %+v", summary.Nodes)
	}

	raw, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lens", Lens: "process", Detail: "raw", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !lensHasNode(raw, "runtime_event/evt-exit", "runtime_event") {
		t.Fatalf("raw lens should keep process_exit for full observability: %+v", raw.Nodes)
	}
}

func TestGraphLensFocusAndJSON(t *testing.T) {
	db := newLensTestDB(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertLensFixture(t, db, now)

	var out bytes.Buffer
	if err := GraphLensJSON(db, GraphLensOptions{
		RunID: "run-lens",
		Lens:  "security",
		Focus: "runtime_event/evt-egress",
		Limit: 100,
	}, &out); err != nil {
		t.Fatal(err)
	}
	var manifest GraphLensManifest
	if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
		t.Fatalf("invalid lens json: %v\n%s", err, out.String())
	}
	if manifest.Query.Focus != "runtime_event/evt-egress" {
		t.Fatalf("focus=%s", manifest.Query.Focus)
	}
	if len(manifest.Edges) == 0 {
		t.Fatalf("expected focused security edges")
	}
	for _, edge := range manifest.Edges {
		if edge.FromID != "runtime_event/evt-egress" && edge.ToID != "runtime_event/evt-egress" {
			t.Fatalf("edge escaped focus: %+v", edge)
		}
	}
}

func newLensTestDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertLensFixture(t *testing.T, db *sql.DB, now string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-lens', 'run-lens', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions (id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-lens', 'lease-lens', 'run-lens', '/tmp/work', 'running', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls (id, run_id, session_id, command, status, created_at, started_at)
		VALUES ('tool-lens', 'run-lens', 'session-lens', 'run setup', 'running', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes (id, session_id, tool_call_id, command, status, started_at)
		VALUES ('proc-lens', 'session-lens', 'tool-lens', 'sh -c setup', 'running', ?)`, now); err != nil {
		t.Fatal(err)
	}
	// The secret read must precede the egress for a real data flow; the taint
	// lens only derives an edge that runs forward in time.
	parsed, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		t.Fatal(err)
	}
	egressTime := parsed.Add(time.Second).UTC().Format(time.RFC3339Nano)
	insertLensEvent(t, db, "evt-secret", "secret_path", `{"path":"/root/.aws/credentials"}`, now)
	insertLensEvent(t, db, "evt-egress", "metadata_ip", `{"dst_ip":"169.254.169.254","comm":"wget"}`, egressTime)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES
		('edge-tool-proc', 'run-lens', 'tool-lens', 'proc-lens', 'runtime_tool_call_process', '', ?),
		('edge-proc-secret', 'run-lens', 'proc-lens', 'runtime_event/evt-secret', 'runtime_process_event', 'evt-secret', ?),
		('edge-proc-egress', 'run-lens', 'proc-lens', 'runtime_event/evt-egress', 'runtime_process_event', 'evt-egress', ?),
		('edge-event-policy', 'run-lens', 'runtime_event/evt-egress', 'policy_decision/policy-lens', 'runtime_event_policy_decision', 'evt-egress', ?)`,
		now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-lens', 'evt-egress', 'run-lens', 'session-lens', 'metadata-ip', 'quarantine', 'metadata IP access', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO risk_signals (id, run_id, session_id, tool_call_id, process_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk-lens', 'run-lens', 'session-lens', 'tool-lens', 'proc-lens', 'evt-egress', 'policy-lens', 'policy_violation', 'high', 'metadata IP access', 'quarantine', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO response_actions (id, run_id, session_id, process_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, created_at)
		VALUES ('response-lens', 'run-lens', 'session-lens', 'proc-lens', 'risk-lens', 'policy-lens', 'quarantine', 'session', 'session-lens', 'recorded', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES
		('edge-policy-risk', 'run-lens', 'policy_decision/policy-lens', 'risk_signal/risk-lens', 'policy_decision_risk_signal', 'evt-egress', ?),
		('edge-risk-response', 'run-lens', 'risk_signal/risk-lens', 'response_action/response-lens', 'risk_signal_response_action', 'evt-egress', ?)`,
		now, now); err != nil {
		t.Fatal(err)
	}
}

func intFromEdgeData(edge GraphLensEdge, key string) int {
	value, ok := edge.Data[key]
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func insertLensEvent(t *testing.T, db *sql.DB, id, eventType, payload, now string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, correlation_method, correlation_confidence, pid, ppid, created_at)
		VALUES (?, 'run-lens', 'session-lens', 'tool-lens', 'proc-lens', 'agentprov_ebpf', ?, ?, 'container_time_window', 0.92, 4242, 4000, ?)`,
		id, eventType, payload, now); err != nil {
		t.Fatal(err)
	}
}

func lensHasNode(manifest GraphLensManifest, id, kind string) bool {
	for _, node := range manifest.Nodes {
		if node.ID == id && node.Kind == kind {
			return true
		}
	}
	return false
}
