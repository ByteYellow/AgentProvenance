package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedBundleRetainsExplicitZeroConfidence(t *testing.T) {
	const runID = "run-zero-confidence"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	if _, err := correlation.RecordBinding(db, correlation.Binding{ID: "scope", RunID: runID, CgroupID: "cg", ConfidenceSet: true, StartedAt: "2026-10-17T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{RunID: runID, CgroupID: "cg", Source: "agentprov_ebpf", EventType: "execve", PID: 42, Payload: `{"argv":["true"]}`, Timestamp: "2026-10-17T00:00:01Z"}); err != nil {
		t.Fatal(err)
	}
	if _, err := signals.Record(db, signals.Signal{ID: "zero-signal", RunID: runID, Dimension: signals.Quality, Type: "judgment", GraphRefKind: "run", GraphRefID: runID, ConfidenceSet: true}); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	bindings, err := correlation.ListBindings(replayDB, correlation.BindingFilter{RunID: runID})
	if err != nil || len(bindings) != 1 || bindings[0].Confidence != 0 {
		t.Fatalf("bindings=%+v err=%v", bindings, err)
	}
	events, err := telemetry.ListEvents(replayDB, runID, "")
	if err != nil || len(events) != 1 || events[0].CorrelationConfidence != 0 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	set, err := signals.Export(replayDB, runID)
	if err != nil || len(set.Signals) != 1 || set.Signals[0].Confidence != 0 {
		t.Fatalf("signals=%+v err=%v", set, err)
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signals.ValidateWireBytes(raw); err != nil {
		t.Fatal(err)
	}
	result, err := provenance.Verify(replayDB, runID)
	if err != nil || result.Status != "ok" {
		t.Fatalf("verify=%+v err=%v", result, err)
	}
}

func TestSignedBundleRetainsRuntimeLifetimes(t *testing.T) {
	const runID = "run-process-lifetimes"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	if _, err := correlation.RecordBinding(db, correlation.Binding{ID: "scope", RunID: runID, CgroupID: "cg", StartedAt: "2026-10-17T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	for i, birth := range []int{100, 200, 100} {
		origin := boot
		if i == 2 {
			origin = "11234567-89ab-cdef-0123-456789abcdef"
		}
		payload, _ := json.Marshal(map[string]any{"argv": []string{"true"}, "command": fmt.Sprintf("worker-%d", i), "process_instance_id": fmt.Sprintf("%s:42:%d", origin, birth), "parent_process_instance_id": origin + ":1:10"})
		if _, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{RunID: runID, CgroupID: "cg", Source: "agentprov_ebpf", EventType: "execve", PID: 42, PPID: 1, Payload: string(payload), Timestamp: fmt.Sprintf("2026-10-17T00:00:0%dZ", i)}); err != nil {
			t.Fatal(err)
		}
	}
	opts := provenance.GraphLensOptions{RunID: runID, Lens: "process", Detail: "raw"}
	before, err := provenance.BuildGraphLens(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Nodes) != 8 {
		t.Fatalf("merged process graph: %+v", before.Nodes)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	after, err := provenance.BuildGraphLens(replayDB, opts)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(before.Edges, func(i, j int) bool { return before.Edges[i].ID < before.Edges[j].ID })
	sort.Slice(after.Edges, func(i, j int) bool { return after.Edges[i].ID < after.Edges[j].ID })
	if !reflect.DeepEqual(before.Nodes, after.Nodes) || !reflect.DeepEqual(before.Edges, after.Edges) {
		t.Fatalf("lifecycle graph changed across signed roundtrip\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestSignedBundleRetainsRecordedCorrelationAmbiguity(t *testing.T) {
	const runID = "run-correlation"
	pathsA := mustInit(t, filepath.Join(t.TempDir(), "source"))
	dbA := mustOpen(t, pathsA)
	defer dbA.Close()
	for _, id := range []string{"alice", "bob"} {
		if _, err := correlation.RecordBinding(dbA, correlation.Binding{
			ID: id, RunID: runID, SessionID: "session", ToolCallID: "tool-" + id,
			CgroupID: "cg", StartedAt: "2026-10-17T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	eventID, err := telemetry.IngestFiltered(dbA, telemetry.IngestEvent{
		CgroupID: "cg", PID: 30, EventType: "execve", Source: "agentprov_ebpf",
		Timestamp: "2026-10-17T00:00:01Z", Payload: `{"argv":["python3","setup.py","install"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := telemetry.CorrelationReportOptions{EventID: eventID}
	original, err := telemetry.BuildCorrelationReport(dbA, opts)
	if err != nil || len(original.Items) != 1 || original.Items[0].Match.Status != "ambiguous" {
		t.Fatalf("original: %+v err=%v", original, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: dbA, Paths: pathsA, SignKey: priv}).ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	pathsB := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbB := mustOpen(t, pathsB)
	defer dbB.Close()
	if _, err := (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	for _, afterUpdate := range []bool{false, true} {
		if afterUpdate {
			if err := correlation.CloseBindingByID(dbB, "bob", "2026-10-17T00:00:00.5Z"); err != nil {
				t.Fatal(err)
			}
		}
		replayed, err := telemetry.BuildCorrelationReport(dbB, opts)
		if err != nil || !reflect.DeepEqual(original, replayed) {
			t.Fatalf("recorded attribution changed after export/import or binding update: %+v err=%v", replayed, err)
		}
	}
}

func TestSignedBundleRetainsModelCommandDerivation(t *testing.T) {
	const runID = "run-model-correlation"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	const boot = "12345678-1234-1234-1234-123456789abc"
	for _, ev := range []struct{ id, typ, at, content string }{
		{"req", "tls_write", "2026-10-17T00:00:00Z", `{"messages":[{"role":"user","content":"Read config"}]}`},
		{"resp", "tls_read", "2026-10-17T00:00:01Z", `{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat /work/config"}}]}`},
		{"exec", "execve", "2026-10-17T00:00:02Z", ""},
	} {
		payload := map[string]any{"content": ev.content, "process_instance_id": boot + ":100:800", "argv": []string{"cat", "/work/config"}}
		if ev.typ != "execve" {
			http := map[string]any{"connection_id": "tls-v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "protocol": "h2", "headers_decoded": true, "stream_id": 1}
			if ev.typ == "tls_write" {
				http["method"] = "POST"
			} else {
				http["status"] = 200
			}
			payload["http"] = http
		}
		body, _ := json.Marshal(payload)
		if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,cgroup_id,pid,payload) VALUES (?,?,'agentprov_ebpf',?,?,'cg-a',100,?)`, ev.id, runID, ev.typ, ev.at, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at) VALUES ('pair',?,'runtime_event/req','runtime_event/resp','llm_call','2026-10-17T00:00:01Z')`, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, runID); err != nil {
		t.Fatal(err)
	}
	opts := provenance.GraphLensOptions{RunID: runID, Lens: "agent-intent", Detail: "raw"}
	original, err := provenance.BuildGraphLens(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	var expected provenance.GraphLensEdge
	var expectedPair provenance.GraphLensEdge
	for _, edge := range original.DerivedEdges {
		if edge.EdgeType == "llm_caused" {
			expected = edge
		}
		if edge.EdgeType == "llm_call" {
			expectedPair = edge
		}
	}
	if expected.ID == "" || expected.DerivationRule != "agentprov.intent_command_scope/v2" || len(expected.EvidenceRefs) != 3 {
		t.Fatalf("source inference metadata: %+v", expected)
	}
	if expectedPair.DerivationRule != "agentprov.tls_connection_exchange/v1" || expectedPair.Confidence == nil || *expectedPair.Confidence != 1 || len(expectedPair.EvidenceRefs) != 2 {
		t.Fatalf("source pairing metadata: %+v", expectedPair)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: priv}).ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	replayed, err := provenance.BuildGraphLens(replayDB, opts)
	if err != nil {
		t.Fatal(err)
	}
	commandFound, pairFound := false, false
	for _, edge := range replayed.DerivedEdges {
		commandFound = commandFound || reflect.DeepEqual(expected, edge)
		pairFound = pairFound || reflect.DeepEqual(expectedPair, edge)
	}
	if !commandFound || !pairFound {
		t.Fatalf("derived associations changed in replay: %+v", replayed.DerivedEdges)
	}
	correlations := func(graph provenance.GraphLensManifest) map[string]string {
		out := map[string]string{}
		for _, node := range graph.Nodes {
			if value := node.Data["correlation"]; value != nil {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				out[node.ID] = string(raw)
			}
		}
		return out
	}
	if before, after := correlations(original), correlations(replayed); len(before) != 2 || !reflect.DeepEqual(before, after) {
		t.Fatalf("pair diagnostics changed in replay: %v / %v", before, after)
	}
}
