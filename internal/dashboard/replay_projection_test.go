package dashboard

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func replayZIPData(t *testing.T, p *PreparedReplay) (map[string][]byte, string) {
	t.Helper()
	var output bytes.Buffer
	if err := p.WriteZIP(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files, all := map[string][]byte{}, &bytes.Buffer{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(f.Name, "data/") {
			prefix := `window.AgentProvOffline.accept("` + strings.TrimSuffix(f.Name, ".js") + `.json.gz","`
			if !bytes.HasPrefix(data, []byte(prefix)) || !bytes.HasSuffix(data, []byte(`");`)) {
				t.Fatalf("unexpected evidence wrapper: %s", f.Name)
			}
			compressed, err := base64.StdEncoding.DecodeString(string(data[len(prefix) : len(data)-3]))
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			data, err = io.ReadAll(gz)
			gz.Close()
			if err != nil || !json.Valid(data) {
				t.Fatalf("invalid evidence JSON: %s %v", f.Name, err)
			}
		}
		if strings.HasSuffix(f.Name, ".db") || strings.HasSuffix(f.Name, ".json.gz") {
			t.Fatalf("private source included: %s", f.Name)
		}
		files[f.Name] = data
		all.Write(data)
	}
	return files, all.String()
}

func TestReplayProjectionWithholdsSharedIntentAndKeepsCapturePolicy(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	policy, _ := agentcontext.NewCapturePolicy("basic", nil)
	svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
	yes, no := true, false
	if err := observability.SaveCaptureSettings(ctx, db, paths, "basic-sharing", observability.CaptureSettings{
		Version: observability.CaptureSettingsVersion, Source: "launch", SensorMode: "auto",
		WorkspaceSnapshot: &yes, TLSFullBody: &no, AgentContext: &yes,
	}); err != nil {
		t.Fatal(err)
	}
	input := `{"type":"assistant","uuid":"a","sessionId":"s","message":{"model":"m","content":[{"type":"text","text":"SELECTED-MODEL-ANSWER"},{"type":"tool_use","id":"private-call","name":"Bash","input":{"command":"EXCLUDED-TOOL-INPUT"}}]}}
{"type":"user","uuid":"r","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"private-call","content":"UNRETAINED-TOOL-OUTPUT"}]}}
`
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "claude", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Save(ctx, "basic-sharing", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "basic-sharing"})
	if err != nil {
		t.Fatal(err)
	}
	var exclude string
	for _, entry := range page.Entries {
		if entry.Kind == "tool_call" {
			exclude = "entry/" + entry.ID
			if entry.IntentContent == nil || entry.IntentContent.State != "stored" {
				t.Fatal("fixture has no shared intent projection")
			}
		}
	}
	if exclude == "" {
		t.Fatal("fixture has no tool call")
	}
	for _, partial := range []bool{false, true} {
		selection := ReplaySelection{RunID: "basic-sharing", Scope: "whole_run"}
		if partial {
			selection.ExcludeRecords = []string{exclude}
		}
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
		if err != nil {
			t.Fatal(err)
		}
		if p.Inventory.CapturePolicy == nil || p.Inventory.CapturePolicy.Preset != "basic" || p.Inventory.CapturePolicy.ToolResults {
			t.Fatal("frozen export preview lost source retention settings")
		}
		if s := p.Inventory.CaptureSettings; s == nil || s.SensorMode != "auto" || !*s.WorkspaceSnapshot || *s.TLSFullBody {
			t.Fatalf("frozen preview lost independent settings: %+v", s)
		}
		files, all := replayZIPData(t, p)
		p.Close()
		if strings.Contains(all, "UNRETAINED-TOOL-OUTPUT") || !strings.Contains(all, "SELECTED-MODEL-ANSWER") {
			t.Fatal("capture policy or retained message changed in replay")
		}
		if strings.Contains(all, "EXCLUDED-TOOL-INPUT") == partial {
			t.Fatalf("partial=%v has wrong tool/intent content", partial)
		}
		found := false
		for _, data := range files {
			var overview agentcontext.Overview
			if json.Unmarshal(data, &overview) == nil && overview.RunID == "basic-sharing" && overview.CapturePolicy != nil {
				found = true
				if overview.CapturePolicy.Preset != "basic" || overview.CapturePolicy.SourceRecords {
					t.Fatalf("changed capture policy: %+v", overview.CapturePolicy)
				}
				if s := overview.CaptureSettings; s == nil || !*s.WorkspaceSnapshot || *s.TLSFullBody || s.Ref == "" {
					t.Fatalf("offline settings changed: %+v", s)
				}
			}
		}
		if !found {
			t.Fatal("offline overview lost source capture policy")
		}
	}
}

func TestReplayProjectionSessionZIP(t *testing.T) {
	paths, db, objects := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	const run = "ui-session-graph"
	pending := int64(235)
	report := observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: run,
		Status: "partial", Scope: "run", KernelState: "observed", RunImpact: "unknown", NodePendingEvents: &pending,
		NodeCounterDelta: map[string]int64{"kernel_dropped_events": 17}, Issues: []string{"node_loss_during_capture"}}
	if err := observability.SaveRuntimeCapture(db, paths, &report); err != nil {
		t.Fatal(err)
	}
	inside := putArtifact(t, objects, run, "workspace_file/shared.txt", map[string]any{"content": "SELECTED-FILE-BODY"})
	outside := putArtifact(t, objects, run, "workspace_file/shared.txt", map[string]any{"content": "UNSELECTED-FILE-VERSION"})
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES ('selected-file',?,'runtime_event/fixture-codex-worker',?,'runtime_event_file','fixture-codex-worker','2026-10-18T00:00:00Z')`, run, inside.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE events SET payload='{"path":"/fixture/shared.txt","note":"UNSELECTED-EVENT-BODY"}' WHERE id='fixture-unassigned'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at)
		VALUES ('boundary-file',?,?,?,'file_version','2026-10-18T00:00:00Z')`, run, inside.Hash, outside.Hash); err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(context.Background(), ReplaySelection{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, all := replayZIPData(t, p)
	for _, marker := range []string{"SELECTED-FILE-BODY", "Synthetic session graph fixture: codex/worker", "Context not included", `"context_not_included":true`, `"status":"subset"`} {
		if !strings.Contains(all, marker) {
			t.Errorf("selected evidence or boundary missing: %s", marker)
		}
	}
	for _, marker := range []string{"UNSELECTED-FILE-VERSION", "UNSELECTED-EVENT-BODY", "Synthetic session graph fixture: codex/root", "Synthetic session graph fixture: claude/root", "Synthetic session graph fixture: codex/quiet"} {
		if strings.Contains(all, marker) {
			t.Errorf("unselected bytes in sharing copy: %s", marker)
		}
	}
	if p.Inventory.Scope != "session" || p.Inventory.Events != 1 || p.Inventory.Contents.ContextEntries != 6 || p.Inventory.Contents.Sessions != 1 {
		t.Fatalf("partial inventory: %+v", p.Inventory)
	}
	if !strings.Contains(string(files["zh-CN/index.html"]), "会话范围 · codex / worker") {
		t.Fatal("partial page presented as whole run")
	}
	foundCoverage := false
	for _, data := range files {
		var overview agentcontext.Overview
		if json.Unmarshal(data, &overview) == nil && overview.RuntimeCoverage.Capture.Ref == report.Ref {
			capture := overview.RuntimeCoverage.Capture
			if capture.Status != "partial" || capture.NodePendingEvents == nil || *capture.NodePendingEvents != 235 || capture.RunDroppedEvents != nil || capture.NodeCounterDelta["kernel_dropped_events"] != 17 {
				t.Fatalf("capture gap changed by selection: %+v", capture)
			}
			foundCoverage = true
		}
	}
	if !foundCoverage {
		t.Fatal("original run-level capture report not retained")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=?`, run).Scan(&count); err != nil || count != 4 {
		t.Fatalf("source store changed: %d %v", count, err)
	}
}

func TestReplayProjectionExcludesRevisionsAndSharedRawBytes(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	src := agentcontext.Source{Harness: "codex", SessionID: "one", Channel: "transcript", ParserVersion: "fixture/v1", Binding: "explicit"}
	ptr := func(s string) *string { return &s }
	save := func(records ...agentcontext.Record) {
		t.Helper()
		if _, err := svc.Save(ctx, "raw-lines", src, records, agentcontext.Coverage{Status: agentcontext.Partial, Issues: []agentcontext.Issue{{Code: "source_truncated"}}}); err != nil {
			t.Fatal(err)
		}
	}
	save(
		agentcontext.Record{Key: "private", Sequence: 1, Kind: "message", Role: "assistant", Body: ptr("EXCLUDED-OLD-BODY"), RawBody: ptr(`{"one":"EXCLUDED-OLD-RAW","two":"PUBLIC-BODY"}`)},
		agentcontext.Record{Key: "public", Sequence: 1, SourceOrdinal: 1, Kind: "message", Role: "user", Body: ptr("PUBLIC-BODY"), RawBody: ptr(`{"one":"EXCLUDED-OLD-RAW","two":"PUBLIC-BODY"}`)},
		agentcontext.Record{Key: "other", Sequence: 2, Kind: "message", Body: ptr("INDEPENDENT-BODY"), RawBody: ptr("INDEPENDENT-RAW")},
	)
	save(agentcontext.Record{Key: "private", Sequence: 1, Kind: "message", Role: "assistant", Body: ptr("EXCLUDED-NEW-BODY"), RawBody: ptr(`{"one":"EXCLUDED-NEW-RAW","two":"PUBLIC-BODY"}`)})
	server := Server{DB: db}
	base, err := server.resolveReplaySelection(ctx, ReplaySelection{RunID: "raw-lines", Scope: "whole_run"})
	if err != nil {
		t.Fatal(err)
	}
	var exclude string
	for _, record := range base.Records {
		if base.Entries[strings.TrimPrefix(record.ID, "entry/")].SourceKey == "private" && record.Indexed {
			exclude = record.ID
		}
	}
	if exclude == "" {
		t.Fatal("fixture record missing")
	}
	p, err := server.PrepareSelectedOfflineReplay(ctx, ReplaySelection{RunID: "raw-lines", Scope: "whole_run", ExcludeRecords: []string{exclude}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_, all := replayZIPData(t, p)
	for _, marker := range []string{"EXCLUDED-OLD-BODY", "EXCLUDED-NEW-BODY", "EXCLUDED-OLD-RAW", "EXCLUDED-NEW-RAW"} {
		if strings.Contains(all, marker) {
			t.Errorf("excluded revision/raw bytes retained: %s", marker)
		}
	}
	for _, marker := range []string{"PUBLIC-BODY", "INDEPENDENT-BODY", "INDEPENDENT-RAW", "shared_raw_record_excluded", "source_truncated"} {
		if !strings.Contains(all, marker) {
			t.Errorf("retained body or gap missing: %s", marker)
		}
	}
	if p.Inventory.Contents.ContextEntries != 2 || p.Inventory.Contents.RawRefs != 1 {
		t.Fatalf("retained readers: %+v", p.Inventory.Contents)
	}
	summary := p.Inventory.SelectionSummary
	if summary == nil || summary.Included != 2 || summary.Excluded != 2 || summary.Reasons["excluded_record"] != 1 || summary.Reasons["linked_record_excluded"] != 1 {
		t.Fatalf("revision-aware selection summary: %+v", summary)
	}
}

func TestReplayProjectionReaderAliasesAndReadonlyDatabase(t *testing.T) {
	paths, db, objects := artifactStore(t)
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	ctx := context.Background()
	const run = "ui-session-graph"
	scope, err := (agentcontext.Service{DB: db}).SessionGraphScope(ctx, run, "codex", "worker")
	if err != nil {
		t.Fatal(err)
	}
	tool := scope.ToolIDs[0]
	alias, err := objects.PutExternalObject(provenance.ExternalObjectInput{Type: "tool_call", RunID: run, SourceID: tool, Payload: map[string]any{"command": "EXCLUDED-TOOL-ENVELOPE"}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := (Server{DB: db}).freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	plan, err := (Server{DB: snapshot.DB}).resolveReplaySelection(ctx, ReplaySelection{RunID: run, Scope: "whole_run", ExcludeRecords: []string{"2/" + tool}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := snapshot.projectSelection(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, query := range []string{`INSERT INTO events(id,source,event_type,payload,created_at) VALUES('write','fixture','exec','{}','now')`, `DELETE FROM tool_calls`} {
		if _, err := p.DB.Exec(query); err == nil {
			t.Fatal("projection database writable")
		}
	}
	var count int
	if err := p.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE hash=?`, alias.Hash).Scan(&count); err != nil || count != 0 {
		t.Fatalf("excluded envelope retained: %d %v", count, err)
	}
	if err := p.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE id='fixture-codex-worker'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("independent runtime effect removed: %d %v", count, err)
	}
	for _, node := range []string{tool, alias.Hash} {
		page, omitted := p.excludedArtifact(node, "raw")
		if !omitted || page.ContentState != "excluded" || page.Content != "" {
			t.Fatalf("reader exclusion missing: %s %+v", node, page)
		}
	}
	root := p.root
	p.Close()
	if _, err := os.Stat(filepath.Join(root, "agentprov.db")); !os.IsNotExist(err) {
		t.Fatalf("projection not cleaned: %v", err)
	}
}

func TestReplayProjectionEmptySelection(t *testing.T) {
	paths, db, _ := artifactStore(t)
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(context.Background(), ReplaySelection{RunID: "ui-session-graph", Scope: "session", Harness: "codex", SessionID: "quiet", ExcludeCategories: []string{"messages"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, _ := replayZIPData(t, p)
	if p.Inventory.Events != 0 || p.Inventory.Contents.ContextEntries != 0 {
		t.Fatalf("empty selection expanded: %+v", p.Inventory)
	}
	for name, data := range files {
		if strings.HasPrefix(name, "data/") {
			var events []telemetry.EventRecord
			if json.Unmarshal(data, &events) == nil && len(events) > 0 && events[0].EventType != "" {
				t.Fatalf("empty session contains events: %s", name)
			}
		}
	}
}

func TestReplayProjectionAnalysisFollowsRetainedEvidence(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	ctx := context.Background()
	const run = "ui-session-graph"
	for _, name := range []string{"worker", "root"} {
		scope, err := svc.SessionGraphScope(ctx, run, "codex", name)
		if err != nil || len(scope.ToolIDs) == 0 || len(scope.EventIDs) == 0 {
			t.Fatalf("fixture: %+v %v", scope, err)
		}
		event, tool := scope.EventIDs[0], scope.ToolIDs[0]
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO policy_decisions(id,run_id,event_id,decision,reason,created_at) VALUES(?,?,?,'deny',?,'2026-10-18')`, []any{"p-" + name, run, event, name + "-POLICY-MARKER"}},
			{`INSERT INTO risk_signals(id,run_id,event_id,tool_call_id,policy_decision_id,signal_type,severity,reason,created_at) VALUES(?,?,?,?,?,'fixture','high',?,'2026-10-18')`, []any{"r-" + name, run, event, tool, "p-" + name, name + "-RISK-MARKER"}},
			{`INSERT INTO response_actions(id,run_id,risk_signal_id,policy_decision_id,action_type,status,target_id,created_at) VALUES(?,?,?,?,'deny','recorded',?,'2026-10-18')`, []any{"a-" + name, run, "r-" + name, "p-" + name, name + "-ACTION-MARKER"}},
			{`INSERT INTO signals(id,run_id,event_id,graph_ref_kind,graph_ref_id,dimension,signal_type,label,created_at) VALUES(?,?,?,'tool_call',?,'security','fixture',?,'2026-10-18')`, []any{"s-" + name, run, event, tool, name + "-SIGNAL-MARKER"}},
			{`INSERT INTO intent_diffs(id,run_id,tool_call_id,status,observed_effects,mismatch_reason,created_at) VALUES(?,?,?,'declared_vs_effect_mismatch',?,?,'2026-10-18')`, []any{"i-" + name, run, tool, fmt.Sprintf(`[{"event_id":%q}]`, event), name + "-INTENT-MARKER"}},
			{`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES(?,?,?,?,'policy_decision_risk_signal','2026-10-18')`, []any{"pr-" + name, run, "policy_decision/p-" + name, "risk_signal/r-" + name}},
			{`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES(?,?,?,?,'risk_signal_response_action','2026-10-18')`, []any{"ra-" + name, run, "risk_signal/r-" + name, "response_action/a-" + name}},
		} {
			if _, err := db.Exec(item.query, item.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(`INSERT INTO signals(id,run_id,event_id,graph_ref_kind,graph_ref_id,dimension,signal_type,label,created_at)
		VALUES ('outside-target',?,'fixture-codex-worker','tool_call','not-retained','security','fixture','OUTSIDE-TARGET-MARKER','2026-10-18')`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO cost_samples(id,run_id,created_at) VALUES('aggregate',?,'2026-10-18')`, run); err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, ReplaySelection{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, all := replayZIPData(t, p)
	for _, kind := range []string{"POLICY", "RISK", "ACTION", "SIGNAL", "INTENT"} {
		if !strings.Contains(all, "worker-"+kind+"-MARKER") || strings.Contains(all, "root-"+kind+"-MARKER") {
			t.Errorf("analysis selection failed for %s", kind)
		}
	}
	if strings.Contains(all, "OUTSIDE-TARGET-MARKER") {
		t.Fatal("analysis referencing an unselected tool leaked")
	}
	for _, table := range []string{"policy_decisions", "risk_signals", "response_actions", "intent_diffs", "cost_samples"} {
		if p.Inventory.AnalysisOmissions[table] != 1 {
			t.Errorf("omission inventory %s: %+v", table, p.Inventory.AnalysisOmissions)
		}
	}
	if p.Inventory.AnalysisOmissions["signals"] != 2 || !strings.Contains(string(files["en/index.html"]), "some analyses omitted") {
		t.Fatal("omitted analysis not disclosed")
	}
}

func TestReplayProjectionChunkedFileAndCategoryExclusion(t *testing.T) {
	paths, db, objects := artifactStore(t)
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	const run = "ui-session-graph"
	body := strings.Repeat("saved long file\n", 20000) + "SELECTED-CHUNK-TAIL"
	content, err := objects.PutTextContent(provenance.TextContentInput{RunID: run, SourceID: "file/long", Text: body})
	if err != nil {
		t.Fatal(err)
	}
	file := putArtifact(t, objects, run, "workspace_file/long.txt", map[string]any{"content_ref": content.Ref})
	legacy := putArtifact(t, objects, run, "workspace_file/legacy.txt", map[string]any{"kind": "stored_text", "text_manifest": content.TextManifest})
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES('long-file',?,'runtime_event/fixture-codex-worker',?,'runtime_event_file','fixture-codex-worker','2026-10-18')`, run, file.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at)
		VALUES('legacy-long-file',?,'runtime_event/fixture-codex-worker',?,'runtime_event_file','fixture-codex-worker','2026-10-18')`, run, legacy.Hash); err != nil {
		t.Fatal(err)
	}
	for _, exclude := range []bool{false, true} {
		selection := ReplaySelection{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker"}
		if exclude {
			selection.ExcludeCategories = []string{"files"}
		}
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(context.Background(), selection)
		if err != nil {
			t.Fatal(err)
		}
		files, all := replayZIPData(t, p)
		encoded := strings.TrimSuffix(strings.TrimPrefix(string(files["assets/catalog.js"]), `window.AgentProvOfflineCatalog="`), `";`)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		var catalog struct{ Runs map[string]ReplayRun }
		if err != nil || json.Unmarshal(raw, &catalog) != nil {
			t.Fatal("invalid catalog")
		}
		var readers map[string]ReplayPages
		if err := json.Unmarshal(files[strings.Replace(catalog.Runs[run].Artifacts.Path, ".json.gz", ".js", 1)], &readers); err != nil {
			t.Fatal(err)
		}
		for _, hash := range []string{file.Hash, legacy.Hash} {
			pages := readers["en/body/"+hash]
			if len(pages.Pages) == 0 {
				t.Fatalf("missing artifact reader %s", hash)
			}
			var last artifactResp
			if err := json.Unmarshal(files[strings.Replace(pages.Pages[len(pages.Pages)-1].Path, ".json.gz", ".js", 1)], &last); err != nil {
				t.Fatal(err)
			}
			if exclude && last.ContentState != "excluded" || !exclude && !strings.Contains(last.Content, "SELECTED-CHUNK-TAIL") {
				t.Fatalf("chunk reader, exclude=%v: %+v", exclude, last)
			}
		}
		p.Close()
		if strings.Contains(all, "SELECTED-CHUNK-TAIL") == exclude {
			t.Errorf("chunk tail selection failed, exclude=%v", exclude)
		}
	}
}

func TestReplayProjectionFailureCleansPrivateStore(t *testing.T) {
	paths, db, _ := artifactStore(t)
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	snapshot, err := (Server{DB: db}).freezeReplaySource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	plan, err := (Server{DB: snapshot.DB}).resolveReplaySelection(context.Background(), ReplaySelection{RunID: "ui-session-graph", Scope: "session", Harness: "codex", SessionID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	t.Setenv("TMPDIR", private)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = snapshot.projectSelection(ctx, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	snapshot.DB.Close()
	if _, err = snapshot.projectSelection(context.Background(), plan); err == nil {
		t.Fatal("broken source accepted")
	}
	entries, err := os.ReadDir(private)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private projection left after failure: %v %v", entries, err)
	}
}
