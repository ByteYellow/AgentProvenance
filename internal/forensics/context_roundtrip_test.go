package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/intent"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSignedPeerMessageRetainsOfflineBodyAndContract(t *testing.T) {
	ctx := context.Background()
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	body := strings.Repeat("peer message evidence\n", 420000) + "END-OF-PEER-MESSAGE"
	raw, err := json.Marshal(map[string]any{
		"recipient": "bob", "message": body,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := string(raw)
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, "run", agentcontext.Source{Harness: "claude", SessionID: "s", AgentID: "alice", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
		{Key: "send", Sequence: 1, Kind: "tool_call", AgentID: "alice", ToolCallID: "send", ToolName: "SendMessage", Body: &input},
	}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	var message string
	if err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE run_id='run' AND object_type='artifact' AND source_id LIKE 'agent_message/%'`).Scan(&message); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	fresh := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbFresh := mustOpen(t, fresh)
	defer dbFresh.Close()
	info, err := (forensics.Service{DB: dbFresh, Paths: fresh}).ImportBundle(bundle.Path)
	if err != nil || info.Omitted != 0 {
		t.Fatalf("import: %+v %v", info, err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	handler := (dashboard.Server{DB: dbFresh}).Handler()
	var output strings.Builder
	for offset := int64(0); ; {
		query := url.Values{"run": {"run"}, "node": {message}, "mode": {"body"}, "offset": {fmt.Sprint(offset)}, "limit": {"262144"}}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/artifact?"+query.Encode(), nil))
		var page struct {
			Content      string `json:"content"`
			ContentState string `json:"content_state"`
			NextOffset   int64  `json:"next_offset"`
			HasMore      bool   `json:"has_more"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.ContentState != "stored" {
			t.Fatalf("offline body: %s %v", w.Body.String(), err)
		}
		output.WriteString(page.Content)
		if !page.HasMore {
			break
		}
		if page.NextOffset <= offset {
			t.Fatal("body page did not advance")
		}
		offset = page.NextOffset
	}
	if output.String() != body {
		t.Fatal("offline peer message or its tail changed")
	}
	contracts, err := intent.ExtractContracts(dbFresh, "run", nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, contract := range contracts {
		if contract.Kind == intent.ContractPeerMessage {
			found = true
			if contract.Target != body || contract.ScopeAgent != "bob" {
				t.Fatal("peer contract no longer reads its saved message")
			}
		}
	}
	if !found {
		t.Fatal("peer contract disappeared after portable replay")
	}
	v, err := provenance.Verify(dbFresh, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify peer message: %+v %v", v, err)
	}
	var messages int
	if err := dbFresh.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id='run' AND source_id LIKE 'agent_message/%'`).Scan(&messages); err != nil || messages != 1 {
		t.Fatalf("content chunks were exposed as additional messages: %d %v", messages, err)
	}
	var chunkPath string
	if err := dbFresh.QueryRow(`SELECT path FROM provenance_objects WHERE run_id='run' AND object_type='text_chunk' AND source_id LIKE 'agent_message_body/%' LIMIT 1`).Scan(&chunkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(chunkPath, chunkPath+"-missing"); err != nil {
		t.Fatal(err)
	}
	if _, err := intent.ExtractContracts(dbFresh, "run", nil); err == nil {
		t.Fatal("missing peer message content was silently omitted from analysis")
	}
}

func TestSignedContextRoundTripBeyondLegacyLimits(t *testing.T) {
	for _, size := range []int{(64 << 10) + 19, (4 << 20) + 19, (8 << 20) + 19} {
		t.Run(stringSize(size), func(t *testing.T) {
			ctx := context.Background()
			pathsA := mustInit(t, filepath.Join(t.TempDir(), "source"))
			dbA := mustOpen(t, pathsA)
			t.Cleanup(func() { dbA.Close() })
			body := strings.Repeat("x", size) + "END-OF-RESULT"
			svc := agentcontext.Service{DB: dbA, Paths: pathsA}
			_, err := svc.Save(ctx, "run", agentcontext.Source{Harness: "codex", SessionID: "session", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
				{Key: "result", Sequence: 1, Kind: "tool_result", ToolCallID: "tool", Body: &body},
			}, agentcontext.Coverage{Status: agentcontext.OK, Counts: agentcontext.Counts{Read: agentcontext.Number(1)}})
			if err != nil {
				t.Fatal(err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: dbA, Paths: pathsA, SignKey: key}).ExportBundle("run")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			pathsB := mustInit(t, filepath.Join(t.TempDir(), "replay"))
			dbB := mustOpen(t, pathsB)
			t.Cleanup(func() { dbB.Close() })
			info, err := (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(bundle.Path)
			if err != nil || info.Omitted != 0 {
				t.Fatalf("import: %+v %v", info, err)
			}
			// Remove the original blob location: replay must use only store B.
			if err := os.Rename(pathsA.Provenance, pathsA.Provenance+"-offline"); err != nil {
				t.Fatal(err)
			}
			page, err := (agentcontext.Service{DB: dbB, Paths: pathsB}).Entries(ctx, agentcontext.PageOptions{RunID: "run"})
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("entries: %+v %v", page, err)
			}
			var output strings.Builder
			for offset := int64(0); ; {
				p, err := provenance.ReadTextContentPage(dbB, "run", page.Entries[0].Content.Ref, offset, 200000)
				if err != nil {
					t.Fatal(err)
				}
				output.WriteString(p.Content)
				if !p.HasMore {
					break
				}
				offset = p.NextOffset
			}
			if output.String() != body {
				t.Fatal("offline full text differs")
			}
			o, err := (agentcontext.Service{DB: dbB, Paths: pathsB}).Overview(ctx, "run")
			if err != nil || len(o.Coverage) != 1 || o.Coverage[0].Status != agentcontext.OK || o.ToolResults == nil || *o.ToolResults != 1 {
				t.Fatalf("coverage: %+v %v", o, err)
			}
		})
	}
}

func TestSignedConfigurationHistoryRetainsOfflineComparison(t *testing.T) {
	ctx := context.Background()
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	svc := agentcontext.Service{DB: db, Paths: paths}
	a, b := `{"model":"first","sandbox":"read-only"}`, `{"model":"second"}`
	const historyGap = "configuration.change_history_completeness"
	if _, err := svc.Save(ctx, "run", agentcontext.Source{Harness: "codex", SessionID: "s", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
		{Key: "before", Sequence: 1, Kind: "configuration", Body: &a},
		{Key: "after", Sequence: 2, Kind: "configuration", Body: &b},
	}, agentcontext.Coverage{Status: agentcontext.OK, MissingFields: []string{historyGap}}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(p.Entries) != 2 {
		t.Fatalf("history: %+v %v", p, err)
	}
	before, err := svc.CompareSnapshots(ctx, "run", p.Entries[0].ID, "", p.Entries[1].ID)
	if err != nil || before.Status != "different" {
		t.Fatalf("comparison: %+v %v", before, err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	fresh := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbFresh := mustOpen(t, fresh)
	defer dbFresh.Close()
	if _, err := (forensics.Service{DB: dbFresh, Paths: fresh}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	after, err := (agentcontext.Service{DB: dbFresh, Paths: fresh}).CompareSnapshots(ctx, "run", p.Entries[0].ID, "", p.Entries[1].ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("portable configuration changed: before=%+v after=%+v err=%v", before, after, err)
	}
	report, err := (agentcontext.Service{DB: dbFresh, Paths: fresh}).Overview(ctx, "run")
	if err != nil || len(report.Coverage) != 1 || !reflect.DeepEqual(report.Coverage[0].MissingFields, []string{historyGap}) {
		t.Fatalf("portable configuration coverage changed: %+v %v", report, err)
	}
	v, err := provenance.Verify(dbFresh, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify history: %+v %v", v, err)
	}
}

func stringSize(n int) string {
	if n < 1<<20 {
		return "64KiB"
	}
	if n < 8<<20 {
		return "4MiB"
	}
	return "8MiB"
}

func TestSignedCodexSourceFormsAndOutcomesReplayOffline(t *testing.T) {
	ctx := context.Background()
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	input := `{"type":"session_meta","payload":{"id":"s","cli_version":"fixture-version"}}
{"type":"event_msg","payload":{"type":"user_message","message":"run tests","images":["source-image-ref"]}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"run tests"}]}}
{"type":"response_item","payload":{"type":"function_call","call_id":"c","name":"exec_command","arguments":"{\"cmd\":\"false\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":{"output":"failure details","metadata":{"exit_code":1}}}}
`
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "codex", Binding: "explicit"})
	if err != nil || parsed.Coverage.Status != agentcontext.OK {
		t.Fatalf("parse: %+v %v", parsed, err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	before, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(before.Entries) != 5 {
		t.Fatalf("source records: %+v %v", before, err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	fresh := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbFresh := mustOpen(t, fresh)
	defer dbFresh.Close()
	info, err := (forensics.Service{DB: dbFresh, Paths: fresh}).ImportBundle(bundle.Path)
	if err != nil || info.Omitted != 0 {
		t.Fatalf("import: %+v %v", info, err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	replay := agentcontext.Service{DB: dbFresh, Paths: fresh}
	after, err := replay.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("source identities, representations or references changed: %v", err)
	}
	for i, entry := range after.Entries {
		for _, content := range []struct{ ref, expected string }{
			{entry.Content.Ref, *parsed.Records[i].Body}, {entry.RawContent.Ref, *parsed.Records[i].RawBody},
		} {
			page, err := provenance.ReadTextContentPage(dbFresh, "run", content.ref, 0, 65536)
			if err != nil || page.Content != content.expected {
				t.Fatalf("offline content: %+v %v", page, err)
			}
		}
	}
	links, err := replay.Links(ctx, "run", after.Entries[4].ID)
	if err != nil || len(links.Links) != 1 || links.Links[0].Relation != "context_tool_result" {
		t.Fatalf("replayed source failure link: %+v %v", links, err)
	}
	v, err := provenance.Verify(dbFresh, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify replay: %+v %v", v, err)
	}
}

func TestSignedCompoundAndDispatchedContextReplayOffline(t *testing.T) {
	for _, tc := range []struct{ harness, input string }{
		{"claude", `{"type":"user","sessionId":"s","message":{"content":"one"}}` + "\x00" + `{"type":"user","sessionId":"s","message":{"content":"two"}}` + "\n"},
		{"deepseek", `{"type":"session","version":4,"id":"s"}
{"type":"tool/ptc-dispatch-start","seq":0,"time":1790548591000,"data":{"subCallId":"sub","parentCallId":"parent","name":"read_file","arguments":{"path":"report.py"}}}
{"type":"tool/ptc-dispatch","seq":1,"time":1790548592000,"data":{"subCallId":"sub","parentCallId":"parent","name":"read_file","arguments":{"path":"report.py"},"isError":true,"content":[{"type":"text","text":"not found"}]}}
{"type":"tool/result","seq":2,"time":1790548593000,"surfaceOp":{"op":"replace","startSeq":1,"endSeq":1},"sourceEventSeqs":[1],"data":{"message":{"toolCallId":"sub","content":[{"type":"text","text":"summary"}]}}}
`},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			ctx := context.Background()
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			parsed, err := agentcontext.Parse(ctx, strings.NewReader(tc.input), agentcontext.ParseOptions{Harness: tc.harness, Binding: "explicit"})
			if err != nil || parsed.Coverage.Status != agentcontext.OK {
				t.Fatalf("parse: %+v %v", parsed, err)
			}
			svc := agentcontext.Service{DB: db, Paths: paths}
			if _, err := svc.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
				t.Fatal(err)
			}
			if _, err := hooksbridge.IngestContext(ctx, db, paths, "run"); err != nil {
				t.Fatal(err)
			}
			before, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", IncludeRevisions: true})
			if err != nil || len(before.Entries) != len(parsed.Records) {
				t.Fatalf("source records: %+v %v", before, err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			fresh := mustInit(t, filepath.Join(t.TempDir(), "replay"))
			dbFresh := mustOpen(t, fresh)
			defer dbFresh.Close()
			info, err := (forensics.Service{DB: dbFresh, Paths: fresh}).ImportBundle(bundle.Path)
			if err != nil || info.Omitted != 0 {
				t.Fatalf("import: %+v %v", info, err)
			}
			if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
				t.Fatal(err)
			}
			replayed := agentcontext.Service{DB: dbFresh, Paths: fresh}
			after, err := replayed.Entries(ctx, agentcontext.PageOptions{RunID: "run", IncludeRevisions: true})
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("replay changed source records: %v", err)
			}
			for i, entry := range after.Entries {
				for _, item := range []struct{ ref, want string }{
					{entry.Content.Ref, *parsed.Records[i].Body}, {entry.RawContent.Ref, *parsed.Records[i].RawBody},
				} {
					page, err := provenance.ReadTextContentPage(dbFresh, "run", item.ref, 0, 65536)
					if err != nil || page.Content != item.want {
						t.Fatalf("saved content changed: %+v %v", page, err)
					}
				}
			}
			v, err := provenance.Verify(dbFresh, "run")
			if err != nil || v.ErrorCount != 0 {
				t.Fatalf("graph verify: %+v %v", v, err)
			}
		})
	}
}
