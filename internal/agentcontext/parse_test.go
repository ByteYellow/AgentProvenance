package agentcontext

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/klauspost/compress/zstd"
)

func parseFixture(t *testing.T, harness, input string) Parsed {
	t.Helper()
	p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: harness, Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const codexFixture = `{"type":"session_meta","timestamp":"2026-09-28T10:00:00Z","payload":{"id":"thread-a","cwd":"/task","cli_version":"0.143.0"}}
{"type":"turn_context","timestamp":"2026-09-28T10:00:01Z","payload":{"approval_policy":"on-request","sandbox_policy":{"type":"workspace-write"},"model":"example"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Run the test suite"}]}}
{"type":"response_item","payload":{"type":"function_call","call_id":"call-one","name":"exec_command","arguments":"{\"cmd\":\"python3 -m unittest\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"call-one","output":"FAILED: expected 2, got 3"}}
{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"edit-one","name":"apply_patch","input":"*** Begin Patch\n*** End Patch"}}
{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"edit-one","output":"patch rejected","is_error":true}}
{"type":"response_item","payload":{"type":"function_call","call_id":"spawn-one","name":"multi_agent.spawn_agent","arguments":"{\"message\":\"inspect tests\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"spawn-one","output":"{\"agent_id\":\"child-real\"}"}}
`

func TestCodexCompleteContextAndRealChildIdentity(t *testing.T) {
	p := parseFixture(t, "codex", codexFixture)
	if p.Coverage.Status != OK || p.Source.SessionID != "thread-a" {
		t.Fatalf("parse: %+v", p)
	}
	counts := map[string]int{}
	child, failed, output := false, false, false
	for _, r := range p.Records {
		counts[r.Kind]++
		if r.RawBody == nil {
			t.Fatal("raw source missing")
		}
		if r.ToolCallID == "call-one" && r.Kind == "tool_result" {
			output = r.Body != nil && strings.Contains(*r.Body, "expected 2") && r.ToolName == "exec_command" && r.Status == "returned"
		}
		if r.ToolCallID == "edit-one" && r.Status == "error" {
			failed = true
		}
		if r.Kind == "session" && r.Status == "started" && strings.Contains(*r.Body, "child-real") {
			child = true
		}
	}
	if counts["tool_call"] != 3 || counts["tool_result"] != 3 || counts["configuration"] != 1 || !child || !failed || !output {
		t.Fatalf("context=%v child=%v error=%v output=%v", counts, child, failed, output)
	}
	childLog := `{"type":"session_meta","payload":{"id":"child-real","source":{"subagent":{"thread_spawn":{"parent_thread_id":"thread-a"}}}}}`
	c := parseFixture(t, "codex", childLog)
	if c.Source.ParentSessionID != "thread-a" || c.Source.AgentID != "child-real" {
		t.Fatalf("child: %+v", c.Source)
	}
}

func TestClaudeToolsAndHookPermissionAreNotConflated(t *testing.T) {
	input := `{"type":"user","uuid":"u","sessionId":"s","message":{"role":"user","content":"fix tests"}}
{"type":"assistant","uuid":"a","sessionId":"s","message":{"role":"assistant","model":"example","content":[{"type":"text","text":"Running tests"},{"type":"tool_use","id":"call","name":"Bash","input":{"command":"false"}}]}}
{"type":"user","uuid":"r","sessionId":"s","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call","is_error":true,"content":"exit code 1"}]}}
`
	p := parseFixture(t, "claude", input)
	if p.Coverage.Status != OK || len(p.Records) != 5 {
		t.Fatalf("claude: %+v", p)
	}
	result := p.Records[len(p.Records)-1]
	if result.Kind != "tool_result" || result.Role != "tool" || result.Status != "error" || *result.Body != "exit code 1" {
		t.Fatalf("result: %+v", result)
	}
	hooks := `{"session_id":"s","hook_event_name":"PermissionRequest","agent_id":"alice","tool_name":"Bash","tool_use_id":"alice-call","tool_input":{"command":"ls"},"permission_mode":"default"}
{"session_id":"s","hook_event_name":"PostToolUseFailure","agent_id":"bob","tool_name":"Bash","tool_use_id":"bob-call","error":"not permitted"}
`
	h := parseFixture(t, "claude", hooks)
	if h.Coverage.Status != OK || h.Source.Channel != "hooks" || h.Records[0].Status != "requested" || h.Records[0].AgentID != "alice" || h.Records[2].AgentID != "bob" {
		t.Fatalf("hooks: %+v", h)
	}
	if sourceID(h.Source) == sourceID(p.Source) {
		t.Fatal("hook and transcript source collide")
	}
}

func TestParseDiagnosticsAndResume(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		status      Status
		code        string
	}{
		{"broken-line", codexFixture + "not json\n", Partial, "malformed_json"},
		{"pending-tail", codexFixture + `{"type":`, Partial, "incomplete_tail"},
		{"new-type", codexFixture + `{"type":"future","secret":"do not echo"}` + "\n", Partial, "unrecognized_record"},
		{"wrong-session", codexFixture + `{"type":"session_meta","payload":{"id":"other"}}` + "\n", Ambiguous, "session_identity_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := parseFixture(t, "codex", tc.input)
			if p.Coverage.Status != tc.status {
				t.Fatalf("status=%s", p.Coverage.Status)
			}
			found := false
			for _, issue := range p.Coverage.Issues {
				if issue.Code == tc.code {
					found = true
				}
			}
			if !found {
				t.Fatalf("issues=%+v", p.Coverage.Issues)
			}
			if tc.status == Ambiguous && len(p.Records) != 0 {
				t.Fatal("cross-session records accepted")
			}
			raw, _ := json.Marshal(p.Coverage)
			if bytes.Contains(raw, []byte("do not echo")) {
				t.Fatal("diagnostic contains body")
			}
		})
	}
	resumed, err := Parse(context.Background(), strings.NewReader(codexFixture), ParseOptions{Harness: "codex", Binding: "explicit", SessionID: "thread-a", AfterLine: 7})
	if err != nil || resumed.Source.SessionID != "thread-a" || len(resumed.Records) != 3 || resumed.Records[0].Sequence != 8 {
		t.Fatalf("resume: %+v %v", resumed, err)
	}
	wrong, err := Parse(context.Background(), strings.NewReader(codexFixture), ParseOptions{Harness: "codex", Binding: "explicit", SessionID: "not-this-session"})
	if err != nil || wrong.Coverage.Status != Ambiguous || len(wrong.Records) != 0 {
		t.Fatalf("identity: %+v %v", wrong, err)
	}
}

const deepseekEvents = `{"type":"permission/preset","seq":0,"time":1790548591382,"data":{"preset":"default"}}
{"type":"user/message","seq":1,"time":1790548591412,"surfaceOp":"append","data":{"role":"user","content":[{"type":"text","text":"run tests"}]}}
{"type":"request/header","seq":2,"time":1790548591414,"data":{"header":{"config":{"model":"example","provider":"deepseek-official"}},"reason":"initial"}}
{"type":"tool/call","seq":3,"time":1790548592000,"data":{"callId":"c","name":"bash","arguments":"{\"command\":\"python3 -m unittest\"}"}}
{"type":"approval/asked","seq":4,"time":1790548592001,"data":{"callId":"c","request":"execute"}}
{"type":"approval/decided","seq":5,"time":1790548592002,"data":{"callId":"c","decision":"allow"}}
{"type":"tool/result","seq":6,"time":1790548592328,"surfaceOp":"append","data":{"message":{"role":"tool","toolCallId":"c","isError":true,"content":[{"type":"text","text":"FAILED tests"}]},"error":{"name":"Exit","code":"1","reason":"test failed"},"meta":{"diff":"saved diff"}}}
{"type":"assistant/message","seq":7,"time":1790548592500,"surfaceOp":"append","data":{"message":{"role":"assistant","content":[{"type":"text","text":"The test failed."}]},"stream":[]}}
`

func TestDeepSeekVersionsAndCompressedFrames(t *testing.T) {
	for _, version := range []string{"3", "4"} {
		t.Run("v"+version, func(t *testing.T) {
			s := testService(t)
			header := `{"type":"session","version":` + version + `,"id":"dsh-session","createdAt":1790548591000,"cwd":"/task","isSeeded":false}` + "\n"
			encoder, err := zstd.NewWriter(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer encoder.Close()
			var compressed []byte
			// The real writer commits concatenated frames, including a header-only frame.
			for _, part := range []string{header, deepseekEvents} {
				compressed = append(compressed, encoder.EncodeAll([]byte(part), nil)...)
			}
			path := filepath.Join(t.TempDir(), "session.v"+version+".jsonl.zstd")
			if err := os.WriteFile(path, compressed, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := s.ImportFile(context.Background(), "run", ParseOptions{Harness: "deepseek", Path: path, Binding: "explicit"})
			if err != nil || result.Coverage.Status != OK || result.Stored != 9 {
				t.Fatalf("import: %+v %v", result, err)
			}
			page, err := s.Entries(context.Background(), PageOptions{RunID: "run", Kind: "tool_result"})
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("page: %+v %v", page, err)
			}
			body, err := provenance.ReadTextContentPage(s.DB, "run", page.Entries[0].Content.Ref, 0, 4096)
			if err != nil || !strings.Contains(body.Content, "saved diff") || page.Entries[0].Status != "error" {
				t.Fatalf("result: %+v %v", body, err)
			}
			raw, err := provenance.ReadTextContentPage(s.DB, "run", page.Entries[0].RawContent.Ref, 0, 4096)
			if err != nil || !strings.Contains(raw.Content, `"seq":6`) {
				t.Fatalf("raw: %+v %v", raw, err)
			}
			repeated, err := s.ImportFile(context.Background(), "run", ParseOptions{Harness: "deepseek", Path: path, Binding: "explicit"})
			if err != nil || repeated.Stored != 0 || repeated.Duplicates != 9 {
				t.Fatalf("repeat: %+v %v", repeated, err)
			}
		})
	}
	unknown := parseFixture(t, "deepseek", `{"type":"session","version":99,"id":"future"}`+"\n"+deepseekEvents)
	if unknown.Coverage.Status != Failed || len(unknown.Records) != 0 {
		t.Fatalf("unknown: %+v", unknown)
	}
}

func TestCompatibilityAdaptersRetainResults(t *testing.T) {
	for _, tc := range []struct{ harness, input string }{
		{"kimi", `{"type":"metadata","session_id":"s","protocol_version":"1.4"}
{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"c","name":"Bash","args":{"command":"ls"}}}
{"type":"context.append_loop_event","event":{"type":"tool.result","toolCallId":"c","result":{"output":"hello"}}}`},
		{"grok", `{"role":"user","session_id":"s","content":"read the file"}
{"role":"assistant","tool_calls":[{"id":"c","function":{"name":"read_file","arguments":"{\"path\":\"a.py\"}"}}]}
{"role":"tool","tool_call_id":"c","content":"hello"}`},
	} {
		p := parseFixture(t, tc.harness, tc.input)
		if p.Coverage.Status != OK {
			t.Fatalf("%s: %+v", tc.harness, p)
		}
		last := p.Records[len(p.Records)-1]
		if last.Kind != "tool_result" || last.ToolCallID != "c" || !strings.Contains(*last.Body, "hello") {
			t.Fatalf("%s: %+v", tc.harness, last)
		}
	}
}

type brokenReader struct{ sent bool }

func (r *brokenReader) Read(b []byte) (int, error) {
	if r.sent {
		return 0, io.ErrUnexpectedEOF
	}
	r.sent = true
	return copy(b, `{"type":"session_meta","payload":{"id":"s"}}`+"\n"), nil
}

func TestReadFailureAndEmptyUnknownAreVisible(t *testing.T) {
	p, err := Parse(context.Background(), &brokenReader{}, ParseOptions{Harness: "codex", Binding: "explicit"})
	if err != nil || p.Coverage.Status != Partial || *p.Coverage.Counts.Failed != 1 {
		t.Fatalf("failed read: %+v %v", p, err)
	}
	empty, err := Parse(context.Background(), strings.NewReader(""), ParseOptions{Harness: "codex", SessionID: "s", Binding: "explicit"})
	if err != nil || empty.Coverage.Status != Empty || *empty.Coverage.Counts.Read != 0 {
		t.Fatalf("empty: %+v %v", empty, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, strings.NewReader(codexFixture), ParseOptions{Harness: "codex"}); err == nil {
		t.Fatal("cancel ignored")
	}
}
