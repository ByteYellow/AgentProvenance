package agentcontext

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const deepseekToolForms = `{"type":"assistant/message","seq":0,"time":1790548591000,"data":{"message":{"role":"assistant","content":[{"type":"text","text":"Inspecting the report"},{"type":"tool-call","id":"parent","name":"run_code","arguments":"{\"code\":\"return tools.read_file({path: 'report.py'})\"}"}]}}}
{"type":"tool/call","seq":1,"time":1790548591100,"data":{"callId":"parent","name":"run_code","arguments":"{\"code\":\"return tools.read_file({path: 'report.py'})\"}"}}
{"type":"tool/ptc-dispatch-start","seq":2,"time":1790548591200,"data":{"rootCallId":"parent","parentCallId":"parent","subCallId":"parent:ptc:1","name":"read_file","arguments":{"path":"report.py"}}}
{"type":"tool/ptc-dispatch","seq":3,"time":1790548591300,"data":{"rootCallId":"parent","parentCallId":"parent","subCallId":"parent:ptc:1","name":"read_file","arguments":{"path":"report.py"},"isError":true,"content":[{"type":"text","text":"file not found"}],"error":{"code":"NOT_FOUND"}}}
{"type":"tool/result","seq":4,"time":1790548591400,"surfaceOp":"append","data":{"message":{"role":"tool","source":{"kind":"tool","callId":"parent"},"toolCallId":"parent","isError":true,"content":[{"type":"text","text":"read failed"}]}}}
{"type":"tool/result","seq":5,"time":1790548591500,"surfaceOp":{"op":"replace","startSeq":4,"endSeq":4},"sourceEventSeqs":[4],"data":{"message":{"role":"tool","toolCallId":"parent","content":[{"type":"text","text":"earlier tool output summarized"}]}}}
{"type":"tool/ptc-dispatch","seq":6,"time":1790548591600,"data":{"rootCallId":"parent","parentCallId":"parent","subCallId":"orphan","name":"read_file","arguments":{"path":"notes.md"},"isError":false,"content":[{"type":"text","text":"saved notes"}]}}
`

func TestDeepSeekToolFormsAreQueryableWithoutDuplicateLogicalCalls(t *testing.T) {
	for _, version := range []int{3, 4} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			p := parseFixture(t, "deepseek", fmt.Sprintf("{\"type\":\"session\",\"version\":%d,\"id\":\"s\"}\n", version)+deepseekToolForms)
			if p.Coverage.Status != OK {
				t.Fatalf("parse: %+v", p.Coverage)
			}
			svc, ctx := testService(t), context.Background()
			first, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage)
			if err != nil || first.Stored != len(p.Records) {
				t.Fatalf("save: %+v %v", first, err)
			}
			calls, err := svc.Entries(ctx, PageOptions{RunID: "run", Kind: "tool_call"})
			if err != nil || len(calls.Entries) != 3 {
				t.Fatalf("logical calls: %+v %v", calls, err)
			}
			if calls.Entries[0].ToolCallID != "parent" || calls.Entries[0].Status != "proposed" || calls.Entries[0].Sequence != 3 {
				t.Fatalf("dispatch did not supersede proposal: %+v", calls.Entries[0])
			}
			if calls.Entries[1].ToolCallID != "parent:ptc:1" || calls.Entries[1].ToolName != "read_file" || calls.Entries[1].Sequence != 4 {
				t.Fatalf("sub-call/start time missing: %+v", calls.Entries[1])
			}
			if calls.Entries[2].Status != "completion_only" || len(calls.Entries[2].MissingFields) != 1 || calls.Entries[2].MissingFields[0] != "tool_start_time" {
				t.Fatalf("completion fabricated a start: %+v", calls.Entries[2])
			}
			results, err := svc.Entries(ctx, PageOptions{RunID: "run", Kind: "tool_result"})
			if err != nil || len(results.Entries) != 4 {
				t.Fatalf("results: %+v %v", results, err)
			}
			if results.Entries[0].Status != "error" || results.Entries[1].Status != "error" || results.Entries[2].Status != "context_replacement" || results.Entries[3].Status != "returned" {
				t.Fatalf("source outcomes lost: %+v", results.Entries)
			}
			for _, e := range results.Entries {
				page, err := provenance.ReadTextContentPage(svc.DB, "run", e.RawContent.Ref, 0, 65536)
				if err != nil || (e.ToolCallID == "parent:ptc:1" && !strings.Contains(page.Content, `"parentCallId":"parent"`)) ||
					(e.Status == "context_replacement" && !strings.Contains(page.Content, `"sourceEventSeqs":[4]`)) {
					t.Fatalf("lost raw provenance: %+v %v", page, err)
				}
			}
			revisions, err := svc.Entries(ctx, PageOptions{RunID: "run", Kind: "tool_call", IncludeRevisions: true})
			if err != nil || len(revisions.Entries) != 4 || revisions.Entries[0].Status != "model_proposal" {
				t.Fatalf("proposal history lost: %+v %v", revisions, err)
			}
			repeated, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage)
			if err != nil || repeated.Stored != 0 || repeated.Duplicates != len(p.Records) {
				t.Fatalf("repeat: %+v %v", repeated, err)
			}
		})
	}
}

func TestDeepSeekTypedFailuresAndConflictingResultIdentity(t *testing.T) {
	for _, tc := range []struct{ name, message, want string }{
		{"message-error", `{"toolCallId":"c","isError":true,"content":[]}`, "error"},
		{"legacy-block-error", `{"source":{"callId":"c"},"content":[{"type":"tool-result","isError":true,"content":[]}]}`, "error"},
		{"arbitrary-flag", `{"toolCallId":"c","content":[{"type":"text","text":"isError=true"},{"type":"json","isError":true}]}`, "returned"},
		{"unknown-outcome", `{"toolCallId":"c","content":[]}`, "returned"},
		{"conflict", `{"toolCallId":"c","source":{"callId":"other"},"content":[]}`, "tool_identity_conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := "{\"type\":\"session\",\"version\":4,\"id\":\"s\"}\n" +
				`{"type":"tool/result","seq":0,"data":{"message":` + tc.message + "}}\n"
			p := parseFixture(t, "deepseek", input)
			last := p.Records[len(p.Records)-1]
			if last.Status != tc.want || last.RawBody == nil {
				t.Fatalf("result: %+v", last)
			}
			if tc.name == "conflict" && (p.Coverage.Status != Partial || last.Kind != "session" || last.ToolCallID != "") {
				t.Fatalf("conflicting result assigned: %+v", p)
			}
		})
	}
}
