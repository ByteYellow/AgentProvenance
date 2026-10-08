package agentcontext

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestCodexEventMessagesAreNotAssumedToHaveCanonicalCopies(t *testing.T) {
	ctx := context.Background()
	prefix := `{"type":"session_meta","payload":{"id":"events-only"}}
{"type":"event_msg","timestamp":"2026-09-28T12:00:00Z","payload":{"type":"user_message","message":"repeat this task","images":["source-image-ref"]}}
{"type":"event_msg","payload":{"type":"agent_message","message":"observed answer"}}
{"type":"event_msg","payload":{"type":"user_message","message":"repeat this task"}}
{"type":"event_msg","payload":{"type":"agent_reasoning","text":"source-provided rationale"}}
{"type":"event_msg","payload":{"type":"agent_reasoning_raw_content","text":"source-provided detail"}}
`
	p := parseFixture(t, "codex", prefix)
	if p.Coverage.Status != OK || len(p.Records) != 6 || hasMissing(p.Coverage.MissingFields, "task") {
		t.Fatalf("event-only content lost: %+v", p)
	}
	for i, r := range p.Records[1:] {
		if r.Kind != "message" || r.Body == nil || r.RawBody == nil || r.Sequence != int64(i+2) {
			t.Fatalf("source message %d: %+v", i, r)
		}
	}
	if p.Records[1].Role != "user" || p.Records[2].Role != "assistant" || p.Records[1].Status != "source_message_event" || p.Records[4].Status != "source_reasoning_event" {
		t.Fatalf("source form or role lost: %+v", p.Records)
	}
	if p.Records[1].Key == p.Records[3].Key || !strings.Contains(*p.Records[1].RawBody, "source-image-ref") {
		t.Fatal("equal text collapsed separate source events or dropped source metadata")
	}
	s := testService(t)
	first, err := s.Save(ctx, "run", p.Source, p.Records, p.Coverage)
	if err != nil || first.Stored != 6 {
		t.Fatalf("save: %+v %v", first, err)
	}
	// A late canonical representation is additional evidence, not a guessed
	// replacement for every previous event with the same text.
	tail := `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"repeat this task"}]}}` + "\n"
	late := parseFixture(t, "codex", prefix+tail)
	saved, err := s.Save(ctx, "run", late.Source, late.Records, late.Coverage)
	if err != nil || saved.Stored != 1 || saved.Duplicates != 6 {
		t.Fatalf("late representation: %+v %v", saved, err)
	}
	repeated, err := s.Save(ctx, "run", late.Source, late.Records, late.Coverage)
	if err != nil || repeated.Stored != 0 || repeated.Duplicates != 7 {
		t.Fatalf("reimport: %+v %v", repeated, err)
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "run", Kind: "message"})
	if err != nil || len(page.Entries) != 6 {
		t.Fatalf("message records: %+v %v", page, err)
	}
	for i, entry := range page.Entries {
		body, err := provenance.ReadTextContentPage(s.DB, "run", entry.Content.Ref, 0, 4096)
		if err != nil || body.Content != *late.Records[i+1].Body {
			t.Fatalf("source content changed: %+v %v", body, err)
		}
	}
	resumed, err := Parse(ctx, strings.NewReader(prefix+tail), ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 6})
	if err != nil || resumed.Records[1].ExecutionScope != PriorContext || resumed.Records[6].ExecutionScope != CurrentExecution || *resumed.Coverage.Counts.Read != 1 {
		t.Fatalf("message resume range: %+v %v", resumed, err)
	}
}

func TestCodexToolErrorsUseTypedEnvelopesNotOutputWords(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		want         string
	}{
		{"flag", `"is_error":true,"output":"detail"`, "error"},
		{"camel-flag", `"isError":true,"output":"detail"`, "error"},
		{"exit-code", `"exit_code":2,"output":"detail"`, "error"},
		{"signal-exit", `"exit_code":-9,"output":"detail"`, "error"},
		{"status", `"status":"failed","output":"detail"`, "error"},
		{"conflict", `"isError":false,"status":"failed","output":"detail"`, "error"},
		{"mcp", `"output":{"content":[{"type":"text","text":"detail"}],"isError":true}`, "error"},
		{"shell", `"output":{"output":"detail","metadata":{"exit_code":3}}`, "error"},
		{"encoded-shell", `"output":"{\"output\":\"detail\",\"metadata\":{\"exit_code\":3}}"`, "error"},
		{"no-status", `"output":"FAILED error exit_code=9"`, "returned"},
		{"json-data", `"output":{"status":"failed","exit_code":9}`, "returned"},
		{"nested-data", `"output":{"output":"detail","metadata":{"result":{"exit_code":9}}}`, "returned"},
		{"string-exit", `"exit_code":"2","output":"detail"`, "returned"},
		{"boolean-exit", `"exit_code":true,"output":"detail"`, "returned"},
		{"null-exit", `"exit_code":null,"output":"detail"`, "returned"},
		{"zero", `"exit_code":0,"output":"detail"`, "returned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `{"type":"session_meta","payload":{"id":"s"}}` + "\n" +
				`{"type":"response_item","payload":{"type":"function_call_output","call_id":"call",` + tc.fields + "}}\n"
			p := parseFixture(t, "codex", input)
			if p.Coverage.Status != OK || len(p.Records) != 2 || p.Records[1].Status != tc.want {
				t.Fatalf("outcome: %+v", p)
			}
			if p.Records[1].RawBody == nil || !json.Valid([]byte(*p.Records[1].RawBody)) || p.Records[1].Body == nil {
				t.Fatal("outcome normalization discarded its source")
			}
		})
	}
}
