package agentcontext

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestHookRetentionBeforeStorage(t *testing.T) {
	ctx := context.Background()
	const source = `{"hook_event_name":"PostToolUseFailure","session_id":"s","agent_id":"worker","tool_use_id":"call","tool_name":"Bash","_ts":"2026-10-18T10:00:00Z","error":"EXCLUDED-RESULT","tool_input":{"command":"DUPLICATE-INPUT"},"permission_mode":"PRIVATE-CONFIG","unrelated":"OPAQUE-STATE","transcript_path":"/sessions/main.jsonl"}`
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			policy, _ := NewCapturePolicy(preset, nil)
			data, err := RetainHookEvent([]byte(source), policy)
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{"EXCLUDED-RESULT", "DUPLICATE-INPUT", "PRIVATE-CONFIG", "OPAQUE-STATE"} {
				if strings.Contains(string(data), marker) != (preset == "detailed") {
					t.Fatalf("unexpected hook retention for %s", marker)
				}
			}
			if !strings.Contains(string(data), "/sessions/main.jsonl") {
				t.Fatal("transcript selection anchor removed")
			}
			parsed, err := Parse(ctx, strings.NewReader(string(data)+"\n"), ParseOptions{Harness: "claude", Binding: "exact"})
			if err != nil || parsed.Coverage.Status != OK || len(parsed.Records) != 2 {
				t.Fatalf("parse: %+v %v", parsed.Coverage, err)
			}
			s := testService(t)
			s.CapturePolicy = &policy
			saved, err := s.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage)
			if err != nil || saved.Coverage.Status != OK {
				t.Fatalf("save: %+v %v", saved, err)
			}
			page, err := s.Entries(ctx, PageOptions{RunID: "run", Kind: "tool_result"})
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("tool result missing: %+v %v", page, err)
			}
			e := page.Entries[0]
			if e.Status != "error" || e.ToolCallID != "call" || e.AgentID != "worker" {
				t.Fatalf("core outcome changed: %+v", e)
			}
			if preset == "basic" {
				if e.Content.State != "omitted" || e.Content.Ref != "" || e.Content.Bytes == nil || *e.Content.Bytes != int64(len("EXCLUDED-RESULT")) || e.RawContent.DigestScope != "hook_record" {
					t.Fatalf("omitted bytes lost their descriptor: %+v", e)
				}
				configs, err := s.Entries(ctx, PageOptions{RunID: "run", Kind: "configuration"})
				if err != nil || len(configs.Entries) != 1 || configs.Entries[0].Content.Reason != "capture_policy" {
					t.Fatalf("configuration omission missing: %+v %v", configs, err)
				}
				wrong := testService(t)
				if _, err := wrong.Save(ctx, "other", parsed.Source, parsed.Records, parsed.Coverage); err == nil {
					t.Fatal("basic sidecar silently imported as detailed source")
				}
			}
		})
	}
}

func TestHookPrewriteRedactionSurvivesBodyReading(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		s := testService(t)
		policy, _ := NewCapturePolicy(preset, nil)
		s.CapturePolicy = &policy
		data, err := RetainHookEvent([]byte(`{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"t","tool_name":"Bash","tool_input":{"command":"echo \u0073k-encoded-12345678901234567890"}}`), policy)
		if err != nil || !strings.Contains(string(data), "***REDACTED***") || strings.Contains(string(data), "encoded-12345678901234567890") {
			t.Fatalf("nested/escaped token not masked before logging: %s %v", data, err)
		}
		parsed, err := Parse(context.Background(), strings.NewReader(string(data)+"\n"), ParseOptions{Harness: "claude", Binding: "exact"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Save(context.Background(), "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
		entries, err := s.Entries(context.Background(), PageOptions{RunID: "run", Kind: "tool_call"})
		if err != nil || len(entries.Entries) != 1 {
			t.Fatalf("entries: %+v %v", entries, err)
		}
		e := entries.Entries[0]
		body, err := provenance.ReadTextContentPage(s.DB, "run", e.Content.Ref, 0, 4096)
		if err != nil || !e.Content.Redacted || !body.Redacted || !strings.Contains(body.Content, "***REDACTED***") {
			t.Fatalf("prewrite marker lost in stored body: %+v %+v %v", e.Content, body, err)
		}
		if preset == "detailed" {
			raw, err := provenance.ReadTextContentPage(s.DB, "run", e.RawContent.Ref, 0, 4096)
			if err != nil || !raw.Redacted || !e.RawContent.Redacted {
				t.Fatal("raw redaction marker lost")
			}
		}
	}
}

func TestHookRetentionCoreFieldsOverridesAndRedaction(t *testing.T) {
	for _, event := range []string{"PreToolUse", "UserPromptSubmit", "SubagentStop", "PermissionRequest", "PostToolUse"} {
		for _, preset := range []string{"basic", "detailed"} {
			for _, enabled := range []bool{false, true} {
				policy, _ := NewCapturePolicy(preset, &enabled)
				data, err := RetainHookEvent([]byte(`{"hook_event_name":"`+event+`","session_id":"s","tool_use_id":"t","tool_name":"Bash","tool_input":{"command":"true"},"prompt":"task","tool_response":"RESULT-MARKER","last_assistant_message":"I refuse","agent_id":"child","parent_agent_id":"parent","agent_transcript_path":"child.jsonl","api_key":"sk-testing-1234567890123456789"}`), policy)
				if err != nil || !json.Valid(data) {
					t.Fatalf("filter: %v", err)
				}
				if strings.Contains(string(data), "sk-testing-") {
					t.Fatal("hook sidecar retained credential")
				}
				if policy.SourceRecords {
					continue
				}
				top := obj(data)
				if text(top, "agent_id") != "child" || text(top, "parent_agent_id") != "parent" || text(top, "agent_transcript_path") != "child.jsonl" {
					t.Fatal("child identity or native source anchor dropped")
				}
				if event == "PreToolUse" && len(top["tool_input"]) == 0 || event == "UserPromptSubmit" && text(top, "prompt") != "task" || event == "SubagentStop" && text(top, "last_assistant_message") != "I refuse" {
					t.Fatalf("core %s data lost", event)
				}
				if strings.Contains(string(data), "RESULT-MARKER") != (enabled && event == "PostToolUse") {
					t.Fatalf("result retention not scoped to the result event: %s %s %t", event, preset, enabled)
				}
			}
		}
	}
}

func TestHookRetentionMetadataValidationAndMissingValues(t *testing.T) {
	policy, _ := NewCapturePolicy("basic", nil)
	data, err := RetainHookEvent([]byte(`{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"t","_agentprov_capture":{"malicious":"value"}}`), policy)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := parseHookCapture(obj(data))
	if err != nil || meta.ToolResult != nil {
		t.Fatalf("absent result must remain unknown: %+v %v", meta, err)
	}
	for _, input := range []string{"null", "[]", "{broken}", `{"message":"not a hook"}`} {
		if _, err := RetainHookEvent([]byte(input), policy); err == nil {
			t.Fatalf("accepted invalid hook %q", input)
		}
	}
	meta.Raw.Ref = "fake-original"
	top := obj(data)
	top["_agentprov_capture"], _ = json.Marshal(meta)
	p, err := Parse(context.Background(), strings.NewReader(string(whole(top))+"\n"), ParseOptions{Harness: "claude", SessionID: "s"})
	if err != nil || p.Coverage.Status != Failed || len(p.Records) != 0 {
		t.Fatalf("invalid retention descriptor accepted: %+v %v", p, err)
	}
	for _, code := range []string{"hook_input_limit", "hook_log_limit", "hook_input_invalid", "hook_input_read_failed"} {
		input := `{"hook_event_name":"SessionStart","session_id":"s"}` + "\n" + string(HookCaptureDiagnostic(code)) + "\n"
		p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "claude"})
		if err != nil || p.Coverage.Status != Partial || len(p.Records) != 1 || len(p.Coverage.Issues) != 1 || p.Coverage.Issues[0].Code != code {
			t.Fatalf("diagnostic disappeared: %+v %v", p.Coverage, err)
		}
	}
}
