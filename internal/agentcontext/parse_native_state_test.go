package agentcontext

import (
	"context"
	"strings"
	"testing"
)

func TestClaudeNativeStateDoesNotFabricateConversationOrApproval(t *testing.T) {
	input := `{"type":"user","sessionId":"s","message":{"role":"user","content":"run tests"}}
{"type":"attachment","sessionId":"s","attachment":{"type":"prompt_snapshot","systemPrompt":"source prompt"}}
{"type":"atis-latch","sessionId":"s","atis":false}
{"type":"last-prompt","sessionId":"s","lastPrompt":"run tests"}
{"type":"cost-state","sessionId":"s","totalCostUSD":0.1,"hasUnknownModelCost":true}
{"type":"mode","sessionId":"s","mode":"dontAsk"}
`
	p := parseFixture(t, "claude", input)
	if p.Coverage.Status != OK || len(p.Records) != 6 {
		t.Fatalf("native state: %+v", p)
	}
	for _, r := range p.Records[1:5] {
		if r.Kind != "session" || r.ToolCallID != "" || r.RawBody == nil || r.Body == nil {
			t.Fatalf("state became an action or lost source: %+v", r)
		}
	}
	if p.Records[5].Kind != "configuration" || p.Records[5].Status != "permission_mode" {
		t.Fatalf("mode lost: %+v", p.Records[5])
	}
	resumed, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "claude", Binding: "explicit", AfterLine: 5})
	if err != nil || resumed.Records[4].ExecutionScope != PriorContext || resumed.Records[5].ExecutionScope != CurrentExecution {
		t.Fatalf("native state resume: %+v %v", resumed, err)
	}
	unknown := parseFixture(t, "claude", input+"{\"type\":\"future-native-format\",\"sessionId\":\"s\"}\n")
	if unknown.Coverage.Status != Partial {
		t.Fatal("unknown formats must remain visible")
	}
}

func TestCodexCompletedItemsPreserveSourceWithoutInventingToolCalls(t *testing.T) {
	input := `{"type":"session_meta","payload":{"id":"s","cli_version":"0.159.2"}}
{"type":"world_state","payload":{"full":true,"state":{"cwd":"/task"}}}
{"type":"token_usage_record","payload":{"thread_id":"s","usage":{"input_tokens":12}}}
{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"UserMessage","id":"u","content":[{"type":"text","text":"run tests"}]}}}
{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"AgentMessage","id":"a","content":[{"type":"Text","text":"running"}],"phase":"commentary"}}}
{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-native","command":["python3","-m","unittest"],"exit_code":1,"stderr":"test failed"}}}
{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"FileChange","id":"exec-patch","changes":{"report.py":{"type":"update","unified_diff":"@@ -1 +1 @@\n-old\n+new"}},"status":"completed"}}}
`
	p := parseFixture(t, "codex", input)
	if p.Coverage.Status != OK || len(p.Records) != 7 {
		t.Fatalf("completed items: %+v", p)
	}
	if p.Records[1].Kind != "configuration" || p.Records[2].Kind != "session" || p.Records[3].Role != "user" || p.Records[4].Role != "assistant" {
		t.Fatalf("native roles lost: %+v", p.Records)
	}
	exec := p.Records[5]
	if exec.Kind != "session" || exec.Status != "source_command_execution" || exec.ToolCallID != "" || !strings.Contains(*exec.Body, `"exit_code":1`) || exec.RawBody == nil {
		t.Fatalf("execution fabricated intent or discarded outcome: %+v", exec)
	}
	patch := p.Records[6]
	if patch.Kind != "session" || patch.Status != "source_file_change" || patch.ToolCallID != "" || !strings.Contains(*patch.Body, "unified_diff") || patch.RawBody == nil {
		t.Fatalf("patch report lost or turned into intent: %+v", patch)
	}
	unknown := parseFixture(t, "codex", input+"{\"type\":\"event_msg\",\"payload\":{\"type\":\"item_completed\",\"item\":{\"type\":\"FutureAction\"}}}\n")
	if unknown.Coverage.Status != Partial {
		t.Fatal("unknown completed items must remain visible")
	}
}

func TestCodexResumeSettingsRetainConfigurationHistory(t *testing.T) {
	input := `{"type":"session_meta","payload":{"id":"s","cwd":"/before"}}
{"type":"event_msg","payload":{"type":"thread_settings_applied","thread_settings":{"cwd":"/after","model":"example","approval_policy":"never","reasoning_effort":"medium","permission_profile":{"type":"managed","network":"restricted"}}}}
`
	p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 1})
	if err != nil || p.Coverage.Status != OK || p.Source.Workdir != "/after" || len(p.Records) != 2 {
		t.Fatalf("resume settings: %+v %v", p, err)
	}
	r := p.Records[1]
	if r.Kind != "configuration" || r.ExecutionScope != CurrentExecution || r.RawBody == nil || !strings.Contains(*r.Body, `"approval_policy":"never"`) {
		t.Fatalf("configuration lost: %+v", r)
	}
}
