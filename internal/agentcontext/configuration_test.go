package agentcontext

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestConfigurationCoverageDistinguishesMissingNullEmptyAndFalse(t *testing.T) {
	input := `{"type":"session_meta","payload":{"id":"config","cwd":"/task","cli_version":"1.0"}}
{"type":"turn_context","payload":{"model":null,"approval_policy":"on-request","sandbox_policy":{"type":"workspace-write","network_access":false,"writable_roots":[]},"mcp_servers":{},"tools":[],"plugins":null}}
{"type":"response_item","payload":{"type":"message","role":"user","content":"run tests"}}
`
	p := parseFixture(t, "codex", input)
	if p.Coverage.Status != OK || p.Records[0].Kind != "configuration" || p.Records[0].Status != "session_metadata" {
		t.Fatalf("metadata snapshot: %+v", p)
	}
	for _, field := range []string{"workdir", "application_version", "model", "approval_policy", "sandbox_policy", "directory_restrictions", "network_restrictions", "mcp_servers", "tools", "plugins"} {
		if hasMissing(p.Coverage.MissingFields, "configuration."+field) {
			t.Errorf("present source field reported absent: %s", field)
		}
	}
	for _, field := range []string{"configuration.skills", "configuration.permission_mode", "configuration.provider", "approval", "approval_decision"} {
		if !hasMissing(p.Coverage.MissingFields, field) {
			t.Errorf("absent field not reported: %s", field)
		}
	}
	if hasMissing(p.Coverage.MissingFields, "task") {
		t.Fatal("user task not recognized")
	}
	s := testService(t)
	if _, err := s.Save(context.Background(), "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := s.Entries(context.Background(), PageOptions{RunID: "run", Group: "configuration"})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("query: %+v %v", page, err)
	}
	body, err := provenance.ReadTextContentPage(s.DB, "run", page.Entries[1].Content.Ref, 0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(body.Content), &saved); err != nil {
		t.Fatal(err)
	}
	if model, exists := saved["model"]; !exists || model != nil {
		t.Fatal("explicit null lost")
	}
	if len(saved["tools"].([]any)) != 0 || saved["sandbox_policy"].(map[string]any)["network_access"] != false {
		t.Fatal("empty catalog or false permission lost")
	}
	if _, exists := saved["skills"]; exists {
		t.Fatal("missing source field replaced by a default")
	}
}

func TestConfigurationCoverageDoesNotTreatMessagesAsPolicy(t *testing.T) {
	input := `{"type":"user","sessionId":"s","message":{"role":"user","content":{"model":"claim","permission_mode":"allow","mcp_servers":[]}}}` + "\n"
	p := parseFixture(t, "claude", input)
	for _, field := range []string{"configuration", "configuration.model", "configuration.permission_mode", "configuration.mcp_servers", "approval_decision"} {
		if !hasMissing(p.Coverage.MissingFields, field) {
			t.Errorf("message promoted to configuration: %s", field)
		}
	}
	request := parseFixture(t, "claude", `{"hook_event_name":"PermissionRequest","session_id":"s","tool_use_id":"c","tool_name":"Bash","permission_mode":"default","tool_input":{"command":"true"}}`+"\n")
	if hasMissing(request.Coverage.MissingFields, "approval") || !hasMissing(request.Coverage.MissingFields, "approval_decision") {
		t.Fatal("permission request became approval decision")
	}
}

func TestRecordedConfigurationChangesDoNotProveCompleteHistory(t *testing.T) {
	input := `{"type":"session_meta","payload":{"id":"config"}}
{"type":"turn_context","payload":{"approval_policy":"on-request"}}
{"type":"turn_context","payload":{"approval_policy":"never"}}
`
	p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 2})
	if err != nil || p.Coverage.Status != OK || p.Coverage.PriorContext == nil {
		t.Fatalf("parse configuration history: %+v %v", p.Coverage, err)
	}
	const gap = "configuration.change_history_completeness"
	if !hasMissing(p.Coverage.MissingFields, gap) || !hasMissing(p.Coverage.PriorContext.MissingFields, gap) {
		t.Fatal("recorded changes were treated as complete configuration history")
	}
	s := testService(t)
	if _, err := s.Save(context.Background(), "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	query, err := s.Overview(context.Background(), "run")
	if err != nil || len(query.Coverage) != 1 || !hasMissing(query.Coverage[0].MissingFields, gap) {
		t.Fatalf("coverage query lost configuration history limitation: %+v %v", query, err)
	}
}

func TestClaudeSourceConfigurationHistoryIsComparable(t *testing.T) {
	input := `{"type":"system","subtype":"init","session_id":"s","timestamp":"2026-09-28T01:00:00Z","cwd":"/task","claude_code_version":"1.0","permissionMode":"default","model":"first","mcp_servers":[{"name":"docs","version":"1","tools":[{"name":"search","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}],"skills":[],"plugins":null}
{"type":"permission-mode","sessionId":"s","timestamp":"2026-09-28T01:01:00Z","mode":"plan"}
{"type":"permission-mode","sessionId":"s","timestamp":"2026-09-28T01:02:00Z","mode":"default"}
{"type":"system","subtype":"init","session_id":"s","timestamp":"2026-09-28T01:03:00Z","cwd":"/task","claude_code_version":"1.1","permissionMode":"default","model":"second","mcp_servers":[{"name":"docs","version":"2","tools":[{"name":"search","inputSchema":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer"}}}}]}]}
`
	p := parseFixture(t, "claude", input)
	if p.Coverage.Status != OK {
		t.Fatalf("source config: %+v", p.Coverage)
	}
	s, ctx := testService(t), context.Background()
	if _, err := s.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "run", Kind: "configuration"})
	if err != nil {
		t.Fatal(err)
	}
	var init, permissions []Entry
	for _, entry := range page.Entries {
		switch entry.Status {
		case "initialization":
			init = append(init, entry)
		case "permission_mode":
			permissions = append(permissions, entry)
		}
	}
	if len(init) != 2 || len(permissions) != 2 || init[0].Source.ApplicationVersion != "1.0" || init[1].Source.ApplicationVersion != "1.1" {
		t.Fatalf("configuration versions collapsed: %+v", page.Entries)
	}
	diff, err := s.CompareSnapshots(ctx, "run", init[0].ID, "", init[1].ID)
	if err != nil || diff.Status != "different" {
		t.Fatalf("compare: %+v %v", diff, err)
	}
	changes := map[string]SnapshotChange{}
	for _, change := range diff.Changes {
		changes[change.Path] = change
	}
	for _, path := range []string{"/content/model", "/content/claude_code_version", "/content/mcp_servers/0/version", "/content/mcp_servers/0/tools/0/inputSchema/properties/limit"} {
		if _, exists := changes[path]; !exists {
			t.Errorf("source configuration change not shown: %s", path)
		}
	}
	if change := changes["/content/plugins"]; !change.Before.Present || change.Before.Preview != "null" || change.After.Present {
		t.Fatalf("absent/null conflated: %+v", change)
	}
	if change := changes["/content/skills"]; !change.Before.Present || change.Before.Preview != "[]" || change.After.Present {
		t.Fatalf("absent/empty conflated: %+v", change)
	}
	diff, err = s.CompareSnapshots(ctx, "run", permissions[0].ID, "", permissions[1].ID)
	if err != nil || diff.Status != "different" {
		t.Fatalf("permission history: %+v %v", diff, err)
	}
}

func TestDeepSeekConfigurationCoverageAndApprovalDecision(t *testing.T) {
	header := `{"type":"session","version":4,"id":"s","cwd":"/task"}` + "\n"
	policy := `{"type":"permission/preset","seq":0,"data":{"preset":"default"}}
{"type":"sandbox/mode","seq":1,"data":{"mode":"workspace-write"}}
{"type":"approval/policy","seq":2,"data":{"policy":"on-request"}}
{"type":"plan/mode","seq":3,"data":{"active":false}}
{"type":"request/header","seq":4,"data":{"header":{"config":{"model":"first","provider":"deepseek-official"},"tools":[{"name":"read","parameters":{"type":"object"}}]}}}
{"type":"approval/asked","seq":5,"data":{"callId":"call","request":"execute"}}
`
	p := parseFixture(t, "deepseek", header+policy)
	if p.Coverage.Status != OK || p.Records[4].Kind != "configuration" || p.Records[4].Status != "plan/mode" {
		t.Fatalf("plan snapshot: %+v", p)
	}
	for _, field := range []string{"model", "provider", "workdir", "permission_mode", "sandbox_policy", "approval_policy", "tools"} {
		if hasMissing(p.Coverage.MissingFields, "configuration."+field) {
			t.Errorf("known configuration field missing: %s", field)
		}
	}
	for _, field := range []string{"application_version", "network_restrictions", "directory_restrictions", "mcp_servers", "skills", "plugins"} {
		if !hasMissing(p.Coverage.MissingFields, "configuration."+field) {
			t.Errorf("configuration inferred from mode: %s", field)
		}
	}
	if !hasMissing(p.Coverage.MissingFields, "approval_decision") {
		t.Fatal("policy/request substituted for decision")
	}
	decision := `{"type":"approval/decided","seq":6,"data":{"callId":"call","decision":"deny"}}` + "\n"
	current, err := Parse(context.Background(), strings.NewReader(header+policy+decision), ParseOptions{Harness: "deepseek", Binding: "explicit", AfterLine: 7})
	if err != nil || hasMissing(current.Coverage.MissingFields, "approval_decision") || !hasMissing(current.Coverage.PriorContext.MissingFields, "approval_decision") || !hasMissing(current.Coverage.MissingFields, "configuration.model") {
		t.Fatalf("range-specific decision/configuration: %+v %v", current.Coverage, err)
	}
}
