package agentcontext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/klauspost/compress/zstd"
)

func TestResumeRetainsConfigurationWithoutExtendingPermission(t *testing.T) {
	input := `{"session_id":"s","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_use_id":"old","tool_input":{"command":"true"},"permission_mode":"default","_ts":"2026-09-28T00:00:00Z"}` + "\n"
	input += `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"new","tool_input":{"command":"false"},"_ts":"2026-09-28T01:00:00Z"}` + "\n"
	p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "claude", Binding: "explicit", AfterLine: 1})
	if err != nil || p.Coverage.Status != OK || p.Coverage.PriorContext == nil {
		t.Fatalf("parse: %+v %v", p, err)
	}
	if p.Coverage.StartedAt != "2026-09-28T01:00:00Z" || p.Coverage.PriorContext.EndedAt != "2026-09-28T00:00:00Z" {
		t.Fatalf("time ranges mixed: %+v", p.Coverage)
	}
	if !hasMissing(p.Coverage.MissingFields, "approval") || hasMissing(p.Coverage.PriorContext.MissingFields, "approval") {
		t.Fatalf("old approval filled current gap: %+v", p.Coverage)
	}
	s := testService(t)
	res, err := s.Save(context.Background(), "run", p.Source, p.Records, p.Coverage)
	if err != nil || *res.Coverage.Counts.Stored != 1 || *res.Coverage.PriorContext.Counts.Stored != 2 {
		t.Fatalf("save: %+v %v", res, err)
	}
}

func TestResumeEmptyCurrentRangeAndHistoricalParseFailure(t *testing.T) {
	for _, broken := range []bool{false, true} {
		input := `{"type":"session_meta","payload":{"id":"s"}}` + "\n"
		if broken {
			input += "bad-json\n"
		}
		p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: int64(strings.Count(input, "\n"))})
		if err != nil || len(p.Records) != 1 || p.Coverage.PriorContext == nil || *p.Coverage.Counts.Read != 0 || *p.Coverage.Counts.Failed != 0 {
			t.Fatalf("range: %+v %v", p, err)
		}
		if broken {
			if p.Coverage.Status != Partial || *p.Coverage.PriorContext.Counts.Failed != 1 || p.Coverage.Issues[0].Scope != PriorContext {
				t.Fatalf("historical failure hidden: %+v", p.Coverage)
			}
		} else if p.Coverage.Status != Empty {
			t.Fatalf("old context reported as new activity: %+v", p.Coverage)
		}
	}
}

func TestDeepSeekCompressedResumeKeepsPriorContextAndLateResult(t *testing.T) {
	for _, version := range []int{3, 4} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			ctx := context.Background()
			root, cwd, now := t.TempDir(), t.TempDir(), time.Now().UTC()
			path := filepath.Join(root, fmt.Sprintf("session.v%d.jsonl.zstd", version))
			header := fmt.Sprintf(`{"type":"session","version":%d,"id":"resumed","cwd":%q,"createdAt":%d}`+"\n", version, cwd, now.Add(-time.Hour).UnixMilli())
			prefix := header + `{"type":"approval/decided","seq":0,"data":{"callId":"old","decision":"allow"}}
{"type":"model/selection","seq":1,"data":{"model":"old-model"}}
{"type":"tool/call","seq":2,"data":{"callId":"old","name":"bash","arguments":"{\"command\":\"old\"}"}}
`
			tail := `{"type":"user/message","seq":3,"data":{"role":"user","content":[{"type":"text","text":"continue tests"}]}}
{"type":"tool/result","seq":4,"data":{"message":{"role":"tool","toolCallId":"old","isError":true,"content":[{"type":"text","text":"late error"}]}}}
{"type":"model/selection","seq":5,"data":{"model":"new-model"}}
{"type":"tool/call","seq":6,"data":{"callId":"new","name":"bash","arguments":"{\"command\":\"new\"}"}}
{"type":"tool/result","seq":7,"data":{"message":{"role":"tool","toolCallId":"new","content":[{"type":"text","text":"done"}]}}}
`
			encoder, err := zstd.NewWriter(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer encoder.Close()
			initial := encoder.EncodeAll([]byte(prefix), nil)
			write := func(data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(initial)
			discovery := DiscoverOptions{Harness: "deepseek", Root: root, Workdir: cwd, Snapshot: true}
			before := discoverTest(t, discovery)
			write(append(initial, encoder.EncodeAll([]byte(tail), nil)...))
			selected := SelectSources(ctx, before, discoverTest(t, discovery), SelectOptions{
				SessionID: "resumed", Workdir: cwd, StartedAt: now, EndedAt: now.Add(time.Minute)})
			if selected.Status != OK || len(selected.Sources) != 1 || selected.Sources[0].AfterLine != 4 {
				t.Fatalf("selection: %+v", selected)
			}
			s := testService(t)
			opts := selected.Sources[0].ParseOptions("deepseek")
			result, err := s.ImportFile(ctx, "run", opts)
			if err != nil || result.Stored != 9 || result.Coverage.Status != OK || result.Coverage.PriorContext == nil {
				t.Fatalf("import: %+v %v", result, err)
			}
			if *result.Coverage.Counts.Stored != 5 || *result.Coverage.PriorContext.Counts.Stored != 4 || !hasMissing(result.Coverage.MissingFields, "approval") {
				t.Fatalf("history filled current coverage: %+v", result.Coverage)
			}
			page, err := s.Entries(ctx, PageOptions{RunID: "run"})
			if err != nil || len(page.Entries) != 9 {
				t.Fatalf("entries: %+v %v", page, err)
			}
			for i, entry := range page.Entries {
				want := CurrentExecution
				if i < 4 {
					want = PriorContext
				}
				if entry.ExecutionScope != want || entry.RawContent.Ref == "" {
					t.Fatalf("entry range/raw lost: %+v", entry)
				}
			}
			late := page.Entries[5]
			body, err := provenance.ReadTextContentPage(s.DB, "run", late.Content.Ref, 0, 4096)
			if err != nil || late.Kind != "tool_result" || late.ToolName != "bash" || late.Status != "error" || !strings.Contains(body.Content, "late error") {
				t.Fatalf("late result: %+v %+v %v", late, body, err)
			}
			repeated, err := s.ImportFile(ctx, "run", opts)
			if err != nil || repeated.Stored != 0 || repeated.Duplicates != 9 || *repeated.Coverage.Counts.Duplicates != 5 || *repeated.Coverage.PriorContext.Counts.Duplicates != 4 {
				t.Fatalf("repeat: %+v %v", repeated, err)
			}
		})
	}
}

func hasMissing(fields []string, want string) bool {
	for _, field := range fields {
		if field == want {
			return true
		}
	}
	return false
}
