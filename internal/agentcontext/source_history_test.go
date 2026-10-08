package agentcontext

import (
	"context"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestClaudeSourceHistoryIsPositionScoped(t *testing.T) {
	ctx, s := context.Background(), testService(t)
	input := `{"type":"user","uuid":"u1","sessionId":"history","message":{"role":"user","content":"initial task"}}
{"type":"assistant","uuid":"a1","sessionId":"history","cwd":"/workspace/one","version":"1.0","message":{"role":"assistant","model":"model-one","content":"first response"}}
{"type":"assistant","uuid":"a2","sessionId":"history","cwd":"/workspace/two","version":"1.1","message":{"role":"assistant","model":"model-two","content":[{"type":"text","text":"second response"}]}}
`
	parsed, err := Parse(ctx, strings.NewReader(input), ParseOptions{Harness: "claude", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		result, err := s.Save(ctx, "history-run", parsed.Source, parsed.Records, parsed.Coverage)
		if err != nil || i == 1 && result.Stored != 0 {
			t.Fatalf("save %d: %+v %v", i, result, err)
		}
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "history-run", Kind: "message"})
	if err != nil || len(page.Entries) != 3 {
		t.Fatalf("messages: %+v %v", page, err)
	}
	for i, want := range []struct{ cwd, version string }{{"", ""}, {"/workspace/one", "1.0"}, {"/workspace/two", "1.1"}} {
		entry := page.Entries[i]
		if entry.Source.Workdir != want.cwd || entry.Source.ApplicationVersion != want.version {
			t.Errorf("line %d got cwd=%q version=%q, want %q/%q", entry.Sequence, entry.Source.Workdir, entry.Source.ApplicationVersion, want.cwd, want.version)
		}
	}
	configs, err := s.Entries(ctx, PageOptions{RunID: "history-run", Kind: "configuration"})
	if err != nil {
		t.Fatal(err)
	}
	var bodies []string
	for _, entry := range configs.Entries {
		body, err := provenance.ReadTextContentPage(s.DB, "history-run", entry.Content.Ref, 0, 4096)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body.Content)
	}
	for _, want := range []string{"model-one", "model-two", "/workspace/one", "/workspace/two", "1.0", "1.1"} {
		if !strings.Contains(strings.Join(bodies, "\n"), want) {
			t.Errorf("configuration history lost %q", want)
		}
	}
	updated, err := Parse(ctx, strings.NewReader(input+`{"type":"assistant","uuid":"a3","sessionId":"history","cwd":"/workspace/three","version":"1.2","message":{"role":"assistant","content":"later response"}}`+"\n"), ParseOptions{Harness: "claude", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Save(ctx, "history-run", updated.Source, updated.Records, updated.Coverage)
	if err != nil || result.Duplicates != len(parsed.Records) {
		t.Fatalf("later metadata must not revise previous entries: %+v %v", result, err)
	}
	history, err := s.Entries(ctx, PageOptions{RunID: "history-run", Kind: "message", IncludeRevisions: true})
	if err != nil || len(history.Entries) != 4 {
		t.Fatalf("message revision count: %+v %v", history, err)
	}
	for i := range page.Entries {
		if history.Entries[i].ID != page.Entries[i].ID {
			t.Fatal("an unchanged earlier message was replaced")
		}
	}
	verification, err := provenance.Verify(s.DB, "history-run")
	if err != nil || verification.ErrorCount != 0 {
		t.Fatalf("verification: %+v %v", verification, err)
	}
}

func TestCodexTurnWorkdirDoesNotRewriteEarlierRecords(t *testing.T) {
	ctx, s := context.Background(), testService(t)
	input := `{"type":"session_meta","payload":{"id":"history","cwd":"/workspace/start","cli_version":"1.0"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":"first"}}
{"type":"turn_context","payload":{"cwd":"/workspace/next","model":"model-one"}}
{"type":"response_item","payload":{"type":"message","role":"assistant","content":"second"}}
`
	parsed, err := Parse(ctx, strings.NewReader(input), ParseOptions{Harness: "codex", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(ctx, "codex-history", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "codex-history", Kind: "message"})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("messages: %+v %v", page, err)
	}
	if page.Entries[0].Source.Workdir != "/workspace/start" || page.Entries[1].Source.Workdir != "/workspace/next" {
		t.Fatalf("incorrect turn-scoped directories: %+v", page.Entries)
	}
}
