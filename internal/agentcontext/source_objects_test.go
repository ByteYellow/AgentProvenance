package agentcontext

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestClaudeCompoundLinePreservesRecordsPositionsAndResume(t *testing.T) {
	first := `{"type":"user","sessionId":"s","cwd":"/task","message":{"role":"user","content":"first"}}`
	second := `{"type":"user","sessionId":"s","message":{"role":"user","content":"second"}}`
	third := `{"type":"assistant","sessionId":"s","message":{"role":"assistant","content":"third"}}`
	input := "\x00 " + first + "\x00\t" + second + third + "\x00\n"
	p := parseFixture(t, "claude", input)
	if p.Coverage.Status != OK || *p.Coverage.Counts.Read != 1 || *p.Coverage.Counts.Parsed != 1 || len(p.Records) != 4 {
		t.Fatalf("compound: %+v", p)
	}
	for i, raw := range []string{first, second, third} {
		r := p.Records[i+1]
		if r.Sequence != 1 || r.SourceOrdinal != int64(i+2) || *r.RawBody != raw || (i > 0 && !strings.Contains(r.Key, fmt.Sprintf(":object:%d", i+1))) {
			t.Fatalf("source position/body lost: %+v", r)
		}
	}
	svc, ctx := testService(t), context.Background()
	if _, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	if result, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil || result.Stored != 0 || result.Duplicates != 4 {
		t.Fatalf("repeat: %+v %v", result, err)
	}
	page, err := svc.Entries(ctx, PageOptions{RunID: "run", Kind: "message"})
	if err != nil || len(page.Entries) != 3 {
		t.Fatalf("same-line fallback identities collapsed: %+v %v", page, err)
	}
	cursor := ""
	for i, want := range []string{"first", "second", "third"} {
		one, err := svc.Entries(ctx, PageOptions{RunID: "run", Kind: "message", Limit: 1, Cursor: cursor})
		if err != nil || len(one.Entries) != 1 || one.Entries[0].ID != page.Entries[i].ID {
			t.Fatalf("source order changed across pages: %+v %v", one, err)
		}
		body, err := provenance.ReadTextContentPage(svc.DB, "run", one.Entries[0].Content.Ref, 0, 100)
		if err != nil || body.Content != want || one.HasMore != (i < 2) {
			t.Fatalf("same-line order: %+v %v", body, err)
		}
		cursor = one.NextCursor
	}
	path := filepath.Join(t.TempDir(), "session.jsonl")
	writeSource(t, path, input)
	before := discoverTest(t, DiscoverOptions{Harness: "claude", Root: path, Workdir: "/task", Snapshot: true})
	if !before.Complete || len(before.Candidates) != 1 || before.Candidates[0].Cursor.Lines != 1 {
		t.Fatalf("compound discovery: %+v", before)
	}
	writeSource(t, path, input+`{"type":"user","sessionId":"s","message":{"content":"new"}}`+"\n")
	after := discoverTest(t, DiscoverOptions{Harness: "claude", Root: path})
	selected := SelectSources(ctx, before, after, SelectOptions{Path: path, SessionID: "s", StartedAt: time.Now(), EndedAt: time.Now()})
	if selected.Status != OK || len(selected.Sources) != 1 || selected.Sources[0].AfterLine != 1 {
		t.Fatalf("physical checkpoint changed: %+v", selected)
	}
	result, err := svc.ImportFile(ctx, "resumed", selected.Sources[0].ParseOptions("claude"))
	if err != nil || result.Stored != 5 || result.Coverage.PriorContext == nil || *result.Coverage.PriorContext.Counts.Stored != 4 || *result.Coverage.Counts.Stored != 1 {
		t.Fatalf("resume: %+v %v", result, err)
	}
}

func TestClaudeSameLineRevisionUsesSourceOrderBeforeImportTime(t *testing.T) {
	input := `{"type":"user","uuid":"m","sessionId":"s","message":{"content":"before"}}` +
		`{"type":"user","uuid":"m","sessionId":"s","message":{"content":"after"}}` + "\n"
	p := parseFixture(t, "claude", input)
	svc, ctx := testService(t), context.Background()
	// Save in reverse order to ensure storage time cannot replace source order.
	for i := len(p.Records) - 1; i >= 0; i-- {
		if _, err := svc.Save(ctx, "run", p.Source, p.Records[i:i+1], p.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.Entries(ctx, PageOptions{RunID: "run"})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].SourceOrdinal != 2 {
		t.Fatalf("older source object hid later revision: %+v %v", page, err)
	}
	body, err := provenance.ReadTextContentPage(svc.DB, "run", page.Entries[0].Content.Ref, 0, 100)
	if err != nil || body.Content != "after" {
		t.Fatalf("revision body: %+v %v", body, err)
	}
}

func TestClaudeCompoundLineNeverRepairsMessageBytesOrCrossesLines(t *testing.T) {
	valid := `{"type":"user","sessionId":"s","message":{"content":"keep"}}`
	for _, tc := range []struct {
		name, input string
		records     int
		code        string
	}{
		{"pending-tail", valid + `{"type":`, 1, "incomplete_tail"},
		{"broken-suffix", valid + "not-json\n" + valid + "\n", 2, "malformed_json"},
		{"embedded-nul", strings.Replace(valid, "keep", "ke\x00ep", 1) + "\n" + valid + "\n", 1, "malformed_json"},
		{"physical-lines", `{"type":"user",` + "\n" + `"sessionId":"s"}` + "\n" + valid + "\n", 1, "malformed_json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := parseFixture(t, "claude", tc.input)
			if p.Coverage.Status != Partial || len(p.Records) != tc.records {
				t.Fatalf("repaired or discarded valid data: %+v", p)
			}
			found := false
			for _, issue := range p.Coverage.Issues {
				found = found || issue.Code == tc.code
			}
			if !found {
				t.Fatalf("missing reason: %+v", p.Coverage)
			}
		})
	}
	escaped := parseFixture(t, "claude", strings.Replace(valid, "keep", `ke\u0000ep`, 1)+"\n")
	if escaped.Coverage.Status != OK || *escaped.Records[0].Body != "ke\x00ep" {
		t.Fatal("valid escaped character altered")
	}
	conflict := parseFixture(t, "claude", valid+strings.Replace(valid, `"s"`, `"other"`, 1)+"\n")
	if conflict.Coverage.Status != Ambiguous || len(conflict.Records) != 0 {
		t.Fatal("cross-session same-line content accepted")
	}
	strict := parseFixture(t, "codex", `{"type":"session_meta","payload":{"id":"s"}}`+valid+"\n")
	if len(strict.Records) != 0 || *strict.Coverage.Counts.Failed != 1 {
		t.Fatal("compound tolerance silently applied to other formats")
	}
}

func TestClaudeCompoundLineEnforcesRecordBudget(t *testing.T) {
	input := strings.Repeat(`{"type":"user","sessionId":"s","message":{"content":"x"}}`, MaxRecords+2) + "\n"
	p := parseFixture(t, "claude", input)
	if p.Coverage.Status != Partial || len(p.Records) != MaxRecords || *p.Coverage.Counts.Truncated == 0 {
		t.Fatalf("same-line budget bypass: records=%d coverage=%+v", len(p.Records), p.Coverage)
	}
}
