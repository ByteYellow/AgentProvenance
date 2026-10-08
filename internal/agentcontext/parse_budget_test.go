package agentcontext

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func hasBudgetIssue(c Coverage, code string) bool {
	for _, issue := range c.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func TestSharedInputBudgetIsChargedAcrossSources(t *testing.T) {
	input := `{"type":"user","sessionId":"s","message":{"content":"task"}}` + "\n"
	budget := &ParseBudget{InputBytes: int64(len(input)) + 10, Records: 100}
	parse := func(input string) Parsed {
		t.Helper()
		p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "claude", SessionID: "s", Budget: budget})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := parse(input)
	if first.Coverage.Status != OK || len(first.Records) != 1 || budget.InputBytes != 10 || budget.Records != 99 {
		t.Fatalf("first source: %+v budget=%+v", first, budget)
	}
	second := parse(input)
	if second.Coverage.Status != Partial || len(second.Records) != 0 || budget.InputBytes != 0 || !hasBudgetIssue(second.Coverage, "capture_input_budget") {
		t.Fatalf("second source did not use shared input budget: %+v budget=%+v", second, budget)
	}
	third := parse(input)
	if *third.Coverage.Counts.Read != 0 || *third.Coverage.Counts.Truncated != 1 || budget.InputBytes != 0 {
		t.Fatalf("exhausted input was read or silently treated as empty: %+v", third)
	}
}

func TestSharedRecordBudgetBoundsCompoundLinesAndNextSource(t *testing.T) {
	input := `{"type":"user","sessionId":"s","message":{"content":"task"}}`
	budget := &ParseBudget{InputBytes: 1 << 20, Records: 2}
	p, err := Parse(context.Background(), strings.NewReader(input+input+input+"\n"), ParseOptions{Harness: "claude", Budget: budget})
	if err != nil || len(p.Records) != 2 || budget.Records != 0 || !hasBudgetIssue(p.Coverage, "capture_record_budget") {
		t.Fatalf("compound limit: %+v budget=%+v err=%v", p, budget, err)
	}
	left := budget.InputBytes
	p, err = Parse(context.Background(), strings.NewReader(input+"\n"), ParseOptions{Harness: "claude", Budget: budget})
	if err != nil || len(p.Records) != 0 || p.Coverage.Status != Partial || budget.InputBytes != left {
		t.Fatalf("exhausted record budget still read input: %+v budget=%+v err=%v", p, budget, err)
	}
}

func TestSharedBudgetChargesRejectedRecords(t *testing.T) {
	input := `{"type":"user","sessionId":"one","message":{"content":"one"}}
{"type":"user","sessionId":"two","message":{"content":"two"}}
`
	budget := &ParseBudget{InputBytes: 1 << 20, Records: 10}
	p, err := Parse(context.Background(), strings.NewReader(input), ParseOptions{Harness: "claude", Budget: budget})
	if err != nil || len(p.Records) != 0 || p.Coverage.Status != Ambiguous || budget.Records != 8 || budget.InputBytes != 1<<20-int64(len(input)) {
		t.Fatalf("rejected records reset consumed work: %+v budget=%+v err=%v", p, budget, err)
	}
}

func TestBudgetExhaustionDoesNotAccuseUnchangedResumeSource(t *testing.T) {
	header := `{"type":"session_meta","payload":{"id":"s"}}` + "\n"
	prefix := header + `{"type":"event_msg","payload":{"type":"user_message","message":"task"}}` + "\n"
	cursor := &SourceCursor{Valid: true, Bytes: int64(len(prefix)), Lines: 2, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(prefix)))}
	for _, budget := range []*ParseBudget{
		{InputBytes: int64(len(header) + 10), Records: 10},
		{InputBytes: 1 << 20, Records: 1},
	} {
		p, err := Parse(context.Background(), strings.NewReader(prefix), ParseOptions{Harness: "codex", SessionID: "s", AfterLine: 2, Cursor: cursor, Budget: budget})
		if err != nil || len(p.Records) != 0 || hasBudgetIssue(p.Coverage, "source_changed_before_resume") || hasBudgetIssue(p.Coverage, "source_cursor_out_of_range") {
			t.Fatalf("budget was misreported as source mutation: %+v %v", p, err)
		}
		if p.Coverage.Status == OK || p.Coverage.Status == Empty {
			t.Fatalf("resume prefix was not completely parsed: %+v", p)
		}
	}
}

func TestCompressedImportConsumesDecompressedSharedBudget(t *testing.T) {
	input := `{"type":"session","version":4,"id":"s"}` + "\n"
	input += `{"type":"user/message","seq":0,"data":{"role":"user","content":[{"type":"text","text":"` + strings.Repeat("task ", 4096) + `"}]}}` + "\n"
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	path := filepath.Join(t.TempDir(), "session.v4.jsonl.zstd")
	if err := os.WriteFile(path, encoder.EncodeAll([]byte(input), nil), 0600); err != nil {
		t.Fatal(err)
	}
	budget := &ParseBudget{InputBytes: 1024, Records: 100}
	svc := testService(t)
	result, err := svc.ImportFile(context.Background(), "run", ParseOptions{Harness: "deepseek", Path: path, Binding: "explicit", Budget: budget})
	if err != nil || result.Coverage.Status != Partial || budget.InputBytes != 0 || !hasBudgetIssue(result.Coverage, "capture_input_budget") {
		t.Fatalf("compressed source bypassed the budget: %+v budget=%+v err=%v", result, budget, err)
	}
	if budget.Records != 99 {
		t.Fatalf("partial JSON became a source record: %+v", budget)
	}
}
