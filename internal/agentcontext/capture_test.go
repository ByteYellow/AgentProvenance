package agentcontext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func capturePreset(t *testing.T, preset string, results *bool) *CapturePolicy {
	t.Helper()
	p, err := NewCapturePolicy(preset, results)
	if err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestCapturePresetsAndOverrides(t *testing.T) {
	for _, test := range []struct {
		preset  string
		results *bool
		want    CapturePolicy
	}{
		{"", nil, CapturePolicy{Version: CapturePolicyVersion, Preset: "detailed", ToolResults: true, SourceRecords: true, History: true, Configuration: true}},
		{"basic", nil, CapturePolicy{Version: CapturePolicyVersion, Preset: "basic"}},
		{"basic", boolPointer(true), CapturePolicy{Version: CapturePolicyVersion, Preset: "basic", ToolResults: true, Overrides: map[string]bool{"tool_results": true}}},
		{"detailed", boolPointer(false), CapturePolicy{Version: CapturePolicyVersion, Preset: "detailed", History: true, Configuration: true, Overrides: map[string]bool{"tool_results": false}}},
	} {
		p, err := NewCapturePolicy(test.preset, test.results)
		if err != nil || !reflect.DeepEqual(p, test.want) || p.validate() != nil {
			t.Fatalf("preset %q: %+v %v", test.preset, p, err)
		}
	}
	if _, err := NewCapturePolicy("off", nil); err == nil {
		t.Fatal("sensor disable was accepted as a capture preset")
	}
	p := *capturePreset(t, "basic", nil)
	p.History = true
	if p.validate() == nil {
		t.Fatal("unrecorded override accepted")
	}
}

func boolPointer(v bool) *bool { return &v }

func TestBasicCaptureOmitsBeforeWritingAndReportsScope(t *testing.T) {
	ctx, s := context.Background(), testService(t)
	s.CapturePolicy = capturePreset(t, "basic", nil)
	prior := "HISTORY-CONTENT-MUST-NOT-PERSIST"
	result := strings.Repeat("LONG-RESULT-MUST-NOT-PERSIST", 10000)
	configuration := `{"rules":"CONFIGURATION-MUST-NOT-PERSIST"}`
	state := `{"notes":"NATIVE-STATE-MUST-NOT-PERSIST"}`
	input := `{"cmd":"printf done"}`
	raw := `{"unused":"RAW-RECORD-MUST-NOT-PERSIST"}`
	records := []Record{
		{Key: "old", Sequence: 1, Kind: "message", Body: &prior, RawBody: &raw, ExecutionScope: PriorContext},
		{Key: "call", Sequence: 2, Kind: "tool_call", ToolCallID: "call", ToolName: "exec_command", Body: &input, RawBody: &raw},
		{Key: "result", Sequence: 3, Kind: "tool_result", ToolCallID: "call", Status: "error", Body: &result, RawBody: &raw},
		{Key: "config", Sequence: 4, Kind: "configuration", Body: &configuration, RawBody: &raw},
		{Key: "state", Sequence: 5, Kind: "session", Body: &state, RawBody: &raw},
	}
	saved, err := s.Save(ctx, "run", testSource(), records, Coverage{Status: OK,
		PriorContext: &PriorRange{FirstLine: 1, LastLine: 1, Counts: processingCounts()}})
	if err != nil || saved.Stored != 4 || saved.Coverage.Status != OK || *saved.Coverage.PriorContext.Counts.Stored != 0 {
		t.Fatalf("basic save: %+v %v", saved, err)
	}
	counts := map[string]int64{}
	for _, omission := range saved.Coverage.Omissions {
		if omission.Reason != "capture_policy" {
			t.Fatalf("wrong omission: %+v", omission)
		}
		counts[omission.Category] = omission.Records
	}
	if !reflect.DeepEqual(counts, map[string]int64{"history": 1, "source_records": 4, "tool_result": 1, "configuration": 1, "session_details": 1}) {
		t.Fatalf("omission accounting: %+v", counts)
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "run"})
	if err != nil || len(page.Entries) != 4 {
		t.Fatalf("records: %+v %v", page, err)
	}
	for _, entry := range page.Entries {
		if entry.RawContent.State != "omitted" || entry.RawContent.Ref != "" || entry.RawContent.DigestScope != "source_record" {
			t.Fatalf("raw was retained: %+v", entry)
		}
		if entry.Kind == "tool_call" {
			body, err := provenance.ReadTextContentPage(s.DB, "run", entry.Content.Ref, 0, 1024)
			if err != nil || body.Content != input {
				t.Fatalf("core input: %+v %v", body, err)
			}
		} else if entry.Content.Ref != "" || entry.Content.State != "omitted" || entry.Content.Reason != "capture_policy" || entry.Content.SHA256 == "" || entry.Content.Bytes == nil {
			t.Fatalf("not an explicit omission: %+v", entry)
		}
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(s.Paths.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range []string{prior, "LONG-RESULT-MUST-NOT-PERSIST", "CONFIGURATION-MUST-NOT-PERSIST", "NATIVE-STATE-MUST-NOT-PERSIST", "RAW-RECORD-MUST-NOT-PERSIST"} {
			if strings.Contains(string(data), marker) {
				t.Errorf("omitted content persisted in %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCapturePolicyPersistsAndRejectsMidRunChanges(t *testing.T) {
	ctx, s := context.Background(), testService(t)
	s.CapturePolicy = capturePreset(t, "basic", nil)
	body, raw := "result", `{"result":"result"}`
	record := Record{Key: "call", Kind: "tool_result", Body: &body, RawBody: &raw}
	if _, err := s.Save(ctx, "run", testSource(), []Record{record}, Coverage{Status: OK}); err != nil {
		t.Fatal(err)
	}
	s.CapturePolicy = nil
	record.Key = "next"
	if r, err := s.Save(ctx, "run", testSource(), []Record{record}, Coverage{Status: OK}); err != nil || r.Coverage.CapturePolicy.Preset != "basic" {
		t.Fatalf("policy wasn't reused: %+v %v", r, err)
	}
	s.CapturePolicy = capturePreset(t, "detailed", nil)
	if _, err := s.Save(ctx, "run", testSource(), []Record{record}, Coverage{Status: OK}); err == nil {
		t.Fatal("run policy changed silently")
	}
	overview, err := s.Overview(ctx, "run")
	if err != nil || overview.CapturePolicy == nil || overview.CapturePolicy.Preset != "basic" || len(overview.Coverage) != 1 {
		t.Fatalf("overview: %+v %v", overview, err)
	}
	if o, err := s.Overview(ctx, "old-run"); err != nil || o.CapturePolicy != nil {
		t.Fatalf("fabricated legacy policy: %+v %v", o, err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Overview(ctx, "run"); err == nil {
		t.Fatal("failed policy read became default policy")
	}
}

func TestResultOverrideCannotLeakThroughRawRecords(t *testing.T) {
	ctx := context.Background()
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, boolPointer(false))
			input := `{"type":"session_meta","payload":{"id":"s"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"call","output":"DISALLOWED-RESULT-BODY"}}
`
			parsed, err := Parse(ctx, strings.NewReader(input), ParseOptions{Harness: "codex", Binding: "explicit"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
				t.Fatal(err)
			}
			page, err := s.Entries(ctx, PageOptions{RunID: "run"})
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page.Entries {
				if entry.RawContent.State == "stored" || (entry.Kind == "tool_result" && entry.Content.State == "stored") {
					t.Fatalf("result override ignored: %+v", entry)
				}
			}
		})
	}
}

func TestCoreIntentProjectionOnlyContainsSupportedEvidence(t *testing.T) {
	input := `{"type":"assistant","sessionId":"s","timestamp":"2026-10-18T00:00:00Z","source_config":"DO-NOT-RETAIN","message":{"model":"m","stop_reason":"tool_use","usage":{"extra":"DO-NOT-RETAIN"},"content":[{"type":"thinking","thinking":"reason","signature":"DO-NOT-RETAIN"},{"type":"tool_use","id":"c","name":"Bash","input":{"command":"true"}},{"type":"tool_result","tool_use_id":"c","content":"DO-NOT-RETAIN"}]}}`
	body, err := coreIntentRecord(Source{Harness: "claude"}, &input)
	if err != nil || body == nil || strings.Contains(*body, "DO-NOT-RETAIN") {
		t.Fatalf("projection: %v %v", body, err)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(*body), &value); err != nil || value["projection"] != "claude-model-calls/v1" || value["sessionId"] != "s" {
		t.Fatalf("projection identity: %+v %v", value, err)
	}
	for _, raw := range []string{`{"type":"user","message":{"content":[{"type":"tool_result","content":"output"}]}}`, `{"type":"system","config":"extra"}`} {
		if body, err := coreIntentRecord(Source{Harness: "claude"}, &raw); err != nil || body != nil {
			t.Fatalf("non-intent source retained: %v %v", body, err)
		}
	}
}
