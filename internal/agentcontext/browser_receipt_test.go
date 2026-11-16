package agentcontext

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func receiptFixture() map[string]any {
	scope := map[string]any{"producer_id": "lab", "namespace": "team", "instance_id": "vm", "generation": "g1", "browser_id": "browser-1", "context_id": "context-1"}
	return map[string]any{
		"schema_version": "agentprovenance.browser_operation_receipt/v1", "scope": scope,
		"target_id": "page", "operation_id": "op", "action": "screenshot",
		"normalized_input_digest": "sha256:" + strings.Repeat("1", 64), "input_digest_basis": "privacy_projected_input/v1", "input_redactions": []string{},
		"accepted_at": "2026-11-15T10:00:01Z", "started_at": "2026-11-15T10:00:02Z", "ended_at": "2026-11-15T10:00:03Z", "sequence": 1,
		"run_id": nil, "caller_session_id": nil, "caller_tool_call_id": nil, "capture_epoch": "browser-1", "outcome": "ok", "gap_refs": []string{},
		"source_refs": map[string]any{
			"accept": map[string]any{"log": "browser.jsonl", "event_id": "accept", "sha256": strings.Repeat("2", 64)},
			"start":  map[string]any{"log": "browser.jsonl", "event_id": "start", "sha256": strings.Repeat("3", 64)},
			"end":    map[string]any{"log": "browser.jsonl", "event_id": "end", "sha256": strings.Repeat("4", 64)},
		},
		"result_digest": "sha256:" + strings.Repeat("5", 64), "digest": "sha256:" + strings.Repeat("6", 64),
		"bridge_identity": map[string]any{"source": "local_bridge_configuration", "authentication": "unverified", "transcript_identity": "source_asserted_only",
			"identity": map[string]any{"producer_id": "lab", "namespace": "team", "instance_id": "vm", "generation": "g1"}},
	}
}

func receiptAction(id, kind string) map[string]any {
	event := browserEvent(id, kind, "page", "")
	event["operation_id"], event["operation"], event["payload"] = "op", "screenshot", map[string]any{}
	return event
}

func receiptAccept() map[string]any {
	event := receiptAction("accept", "action_accept")
	delete(event, "target_type")
	delete(event, "cdp_session_id")
	full, payload := receiptFixture(), map[string]any{}
	for _, key := range []string{"schema_version", "normalized_input_digest", "input_digest_basis", "input_redactions", "capture_epoch", "sequence", "run_id", "caller_session_id", "caller_tool_call_id"} {
		payload[key] = full[key]
	}
	event["payload"] = payload
	return event
}

func receiptToolFixture(operation string) map[string]any {
	receipt := receiptFixture()
	return map[string]any{"schema_version": BrowserToolResultVersion, "operation": operation,
		"browser_operation": map[string]any{"scope": receipt["scope"], "target_id": "page", "operation_id": "op", "operation": "screenshot"},
		"browser_receipt":   receipt, "execution_status": "ok", "waiting_state": "settled", "capture_status": "ok", "output": map[string]any{"bytes": 12}}
}

func receiptJSON(t *testing.T, value any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func receiptEvidence(t *testing.T, value any) {
	t.Helper()
	if directory := os.Getenv("AGENTPROV_BROWSER_GO_EVIDENCE_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, strings.ReplaceAll(t.Name(), "/", "-")+".json"), append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBrowserReceiptAdmissionRegression(t *testing.T) {
	parsed := parseBrowser(t, browserHeader(), receiptAccept())
	receiptEvidence(t, parsed)
	if parsed.Coverage.Status != OK || len(parsed.Records) != 2 {
		t.Fatalf("durable admission not imported: status=%s records=%d", parsed.Coverage.Status, len(parsed.Records))
	}
	entry := parsed.Records[1]
	if entry.Kind == "tool_call" || entry.Kind == "tool_result" || entry.Browser.OperationID != "op" {
		t.Fatal("admission must retain identity without becoming an execution")
	}
	if len(receiptJSON(t, entry.Browser)["receipt"]) == 0 {
		t.Fatal("admission receipt metadata missing")
	}
}

func TestBrowserReceiptScreenshotTerminalRegression(t *testing.T) {
	image := receiptAction("image", "screenshot")
	image["image"] = "ZmFrZQ=="
	parsed := parseBrowser(t, browserHeader(), receiptAction("start", "action_start"), image, receiptAction("end", "action_end"))
	terminals := 0
	for _, record := range parsed.Records {
		if record.Kind == "tool_result" {
			terminals++
		}
	}
	receiptEvidence(t, map[string]any{"terminal_count": terminals, "parsed": parsed})
	if terminals != 1 {
		t.Fatalf("screenshot and action_end emitted %d terminal records, want 1", terminals)
	}
}

func TestBrowserReceiptQueryRetentionRegression(t *testing.T) {
	body := receiptToolFixture("read")
	body["browser_receipt"].(map[string]any)["bridge_identity"].(map[string]any)["authentication"] = "verified"
	hook := map[string]any{"session_id": "agent", "hook_event_name": "PostToolUse", "tool_use_id": "query-call", "tool_name": "mcp__browser__browser_result", "tool_response": body}
	raw, _ := json.Marshal(hook)
	policy, _ := NewCapturePolicy("basic", nil)
	retained, err := RetainHookEvent(raw, policy)
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseFixture(t, "claude", string(retained)+"\n")
	svc := testService(t)
	svc.CapturePolicy = &policy
	if _, err := svc.Save(context.Background(), "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	receiptEvidence(t, page)
	if len(page.Entries) != 1 || page.Entries[0].BrowserOperation == nil {
		t.Fatal("read receipt disappeared after basic retention")
	}
	metadata := receiptJSON(t, page.Entries[0].BrowserOperation)
	var observation map[string]json.RawMessage
	_ = json.Unmarshal(metadata["receipt"], &observation)
	if string(metadata["result_operation"]) != `"read"` || string(observation["authentication"]) != `"unverified"` {
		t.Fatal("query mode or unverified trust boundary was lost")
	}
	if len(BrowserAssociations(page.Entries)) != 0 {
		t.Fatal("query became an execution association")
	}
}

func parseBrowserReceiptOptions(t *testing.T, opts ParseOptions, values ...map[string]any) Parsed {
	t.Helper()
	var input strings.Builder
	for _, value := range values {
		raw, _ := json.Marshal(value)
		input.Write(raw)
		input.WriteByte('\n')
	}
	parsed, err := Parse(context.Background(), strings.NewReader(input.String()), opts)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestBrowserReceiptStoredResultOriginAndOriginalRefs(t *testing.T) {
	for _, origin := range []string{"external_file", "local_operator"} {
		for _, wrapper := range []string{"direct", "receipt", "browser_receipt", "mcp_result"} {
			t.Run(origin+"/"+wrapper, func(t *testing.T) {
				full := receiptFixture()
				full["bridge_identity"].(map[string]any)["authentication"] = "verified"
				event := receiptAction("result", "action_result")
				delete(event, "cdp_session_id")
				delete(event, "target_type")
				event["authentication"], event["origin"] = "verified", "local_operator"
				event["payload"] = full
				if wrapper == "mcp_result" {
					body := receiptToolFixture("execute")
					body["browser_receipt"] = full
					event["payload"] = body
				} else if wrapper != "direct" {
					event["payload"] = map[string]any{wrapper: full}
				}
				opts := ParseOptions{Harness: "browser", Binding: "explicit"}
				if origin == "local_operator" {
					opts.BindingEvidence = []string{BrowserLocalOperatorEvidence}
				}
				parsed := parseBrowserReceiptOptions(t, opts, browserHeader(), event)
				if parsed.Coverage.Status != OK || len(parsed.Records) != 2 {
					t.Fatalf("receipt result import: %s", parsed.Coverage.Status)
				}
				svc := testService(t)
				svc.CapturePolicy = capturePreset(t, "basic", nil)
				if _, err := svc.Save(context.Background(), "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
					t.Fatal(err)
				}
				page, err := svc.Entries(context.Background(), PageOptions{RunID: "run", Kind: "tool_result"})
				if err != nil || len(page.Entries) != 1 {
					t.Fatalf("stored receipt: entries=%d err=%v", len(page.Entries), err)
				}
				observation := page.Entries[0].Browser.Receipt
				if observation == nil || observation.Origin != origin || observation.Authentication != "unverified" || observation.DigestStatus != "source_asserted" {
					t.Fatal("source claims acquired trust or origin was lost")
				}
				originalJSON, _ := json.Marshal(full)
				var original BrowserReceipt
				if json.Unmarshal(originalJSON, &original) != nil || !reflect.DeepEqual(observation.Receipt, original) {
					t.Fatal("original receipt, scope, generation, timestamps or refs changed")
				}
			})
		}
	}
}

func TestBrowserReceiptScreenshotIncrementalTerminalCount(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "durable_admission"}[modern], func(t *testing.T) {
			image := receiptAction("image", "screenshot")
			image["image"] = base64.StdEncoding.EncodeToString(notebookPNG(t))
			values := []map[string]any{browserHeader()}
			if modern {
				values = append(values, receiptAccept())
			}
			values = append(values, receiptAction("start", "action_start"), image)
			svc := testService(t)
			for _, ending := range []bool{false, true, true} {
				input := append([]map[string]any{}, values...)
				if ending {
					result := receiptAction("result", "action_result")
					result["payload"] = receiptFixture()
					input = append(input, receiptAction("end", "action_end"), result)
				}
				parsed := parseBrowser(t, input...)
				if parsed.Coverage.Status != OK {
					t.Fatalf("incremental parse: %s", parsed.Coverage.Status)
				}
				if _, err := svc.Save(context.Background(), "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
					t.Fatal(err)
				}
				page, err := svc.Entries(context.Background(), PageOptions{RunID: "run", Kind: "tool_result"})
				want := 1
				if modern && !ending {
					want = 0
				}
				if err != nil || len(page.Entries) != want {
					t.Fatalf("terminal count after append: got=%d want=%d err=%v", len(page.Entries), want, err)
				}
			}
		})
	}
}

func TestBrowserReceiptQueryDoesNotRebindCaller(t *testing.T) {
	raw, _ := json.Marshal(receiptToolFixture("execute"))
	ref := browserResultReference(raw)
	if ref == nil {
		t.Fatal("fixture receipt missing")
	}
	legacy := BrowserOperation{Scope: ref.Scope, TargetID: ref.TargetID, OperationID: ref.OperationID, Operation: ref.Operation}
	if ref.Key() != legacy.Key() {
		t.Fatal("receipt changed operation identity key")
	}
	caller := Entry{ID: "execute", RunID: "run", Kind: "tool_result", ToolCallID: "execute-call", ToolName: "browser_execute",
		Source: Source{Harness: "claude", SessionID: "agent"}, BrowserOperation: ref}
	operation := Entry{ID: "start", RunID: "run", Kind: "tool_call", ToolCallID: "browser-call",
		Source:  Source{Harness: "browser", SessionID: "browser-session", Browser: &ref.Scope},
		Browser: &BrowserEvent{Kind: "action_start", Operation: ref.Operation, OperationID: ref.OperationID, TargetID: ref.TargetID}}
	queryRaw, _ := json.Marshal(receiptToolFixture("read"))
	query := caller
	query.ID, query.ToolCallID, query.ToolName, query.BrowserOperation = "read", "query-call", "browser_result", browserResultReference(queryRaw)
	if query.BrowserOperation == nil || query.BrowserOperation.Scope.Generation != "g1" || query.BrowserOperation.Key() != ref.Key() {
		t.Fatal("query lost original generation or identity")
	}
	if got := BrowserAssociations([]Entry{caller, operation, query, query}); len(got) != 1 || got[0].Caller.ToolCallID != caller.ToolCallID {
		t.Fatal("poll changed execution caller")
	}
	for _, tool := range []string{"browser_result", "browser_execute"} {
		query.ToolName = tool
		if len(BrowserAssociations([]Entry{query, operation})) != 0 {
			t.Fatal("read receipt created an execution association")
		}
	}
	for _, field := range []string{"run_id", "caller_session_id", "caller_tool_call_id"} {
		body := receiptToolFixture("execute")
		body["browser_receipt"].(map[string]any)[field] = "another"
		raw, _ := json.Marshal(body)
		caller.BrowserOperation = browserResultReference(raw)
		if caller.BrowserOperation == nil || len(BrowserAssociations([]Entry{caller, operation})) != 0 {
			t.Fatal("receipt lineage mismatch did not remain unresolved")
		}
	}
}

func TestBrowserReceiptUnknownQueryPreservesNullableLifecycle(t *testing.T) {
	body := receiptToolFixture("read")
	receipt := body["browser_receipt"].(map[string]any)
	receipt["outcome"], body["execution_status"] = "unknown", "unknown"
	receipt["started_at"], receipt["ended_at"], receipt["result_digest"] = nil, nil, nil
	receipt["gap_refs"] = []string{"result_not_recorded"}
	refs := receipt["source_refs"].(map[string]any)
	delete(refs, "start")
	delete(refs, "end")
	raw, _ := json.Marshal(body)
	ref := browserResultReference(raw)
	if ref == nil || ref.Receipt.Receipt.Outcome != "unknown" || ref.Receipt.Receipt.StartedAt != nil || ref.Receipt.Receipt.EndedAt != nil {
		t.Fatal("unknown receipt acquired a lifecycle or was lost")
	}
}

func TestBrowserReceiptMalformedAndScopeConflicts(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["schema_version"] = "future" },
		func(r map[string]any) { r["scope"].(map[string]any)["generation"] = "another" },
		func(r map[string]any) { r["capture_epoch"] = "another" },
		func(r map[string]any) { r["digest"] = "invalid" },
		func(r map[string]any) { r["ended_at"] = nil },
		func(r map[string]any) { r["source_refs"] = map[string]any{} },
		func(r map[string]any) {
			r["source_refs"].(map[string]any)["accept"].(map[string]any)["log"] = "../private.jsonl"
		},
		func(r map[string]any) { r["sequence"] = -1 },
		func(r map[string]any) { r["input_redactions"] = []string{"private selector"} },
		func(r map[string]any) { r["gap_refs"] = []string{"private exception text"} },
	} {
		body := receiptToolFixture("execute")
		mutate(body["browser_receipt"].(map[string]any))
		raw, _ := json.Marshal(body)
		if browserResultReference(raw) != nil {
			t.Fatal("malformed receipt became a native reference")
		}
	}
	event := receiptAction("result", "action_result")
	event["payload"] = receiptFixture()
	header := browserHeader()
	header["generation"] = "another"
	parsed := parseBrowser(t, header, event)
	if parsed.Coverage.Status != Ambiguous || len(parsed.Records) != 0 {
		t.Fatal("receipt was rebased into a different journal generation")
	}
}

func TestBrowserReceiptDuplicateAndConflictingLifecycle(t *testing.T) {
	for _, duplicate := range []string{"action_accept", "action_start", "action_end"} {
		values := []map[string]any{browserHeader(), receiptAccept(), receiptAction("start", "action_start"), receiptAction("end", "action_end")}
		extra := receiptAction("duplicate", duplicate)
		if duplicate == "action_accept" {
			extra = receiptAccept()
			extra["event_id"] = "duplicate"
		} else if duplicate == "action_end" {
			extra["payload"] = map[string]any{"bytes": 9}
		}
		parsed := parseBrowser(t, append(values, extra)...)
		if parsed.Coverage.Status != Ambiguous || len(parsed.Records) != 0 {
			t.Fatal("conflicting lifecycle admitted: " + duplicate)
		}
	}
	start := receiptAction("start", "action_start")
	parsed := parseBrowser(t, browserHeader(), receiptAccept(), start, start, receiptAction("end", "action_end"))
	if parsed.Coverage.Status != OK || len(parsed.Records) != 4 {
		t.Fatal("identical reread added another action")
	}
}

func TestBrowserReceiptHookMetadataCannotPromoteOrigin(t *testing.T) {
	body, _ := json.Marshal(receiptToolFixture("read"))
	ref := browserResultReference(body)
	raw, _ := json.Marshal(ref)
	raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), `"origin":"transcript"`, `"origin":"local_operator"`), `"authentication":"unverified"`, `"authentication":"verified"`))
	var restored BrowserOperation
	if err := json.Unmarshal(raw, &restored); err != nil || !restored.valid() || restored.Receipt.Origin != "transcript" || restored.Receipt.Authentication != "unverified" {
		t.Fatal("serialized hook metadata supplied importer authority")
	}
}

func TestBrowserReceiptLiveArtifacts(t *testing.T) {
	directory := os.Getenv("AGENTPROV_BROWSER_LIVE_RECEIPT_DIR")
	if directory == "" {
		t.Skip("opt-in existing Chrome/MCP artifacts")
	}
	paths, err := filepath.Glob(filepath.Join(directory, "capture", "browser*.jsonl"))
	if err != nil || len(paths) < 2 {
		t.Fatal("live journal generations missing")
	}
	svc := testService(t)
	svc.CapturePolicy = capturePreset(t, "basic", nil)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(context.Background(), file, ParseOptions{Harness: "browser", Binding: "explicit", Path: path})
		file.Close()
		if err != nil || parsed.Coverage.Status != OK {
			t.Fatalf("live capture import: %s %v", parsed.Coverage.Status, err)
		}
		if _, err := svc.Save(context.Background(), "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(directory, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Passed       bool `json:"passed"`
		Observations []struct {
			Tool   string          `json:"tool"`
			Result json.RawMessage `json:"result"`
		} `json:"observations"`
	}
	if json.Unmarshal(raw, &result) != nil || !result.Passed {
		t.Fatal("live acceptance was not successful")
	}
	queries := 0
	for _, observation := range result.Observations {
		if observation.Tool != "browser_result" && observation.Tool != "browser_execute" {
			continue
		}
		ref := browserResultReference(observation.Result)
		if ref == nil || ref.Receipt == nil || ref.Receipt.Authentication != "unverified" {
			t.Fatal("real Python result failed Go receipt decoding")
		}
		if observation.Tool == "browser_result" {
			queries++
			if ref.ResultOperation != "read" || ref.Scope.Generation != "first" {
				t.Fatal("real recovery query lost original generation")
			}
		}
	}
	if queries != 6 {
		t.Fatal("expected six recovery queries")
	}
	receiptEvidence(t, map[string]any{"passed": true, "journal_generations": len(paths), "recovery_queries": queries})
}
