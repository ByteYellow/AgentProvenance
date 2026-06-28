package mcpserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/aitools"
)

// run feeds newline-delimited JSON-RPC requests through Serve and returns the
// decoded response objects (notifications produce no line, so the count may be
// smaller than len(requests)). A nil *sql.DB is fine for the handshake, the
// inline gate, and the error paths -- none of them touch the store.
func run(t *testing.T, requests ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	if err := Serve(nil, in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, m)
	}
	return resps
}

func result(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	if errObj, ok := resp["error"]; ok {
		t.Fatalf("unexpected error response: %v", errObj)
	}
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("response has no result object: %v", resp)
	}
	return res
}

func TestInitializeEchoesProtocolVersionAndAdvertisesTools(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	res := result(t, resps[0])
	if got := res["protocolVersion"]; got != "2025-03-26" {
		t.Errorf("protocolVersion = %v, want echoed 2025-03-26", got)
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("capabilities missing tools: %v", caps)
	}
	info, _ := res["serverInfo"].(map[string]any)
	if info["name"] != serverName {
		t.Errorf("serverInfo.name = %v, want %s", info["name"], serverName)
	}
}

func TestInitializeFallsBackToDefaultVersion(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	res := result(t, resps[0])
	if got := res["protocolVersion"]; got != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want default %s", got, ProtocolVersion)
	}
}

func TestToolsListMatchesCatalog(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res := result(t, resps[0])
	tools, ok := res["tools"].([]any)
	if !ok {
		t.Fatalf("tools is not an array: %v", res["tools"])
	}
	if len(tools) != len(aitools.Catalog()) {
		t.Fatalf("tools/list returned %d tools, catalog has %d", len(tools), len(aitools.Catalog()))
	}
	got := map[string]bool{}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		name, _ := tool["name"].(string)
		if name == "" {
			t.Errorf("tool missing name: %v", tool)
		}
		if _, ok := tool["inputSchema"].(map[string]any); !ok {
			t.Errorf("tool %q missing camelCase inputSchema: %v", name, tool)
		}
		if _, ok := tool["description"].(string); !ok {
			t.Errorf("tool %q missing description", name)
		}
		got[name] = true
	}
	for _, want := range []string{"verify_run", "get_signals", "list_risks", "list_events", "get_timeline", "evaluate_action"} {
		if !got[want] {
			t.Errorf("tools/list missing %q", want)
		}
	}
}

func TestToolsCallEvaluateActionReturnsGateVerdict(t *testing.T) {
	// 169.254.169.254 is the cloud metadata IP -> the policy gate must not allow it.
	resps := run(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evaluate_action","arguments":{"event_type":"network_connect","dst_ip":"169.254.169.254"}}}`)
	res := result(t, resps[0])
	if res["isError"] != false {
		t.Errorf("isError = %v, want false (the gate ran successfully)", res["isError"])
	}
	structured, ok := res["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("missing structuredContent: %v", res)
	}
	if structured["decision"] == "allow" || structured["allow"] == true {
		t.Errorf("metadata-IP connect should not be allowed, got %v", structured)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("missing content blocks: %v", res)
	}
	first := content[0].(map[string]any)
	if first["type"] != "text" {
		t.Errorf("content[0].type = %v, want text", first["type"])
	}
	if !strings.Contains(first["text"].(string), "decision") {
		t.Errorf("content text should carry the serialized verdict, got %q", first["text"])
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	resps := run(t,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want 1 response (notification is silent), got %d: %v", len(resps), resps)
	}
	if resps[0]["id"].(float64) != 7 {
		t.Errorf("response id = %v, want the ping id 7", resps[0]["id"])
	}
}

func TestUnknownMethodIsProtocolError(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":8,"method":"resources/list"}`)
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("want error response, got %v", resps[0])
	}
	if errObj["code"].(float64) != codeMethodNotFound {
		t.Errorf("code = %v, want %d", errObj["code"], codeMethodNotFound)
	}
}

func TestUnknownToolIsProtocolError(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`)
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("want error response for unknown tool, got %v", resps[0])
	}
	if errObj["code"].(float64) != codeMethodNotFound {
		t.Errorf("code = %v, want %d", errObj["code"], codeMethodNotFound)
	}
}

func TestMissingToolNameIsInvalidParams(t *testing.T) {
	resps := run(t, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"arguments":{}}}`)
	errObj, ok := resps[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("want error response, got %v", resps[0])
	}
	if errObj["code"].(float64) != codeInvalidParams {
		t.Errorf("code = %v, want %d", errObj["code"], codeInvalidParams)
	}
}

func TestMalformedLineIsParseErrorWithNullID(t *testing.T) {
	resps := run(t, `{not json`)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	if resps[0]["id"] != nil {
		t.Errorf("parse error id = %v, want null", resps[0]["id"])
	}
	errObj := resps[0]["error"].(map[string]any)
	if errObj["code"].(float64) != codeParse {
		t.Errorf("code = %v, want %d", errObj["code"], codeParse)
	}
}
