package agentcontext

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeResultRejectsAmbiguousOrErroredEnvelopes(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"one","schema_version":"two"}`,
		`{"structuredContent":{},"structured_content":{}}`,
		`{"isError":true,"structuredContent":` + browserToolResultFixture + `}`,
		`{"is_error":true,"structured_content":` + browserToolResultFixture + `}`,
		`{"content":[{"type":"text","text":"{}"},{"type":"text","text":"{}"}]}`,
		strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),
		`{} {}`,
	} {
		if nativeToolResult([]byte(raw)) != nil {
			t.Fatal("ambiguous or errored envelope accepted")
		}
	}
	duplicate := `{"schema_version":"one","schema_version":"two"}`
	encoded, _ := json.Marshal(duplicate)
	blocks, _ := json.Marshal([]map[string]any{{"type": "text", "text": duplicate}})
	for _, raw := range [][]byte{encoded, blocks} {
		if nativeToolResult(raw) != nil {
			t.Fatal("duplicate keys hidden inside encoded text accepted")
		}
	}
}
