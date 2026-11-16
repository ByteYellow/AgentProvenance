package browsercustody

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestBrowserCustodyOpaqueAndStrictConfig(t *testing.T) {
	var v Verified
	if err := json.Unmarshal([]byte(`{"run":"run","authentication":"verified"}`), &v); err == nil {
		t.Fatal("JSON authorized a capability")
	}
	if result, err := v.Resolve(context.Background(), nil, "run"); err != nil || len(result) != 0 {
		t.Fatal("zero capability granted custody")
	}
	var absent *Verified
	if absent.RunID() != "" {
		t.Fatal("nil capability run")
	}
	for _, raw := range []string{
		`{"run_id":"a","run_id":"b"}`, `{"run_id":"a","Run_ID":"b"}`,
		`{"mappings":[{"scope":{"context_id":"a","context_id":"b"}}]}`,
		`{"authentication":"verified"}`, `{} {}`, strings.Repeat("[", 34) + strings.Repeat("]", 34),
	} {
		var config Config
		if err := decodeConfig([]byte(raw), &config); err == nil {
			t.Errorf("ambiguous config accepted: %s", raw)
		}
	}
	if !inside("/capture", "/capture/claim.json") || !inside("/capture", "/capture") || inside("/capture", "/receiver/config.json") {
		t.Fatal("authority containment boundary")
	}
}
