package telemetry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestTLSCaptureGapRetainsBytesAndSuppressesBodySniffing(t *testing.T) {
	data := []byte("POST /not-a-request HTTP/1.1\r\nHost: fake.example\r\n\r\n\xff\x00")
	raw := map[string]any{"data": base64.StdEncoding.EncodeToString(data), "data_encoding": "base64", "length": len(data),
		"capture": map[string]any{"rule": "agentprov.tls_reassembly/v2", "state": "incomplete", "reason": "capture_limit", "data_kind": "tls_fragment"}}
	for _, saved := range []string{"0", "1"} {
		t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", saved)
		var payload map[string]any
		if err := json.Unmarshal([]byte(sslPayload(raw, "python", "request")), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["capture"] == nil || payload["truncated"] != true || payload["content_encoding"] != "base64" ||
			payload["preview_sha256"] != fmt.Sprintf("%x", sha256.Sum256(data)) {
			t.Fatalf("gap or original binary bytes lost: %+v", payload)
		}
		if payload["http"] != nil || payload["model"] != nil {
			t.Fatalf("fragment acquired HTTP/model semantics: %+v", payload)
		}
		if saved == "1" && payload["content"] != raw["data"] || saved == "0" && payload["content"] != nil {
			t.Fatalf("body retention policy changed: %+v", payload)
		}
	}
}
