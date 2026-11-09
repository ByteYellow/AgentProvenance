package telemetry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
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

func TestTLSCaptureSequencePositionSurvivesRetention(t *testing.T) {
	position := tlsintent.ChunkPosition{StreamID: 123456789012345678, CallSequence: 13, Offset: 512, TotalBytes: 8192}
	for _, saved := range []string{"0", "1"} {
		t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", saved)
		capture := tlsintent.CaptureIntegrity{Rule: tlsintent.CaptureRule, State: "incomplete", Reason: tlsintent.GapChunkSequence,
			DataKind: tlsintent.DataTLSFragment, Position: &position}
		rawJSON, _ := json.Marshal(map[string]any{"data": "YWJj", "data_encoding": "base64", "length": 3, "capture": capture})
		var raw map[string]any
		if err := json.Unmarshal(rawJSON, &raw); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Capture tlsintent.CaptureIntegrity `json:"capture"`
			Content string                     `json:"content"`
		}
		if err := json.Unmarshal([]byte(sslPayload(raw, "python", "request")), &got); err != nil {
			t.Fatal(err)
		}
		if got.Capture.Position == nil || *got.Capture.Position != position || got.Capture.Rule != tlsintent.CaptureRule ||
			(saved == "0" && got.Content != "") || (saved == "1" && got.Content != "YWJj") {
			t.Fatalf("sequence metadata or retention changed: %+v", got)
		}
	}
}

func TestTLSCaptureCheckpointAndInvalidPosition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		position map[string]any
		valid    bool
	}{
		{"checkpoint", map[string]any{"stream_id": "100", "call_sequence": "9", "offset": 0, "total_bytes": 0, "checkpoint": true}, true},
		{"unknown_length", map[string]any{"stream_id": "100", "call_sequence": "9", "offset": 0, "total_bytes": 0}, false},
		{"missing_offset", map[string]any{"stream_id": "100", "call_sequence": "9", "total_bytes": 4096}, false},
		{"numeric_identity", map[string]any{"stream_id": 100, "call_sequence": "9", "offset": 0, "total_bytes": 4096}, false},
		{"negative_offset", map[string]any{"stream_id": "100", "call_sequence": "9", "offset": -1, "total_bytes": 4096}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := tlsCaptureIntegrity(map[string]any{"capture": map[string]any{
				"state": "incomplete", "reason": "tls_call_sequence", "data_kind": "tls_fragment", "position": tc.position,
			}})
			if (capture.Position != nil) != tc.valid || !capture.Incomplete() {
				t.Fatalf("position validation changed capture integrity: %+v", capture)
			}
		})
	}
}
