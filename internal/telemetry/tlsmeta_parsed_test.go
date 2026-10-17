package telemetry

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestParsedTLSMetadataPreservesHTTP2WithoutBodyCapture(t *testing.T) {
	t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", "")
	raw := map[string]any{
		"connection_id": "tls-v1:" + strings.Repeat("a", 64),
		"protocol":      "h2", "headers_decoded": true, "stream_id": float64(7),
		"method": "POST", "host": "API.Example.COM:8443",
		"path":         "/v1/chat/completions?api_key=hidden#private",
		"endpoint":     "https://user:password@bad.example/ignored?key=hidden",
		"content_type": "application/json; charset=utf-8", "model": "model-test",
		"headers": map[string]any{"Authorization": "Bearer hidden", "Cookie": "session=hidden"},
		"data":    `{"messages":[{"role":"user","content":"A prompt"}]}`, "length": float64(55),
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(sslPayload(raw, "python", "request")), &payload); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"connection_id": "tls-v1:" + strings.Repeat("a", 64),
		"protocol":      "h2", "kind": "request", "headers_decoded": true, "stream_id": float64(7),
		"method": "POST", "host": "api.example.com:8443", "path": "/v1/chat/completions",
		"endpoint": "api.example.com:8443/v1/chat/completions", "content_type": "application/json", "model": "model-test",
	}
	if !reflect.DeepEqual(payload["http"], want) {
		t.Fatalf("http = %#v, want %#v", payload["http"], want)
	}
	if _, ok := payload["content"]; ok {
		t.Fatal("metadata must not enable full body capture")
	}
	encoded, _ := json.Marshal(payload)
	if strings.Contains(string(encoded), "hidden") || strings.Contains(string(encoded), "password") {
		t.Fatalf("non-allow-listed request metadata leaked: %s", encoded)
	}
}

func TestParsedTLSConnectionIDValidation(t *testing.T) {
	for _, id := range []any{"", "SSL*:123", "tls-v1:" + strings.Repeat("g", 64), "tls-v1:" + strings.Repeat("a", 65), "tls-v1:\n" + strings.Repeat("a", 63), 1} {
		got := capturedTLSMeta(map[string]any{"protocol": "h2", "connection_id": id}, "response")
		if got["connection_id"] != nil {
			t.Fatalf("invalid ID retained: %#v", got)
		}
	}
}

func TestParsedTLSMetadataDoesNotSniffBody(t *testing.T) {
	for _, body := range []string{
		"POST /fake HTTP/1.1\r\nHost: fake.example\r\nContent-Type: text/event-stream\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"\x00\x01\x02\x03\xff",
	} {
		got := capturedTLSMeta(map[string]any{"protocol": "http/1.1", "data": body}, "response")
		want := map[string]any{"protocol": "http/1.1", "kind": "response"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("body changed metadata: %#v", got)
		}
	}
}

func TestParsedTLSMetadataResponse(t *testing.T) {
	got := capturedTLSMeta(map[string]any{
		"protocol": "h2", "headers_decoded": true, "stream_id": uint32(3),
		"status": 200, "content_type": "text/event-stream; charset=utf-8",
		"method": "DELETE", "host": "body.example", "path": "/pretend",
	}, "response")
	want := map[string]any{
		"protocol": "h2", "kind": "response", "headers_decoded": true,
		"stream_id": int64(3), "status": 200, "content_type": "text/event-stream", "is_stream": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParsedTLSMetadataRejectsInvalidFields(t *testing.T) {
	for _, stream := range []any{0, -1, float64(1.5), float64(1 << 31), "7", true} {
		got := capturedTLSMeta(map[string]any{
			"protocol": "h2", "stream_id": stream, "status": float64(200.5),
			"host": "user:secret@example.com", "path": "relative/path",
			"method": "POST\r\nHeader: injected", "content_type": "text/plain\r\nAuthorization: x",
			"model": strings.Repeat("m", 257),
		}, "request")
		if !reflect.DeepEqual(got, map[string]any{"protocol": "h2", "kind": "request"}) {
			t.Fatalf("invalid metadata survived: %#v", got)
		}
	}
	for _, protocol := range []any{"other", "", nil, true} {
		if got := capturedTLSMeta(map[string]any{"protocol": protocol, "data": "POST /fake HTTP/1.1\r\n\r\n"}, "request"); got != nil {
			t.Fatalf("unsupported parsed protocol was reinterpreted: %#v", got)
		}
	}
}

func TestLegacyTLSMetadataUsesTopLevelModelOnly(t *testing.T) {
	for _, body := range []string{
		`{"messages":[{"model":"not-the-model"}]}`,
		`{"messages":[{"content":"\"model\":\"not-the-model\""}]}`,
		`{"model":`,
	} {
		got := capturedTLSMeta(map[string]any{"data": "POST /v1/messages HTTP/1.1\r\nHost: api.example\r\n\r\n" + body}, "request")
		if got["model"] != nil {
			t.Fatalf("nested or incomplete model became metadata: %#v", got)
		}
	}
}

func TestLegacyTLSMetadataStripsURLSecrets(t *testing.T) {
	got := capturedTLSMeta(map[string]any{
		"data": "GET https://user:pass@api.example/v1/%66iles?token=secret#private HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer secret\r\n\r\n",
	}, "request")
	if got["path"] != "/v1/%66iles" || got["endpoint"] != "api.example/v1/%66iles" {
		t.Fatalf("endpoint = %#v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "pass") || strings.Contains(string(b), "private") {
		t.Fatalf("URL credentials/query/fragment leaked into metadata: %s", b)
	}
}
