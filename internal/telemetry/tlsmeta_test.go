package telemetry

import "testing"

func TestTLSMetaHTTP1Request(t *testing.T) {
	data := "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"claude-opus-4\",\"messages\":[]}"
	m := tlsMeta(data, "request")
	if m["protocol"] != "http/1.1" || m["kind"] != "request" {
		t.Fatalf("protocol/kind = %v/%v", m["protocol"], m["kind"])
	}
	if m["method"] != "POST" || m["path"] != "/v1/messages" {
		t.Fatalf("method/path = %v/%v", m["method"], m["path"])
	}
	if m["host"] != "api.anthropic.com" {
		t.Fatalf("host = %v", m["host"])
	}
	if m["content_type"] != "application/json" {
		t.Fatalf("content_type = %v", m["content_type"])
	}
	// model is provenance metadata, allowed; message content must never appear.
	if m["model"] != "claude-opus-4" {
		t.Fatalf("model = %v, want claude-opus-4", m["model"])
	}
	if _, leaked := m["messages"]; leaked {
		t.Fatal("tlsMeta must not surface message content")
	}
}

func TestTLSMetaHTTP1Response(t *testing.T) {
	m := tlsMeta("HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n{}", "response")
	if m["kind"] != "response" || m["protocol"] != "http/1.1" {
		t.Fatalf("kind/protocol = %v/%v", m["kind"], m["protocol"])
	}
	if m["status"] != 429 {
		t.Fatalf("status = %v (%T), want 429", m["status"], m["status"])
	}
}

func TestTLSMetaSSEStreamFlag(t *testing.T) {
	m := tlsMeta("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {}", "response")
	if m["is_stream"] != true {
		t.Fatalf("is_stream = %v, want true for text/event-stream", m["is_stream"])
	}
}

func TestTLSMetaHTTP2PrefaceLabeledNotDecoded(t *testing.T) {
	m := tlsMeta("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "request")
	if m["protocol"] != "h2" {
		t.Fatalf("protocol = %v, want h2", m["protocol"])
	}
	if m["headers_decoded"] != false {
		t.Fatalf("headers_decoded = %v, want false (we do not fake HPACK)", m["headers_decoded"])
	}
}

func TestTLSMetaBinaryFramesAreH2NotMisparsed(t *testing.T) {
	// h2 HEADERS frame-ish bytes: length(3) type(1) flags(1) streamid(4) + HPACK.
	data := "\x00\x00\x1f\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x8a\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33"
	m := tlsMeta(data, "request")
	if m["protocol"] != "h2" || m["headers_decoded"] != false {
		t.Fatalf("binary frames should be labeled h2/undecoded, got %+v", m)
	}
	if _, ok := m["method"]; ok {
		t.Fatal("must not invent a method from undecoded h2 bytes")
	}
}

func TestTLSMetaModelTruncatedByWindowIsOmitted(t *testing.T) {
	// The model value is cut off by the 256B capture window (no closing quote).
	data := "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\n\r\n{\"model\":\"gpt-4o-very-long-name-that-got"
	m := tlsMeta(data, "request")
	if _, ok := m["model"]; ok {
		t.Fatalf("a truncated model value must be omitted, got %v", m["model"])
	}
	// But the request line + host still parse.
	if m["host"] != "api.openai.com" || m["method"] != "POST" {
		t.Fatalf("request head should still parse: %+v", m)
	}
}

func TestTLSMetaEmptyIsNil(t *testing.T) {
	if tlsMeta("", "request") != nil {
		t.Fatal("empty data should yield nil meta")
	}
}

func TestTLSMetaDirectionFallback(t *testing.T) {
	// Opaque text that is not classifiable HTTP still gets a kind from direction
	// when there is at least one other signal (here, none -> nil is acceptable).
	m := tlsMeta("Host: example.com\r\n\r\n", "response")
	if m["host"] != "example.com" {
		t.Fatalf("host = %v", m["host"])
	}
	if m["kind"] != "response" {
		t.Fatalf("kind should fall back to direction, got %v", m["kind"])
	}
}
