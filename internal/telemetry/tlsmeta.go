package telemetry

import (
	"strconv"
	"strings"
)

// tlsMeta extracts privacy-safe HTTP provenance metadata from a captured TLS
// plaintext window. The SSL uprobe copies at most 256 bytes (internal/sensor/
// exec.c, sensor_event.path[256]), so this sees only the head of a request or
// response. It returns an allow-listed field set -- protocol, request line,
// host, status, content type, stream flag, and a best-effort model id -- and
// NEVER headers or body wholesale, so it adds provenance (which endpoint/model,
// streaming or not) without persisting prompt/response content.
//
// HTTP/2 is detected and labeled but NOT decoded: HPACK header decoding needs
// per-connection dynamic-table state reconstructed across many writes, which a
// single isolated capture cannot provide. Emitting guessed h2 headers would be
// worse than honestly reporting headers_decoded=false. direction ("request" or
// "response", from the tls_write/tls_read event type) disambiguates when the
// captured bytes are too short or too binary to classify on their own.
func tlsMeta(data, direction string) map[string]any {
	if data == "" {
		return nil
	}
	meta := map[string]any{}
	switch {
	case strings.HasPrefix(data, "PRI * HTTP/2.0"):
		// HTTP/2 connection preface, sometimes the first thing on the wire.
		meta["protocol"] = "h2"
		meta["headers_decoded"] = false
	case isHTTP1ResponseLine(data):
		meta["protocol"] = http1Version(firstToken(data))
		meta["kind"] = "response"
		if code := http1Status(data); code > 0 {
			meta["status"] = code
		}
	case isHTTP1RequestLine(data):
		method, path, version := http1RequestLine(data)
		meta["protocol"] = version
		meta["kind"] = "request"
		meta["method"] = method
		if path != "" {
			meta["path"] = path
		}
	default:
		// Not recognizable HTTP/1.x text. If it is mostly non-printable it is
		// almost certainly h2 frames (HPACK); label it rather than decode it.
		if looksBinary(data) {
			meta["protocol"] = "h2"
			meta["headers_decoded"] = false
		}
	}

	// Header-derived fields, present only when they fit the captured window
	// (HTTP/1.x only; for h2 the bytes are framed and we do not decode them).
	if host := headerValue(data, "host"); host != "" {
		meta["host"] = host
	}
	if ct := headerValue(data, "content-type"); ct != "" {
		meta["content_type"] = ct
		if strings.Contains(strings.ToLower(ct), "text/event-stream") {
			meta["is_stream"] = true
		}
	}

	// Best-effort model id: provenance metadata (which model was called), not
	// content. Taken only if the "model" JSON key survived the 256B window; the
	// message/prompt content is never read.
	if model := jsonStringValue(data, "model"); model != "" {
		meta["model"] = model
	}

	if len(meta) == 0 {
		return nil
	}
	if _, ok := meta["kind"]; !ok && direction != "" {
		meta["kind"] = direction
	}
	return meta
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func firstLine(data string) string {
	if i := strings.IndexByte(data, '\n'); i >= 0 {
		return strings.TrimRight(data[:i], "\r")
	}
	return data
}

func firstToken(data string) string {
	line := firstLine(data)
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i]
	}
	return line
}

func isHTTP1ResponseLine(data string) bool {
	return strings.HasPrefix(data, "HTTP/1.0 ") || strings.HasPrefix(data, "HTTP/1.1 ")
}

func isHTTP1RequestLine(data string) bool {
	line := firstLine(data)
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !httpMethods[parts[0]] {
		return false
	}
	return strings.HasPrefix(parts[2], "HTTP/1.")
}

// http1Version normalizes an "HTTP/1.1" token to a lowercase protocol label.
func http1Version(token string) string {
	switch token {
	case "HTTP/1.0":
		return "http/1.0"
	case "HTTP/1.1":
		return "http/1.1"
	default:
		return "http/1"
	}
}

func http1Status(data string) int {
	parts := strings.Split(firstLine(data), " ")
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return 0
	}
	return code
}

func http1RequestLine(data string) (method, path, version string) {
	parts := strings.Split(firstLine(data), " ")
	if len(parts) != 3 {
		return "", "", "http/1"
	}
	return parts[0], parts[1], http1Version(parts[2])
}

// headerValue returns the value of the first header named name (case-insensitive)
// in the header block (lines before the blank line separating body). Only the
// caller's allow-listed header names are ever requested.
func headerValue(data, name string) string {
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers
		}
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

// jsonStringValue finds `"key":"value"` anywhere in data and returns value, or
// "" if absent. Intentionally tiny: it pulls a single scalar id, not structure.
func jsonStringValue(data, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(data, needle)
	if i < 0 {
		return ""
	}
	rest := data[i+len(needle):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	open := strings.IndexByte(rest, '"')
	if open < 0 {
		return ""
	}
	rest = rest[open+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "" // value truncated by the capture window
	}
	return rest[:end]
}

// looksBinary reports whether the head of data is mostly non-printable, the
// signature of HTTP/2 framing (length/type/flags bytes + HPACK) rather than
// HTTP/1.x text.
func looksBinary(data string) bool {
	n := len(data)
	if n > 64 {
		n = 64
	}
	if n == 0 {
		return false
	}
	nonPrintable := 0
	for i := 0; i < n; i++ {
		c := data[i]
		if c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			nonPrintable++
		}
	}
	return nonPrintable*5 > n // >20% non-printable
}
