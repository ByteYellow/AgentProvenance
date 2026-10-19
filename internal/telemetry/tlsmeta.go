package telemetry

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// capturedTLSMeta prefers the sensor's parsed fields. For reassembled captures,
// data is a decoded BODY, not an HTTP message: sniffing it can turn text inside
// a prompt into a fictitious endpoint or protocol. Legacy raw windows still use
// tlsMeta, without attempting stateless HPACK decoding.
func capturedTLSMeta(raw map[string]any, direction string) map[string]any {
	value, parsed := raw["protocol"]
	if !parsed {
		return sanitizeTLSMeta(tlsMeta(stringAt(raw, "data"), direction), direction)
	}
	protocol, _ := value.(string)
	if protocol != "http/1.0" && protocol != "http/1.1" && protocol != "h2" {
		return nil
	}
	meta := map[string]any{"protocol": protocol, "kind": direction}
	for _, key := range []string{"method", "path", "host", "content_type", "model"} {
		if value, ok := raw[key].(string); ok {
			meta[key] = value
		}
	}
	if decoded, ok := raw["headers_decoded"].(bool); ok {
		meta["headers_decoded"] = decoded
	}
	if id, ok := raw["connection_id"].(string); ok && strings.HasPrefix(id, "tls-v1:") && len(id) == 71 {
		if _, err := hex.DecodeString(id[7:]); err == nil {
			meta["connection_id"] = id
		}
	}
	if status := httpMetadataNumber(raw["status"]); status >= 100 && status <= 599 {
		meta["status"] = int(status)
	}
	if id := httpMetadataNumber(raw["stream_id"]); protocol == "h2" && id > 0 && id <= 0x7fffffff {
		meta["stream_id"] = id
	}
	return sanitizeTLSMeta(meta, direction)
}

// Only endpoint identity and the small protocol allow-list survive here. Query
// strings, fragments, URL userinfo, arbitrary headers and body fields stay out.
func sanitizeTLSMeta(meta map[string]any, direction string) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	out := map[string]any{"kind": direction}
	for _, key := range []string{"protocol", "headers_decoded", "stream_id", "connection_id"} {
		if value, ok := meta[key]; ok {
			out[key] = value
		}
	}
	if direction == "request" {
		if method, _ := meta["method"].(string); httpMethods[method] {
			out["method"] = method
		}
		path, _ := meta["path"].(string)
		if path = safeHTTPPath(path); path != "" {
			out["path"] = path
		}
		host, _ := meta["host"].(string)
		if host = safeHTTPHost(host); host != "" {
			out["host"] = host
			if path != "" {
				out["endpoint"] = host + path
			}
		}
	} else if status, ok := meta["status"].(int); ok && status >= 100 && status <= 599 {
		out["status"] = status
	}
	if ct, _ := meta["content_type"].(string); boundedHTTPText(ct, 256) != "" {
		if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
			out["content_type"] = mediaType
			if mediaType == "text/event-stream" {
				out["is_stream"] = true
			}
		}
	}
	if model, _ := meta["model"].(string); boundedHTTPText(model, 256) != "" {
		out["model"] = model
	}
	if len(out) == 1 {
		return nil
	}
	return out
}

func boundedHTTPText(value string, limit int) string {
	if len(value) > limit || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return ""
	}
	return strings.TrimSpace(value)
}

func safeHTTPHost(value string) string {
	value = boundedHTTPText(value, 255)
	if value == "" || strings.ContainsAny(value, "/?#@\\") {
		return ""
	}
	u, err := url.Parse("//" + value)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func safeHTTPPath(value string) string {
	value = boundedHTTPText(value, 8192)
	if value == "" || value == "*" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/") || len(path) > 4096 {
		return ""
	}
	return path
}

func httpMetadataNumber(value any) int64 {
	switch n := value.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case uint32:
		return int64(n)
	case float64:
		if n >= 0 && n <= math.MaxInt32 && math.Trunc(n) == n {
			return int64(n)
		}
	case json.Number:
		number, err := n.Int64()
		if err == nil {
			return number
		}
	}
	return 0
}

// tlsMeta reads older raw TLS windows. A recognizable HTTP/2 preface remains
// undecoded here; arbitrary binary content does not identify its protocol.
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

	// Only a complete top-level JSON model field is metadata. A prompt containing
	// the string "model" must not become the model identity.
	body := data
	if end := strings.Index(data, "\r\n\r\n"); end >= 0 {
		body = data[end+4:]
	}
	var modelBody struct {
		Model string `json:"model"`
	}
	if json.Unmarshal([]byte(body), &modelBody) == nil && boundedHTTPText(modelBody.Model, 256) != "" {
		meta["model"] = modelBody.Model
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
