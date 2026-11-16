package agentcontext

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Duplicate members and excessive nesting make native identities ambiguous.
func nativeResultJSON(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > MaxLineBytes || !utf8.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var visit func(int) bool
	visit = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return true
		}
		if delim != '{' && delim != '[' {
			return false
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
			}
			if !visit(depth + 1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
	}
	if !visit(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// Accept only the explicit MCP envelope shapes used by supported harnesses.
// Arbitrary nested text and multiple content blocks are not native references.
func nativeToolResult(raw json.RawMessage) json.RawMessage {
	if !nativeResultJSON(raw) {
		return nil
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		if !nativeResultJSON([]byte(encoded)) {
			return nil
		}
		return []byte(encoded)
	}
	var value row
	if json.Unmarshal(raw, &value) == nil && value != nil {
		if flag(value, "isError") || flag(value, "is_error") {
			return nil
		}
		if text(value, "schema_version") != "" {
			return raw
		}
		if _, camel := value["structuredContent"]; camel {
			if _, snake := value["structured_content"]; snake {
				return nil
			}
		}
		for _, key := range []string{"structuredContent", "structured_content"} {
			if nested, ok := value[key]; ok {
				return nested
			}
		}
		raw = value["content"]
	}
	var blocks []row
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) != 1 || text(blocks[0], "type") != "text" {
		return nil
	}
	result := []byte(text(blocks[0], "text"))
	if !nativeResultJSON(result) {
		return nil
	}
	return result
}
