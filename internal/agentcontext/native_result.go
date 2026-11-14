package agentcontext

import "encoding/json"

// Accept only the explicit MCP envelope shapes used by supported harnesses.
// Arbitrary nested text and multiple content blocks are not native references.
func nativeToolResult(raw json.RawMessage) json.RawMessage {
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		return []byte(encoded)
	}
	var value row
	if json.Unmarshal(raw, &value) == nil && value != nil {
		if text(value, "schema_version") != "" {
			return raw
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
	return []byte(text(blocks[0], "text"))
}
