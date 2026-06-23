package provenance

import "encoding/json"

func unwrapRecordProcessPayload(payload string) []byte {
	body := []byte(payload)
	var wrapped struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && len(wrapped.Payload) > 0 {
		return wrapped.Payload
	}
	return body
}
