package correlation

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Preserve input presence across JSON and Go callers without changing the
// stored numeric contract. A missing field keeps the source-specific default.
func (b *Binding) UnmarshalJSON(data []byte) error {
	type wire Binding
	var value wire
	var input = struct {
		*wire
		Confidence json.RawMessage `json:"confidence"`
	}{wire: &value}
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	if len(input.Confidence) > 0 {
		if bytes.Equal(bytes.TrimSpace(input.Confidence), []byte("null")) {
			return fmt.Errorf("binding confidence must be numeric; omit it to use the source default")
		}
		if err := json.Unmarshal(input.Confidence, &value.Confidence); err != nil {
			return err
		}
		value.ConfidenceSet = true
	}
	*b = Binding(value)
	return nil
}

func (b Binding) MarshalJSON() ([]byte, error) {
	type wire Binding
	var confidence *float64
	if b.ConfidenceSet || b.Confidence != 0 {
		confidence = &b.Confidence
	}
	return json.Marshal(struct {
		wire
		Confidence *float64 `json:"confidence,omitempty"`
	}{wire(b), confidence})
}
