package signals

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
)

func validateConfidence(value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return fmt.Errorf("signals: confidence must be a finite number in [0,1]")
	}
	return nil
}

// JSON producers can explicitly report zero. Omission retains the legacy
// default; null is rejected rather than silently becoming an authoritative 1.
func (s *Signal) UnmarshalJSON(data []byte) error {
	return s.decodeJSON(data, false)
}

func (s *Signal) decodeJSON(data []byte, strict bool) error {
	type wire Signal
	var value wire
	var input = struct {
		*wire
		Confidence json.RawMessage `json:"confidence"`
	}{wire: &value}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if len(input.Confidence) > 0 {
		if bytes.Equal(bytes.TrimSpace(input.Confidence), []byte("null")) {
			return fmt.Errorf("signals: confidence must be numeric; omit it to use the default")
		}
		if err := json.Unmarshal(input.Confidence, &value.Confidence); err != nil {
			return err
		}
		value.ConfidenceSet = true
	}
	*s = Signal(value)
	return nil
}

func (s Signal) MarshalJSON() ([]byte, error) {
	type wire Signal
	var confidence *float64
	if s.ConfidenceSet || s.Confidence != 0 {
		confidence = &s.Confidence
	}
	return json.Marshal(struct {
		wire
		Confidence *float64 `json:"confidence,omitempty"`
	}{wire(s), confidence})
}
