package signals

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Conformance is the validation half of the agentprovenance.signals/v1 contract.
// A wire format is only a contract if producers and consumers can independently
// check that bytes conform to it; these functions are that check, usable by
// external collectors, evaluators, and auditors. They validate shape and
// invariants, not storage.

// ValidateSignal checks a single signal against the contract invariants.
func ValidateSignal(s Signal) error {
	if !s.Dimension.Valid() {
		return fmt.Errorf("signals: invalid dimension %q", s.Dimension)
	}
	if strings.TrimSpace(s.Type) == "" {
		return fmt.Errorf("signals: empty signal type")
	}
	if s.Confidence < 0 || s.Confidence > 1 {
		return fmt.Errorf("signals: confidence %g out of range [0,1] (type %q)", s.Confidence, s.Type)
	}
	if s.GraphRefKind == "" || s.GraphRefID == "" {
		return fmt.Errorf("signals: signal %q missing graph_ref (kind=%q id=%q)", s.Type, s.GraphRefKind, s.GraphRefID)
	}
	if (s.SourceTable == "") != (s.SourceID == "") {
		return fmt.Errorf("signals: source_table and source_id must both be set or both empty (type %q)", s.Type)
	}
	if s.EvidenceRefs != "" {
		var refs []string
		if err := json.Unmarshal([]byte(s.EvidenceRefs), &refs); err != nil {
			return fmt.Errorf("signals: evidence_refs must be a JSON array (type %q): %w", s.Type, err)
		}
	}
	if s.Payload != "" {
		var obj map[string]any
		if err := json.Unmarshal([]byte(s.Payload), &obj); err != nil {
			return fmt.Errorf("signals: payload must be a JSON object (type %q): %w", s.Type, err)
		}
	}
	return nil
}

// ValidateSet checks a SignalSet envelope: schema version, count/counts
// consistency, and every signal.
func ValidateSet(set SignalSet) error {
	if set.SchemaVersion != SchemaVersion {
		return fmt.Errorf("signals: schema_version %q does not match %q", set.SchemaVersion, SchemaVersion)
	}
	if set.Count != len(set.Signals) {
		return fmt.Errorf("signals: count %d does not match signals length %d", set.Count, len(set.Signals))
	}
	tally := map[string]int{}
	for i, s := range set.Signals {
		if err := ValidateSignal(s); err != nil {
			return fmt.Errorf("signals: signal[%d]: %w", i, err)
		}
		if s.RunID != "" && set.RunID != "" && s.RunID != set.RunID {
			return fmt.Errorf("signals: signal[%d] run_id %q does not match set run_id %q", i, s.RunID, set.RunID)
		}
		tally[string(s.Dimension)]++
	}
	for dim, n := range set.Counts {
		if tally[dim] != n {
			return fmt.Errorf("signals: counts[%q]=%d does not match actual %d", dim, n, tally[dim])
		}
	}
	return nil
}

// ValidateWireBytes decodes and validates a SignalSet from its JSON wire form.
// This is the entry point an external consumer uses to confirm a payload
// conforms to agentprovenance.signals/v1 before trusting it.
func ValidateWireBytes(data []byte) (SignalSet, error) {
	var set SignalSet
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return SignalSet{}, fmt.Errorf("signals: decode wire bytes: %w", err)
	}
	if err := ValidateSet(set); err != nil {
		return SignalSet{}, err
	}
	return set, nil
}
