package signals

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestSignalConfidencePresenceRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        float64
	}{
		{"default", "", 1}, {"zero", `,"confidence":0`, 0}, {"fraction", `,"confidence":0.25`, 0.25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newDB(t)
			var s Signal
			if err := json.Unmarshal([]byte(`{"run_id":"r","dimension":"quality","type":"judgment","graph_ref_kind":"run","graph_ref_id":"r"`+tc.field+`}`), &s); err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			if tc.field == "" && strings.Contains(string(wire), `"confidence"`) {
				t.Fatalf("default became explicit: %s", wire)
			}
			if err := json.Unmarshal(wire, &s); err != nil {
				t.Fatal(err)
			}
			if _, err := Record(db, s); err != nil {
				t.Fatal(err)
			}
			set, err := Export(db, "r")
			if err != nil || len(set.Signals) != 1 || set.Signals[0].Confidence != tc.want {
				t.Fatalf("set=%+v err=%v", set, err)
			}
			wire, err = json.Marshal(set)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := ValidateWireBytes(wire)
			if err != nil {
				t.Fatal(err)
			}
			s = restored.Signals[0]
			s.ID = "copy"
			if _, err := Record(db, s); err != nil {
				t.Fatal(err)
			}
			values, err := Query(db, Filter{RunID: "r"})
			if err != nil || len(values) != 2 {
				t.Fatalf("values=%+v err=%v", values, err)
			}
			for _, value := range values {
				if value.Confidence != tc.want {
					t.Fatalf("value changed: %+v", value)
				}
			}
		})
	}
}

func TestSignalConfidenceRejectsInvalid(t *testing.T) {
	for _, value := range []float64{-0.1, 1.1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		s := Signal{Dimension: Quality, Type: "judgment", Confidence: value, ConfidenceSet: true}
		if _, err := Record(nil, s); err == nil {
			t.Fatalf("accepted %v", value)
		}
	}
	for _, raw := range []string{`{"confidence":null}`, `{"confidence":"0"}`} {
		var s Signal
		if err := json.Unmarshal([]byte(raw), &s); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestSignalConfidenceDecodeCompatibility(t *testing.T) {
	raw := `{"confidence":0,"extension":true}`
	var signal Signal
	if err := json.Unmarshal([]byte(raw), &signal); err != nil || signal.Confidence != 0 || !signal.ConfidenceSet {
		t.Fatalf("ordinary decoding rejected an extension: %+v err=%v", signal, err)
	}
	if _, err := ValidateWireBytes([]byte(`{"signals":[` + raw + `]}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict conformance accepted an unknown signal field: %v", err)
	}
}
