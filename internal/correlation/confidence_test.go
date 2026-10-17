package correlation

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestBindingConfidencePresence(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        float64
	}{
		{"omitted", "", 0.5},
		{"zero", `,"confidence":0`, 0},
		{"fraction", `,"confidence":0.25`, 0.25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := resolutionDB(t)
			var b Binding
			if err := json.Unmarshal([]byte(`{"id":"b","run_id":"r","process_id":"p","binding_source":"ai_asserted","started_at":"2026-10-17T00:00:00Z"`+tc.field+`}`), &b); err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			if tc.field == "" && strings.Contains(string(wire), `"confidence"`) {
				t.Fatalf("implicit default became explicit: %s", wire)
			}
			if err := json.Unmarshal(wire, &b); err != nil {
				t.Fatal(err)
			}
			if _, err := RecordBinding(db, b); err != nil {
				t.Fatal(err)
			}
			stored, ok, err := GetBinding(db, "b")
			if err != nil || !ok || stored.Confidence != tc.want || !stored.ConfidenceSet {
				t.Fatalf("stored=%+v ok=%v err=%v", stored, ok, err)
			}
			match, ok, err := Resolve(db, RawIdentity{ProcessID: "p", Timestamp: "2026-10-17T00:00:01Z"})
			if err != nil || !ok || match.Confidence != tc.want {
				t.Fatalf("match=%+v ok=%v err=%v", match, ok, err)
			}
			wire, err = json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(wire, &stored); err != nil {
				t.Fatal(err)
			}
			stored.ID = "copy"
			if _, err := RecordBinding(db, stored); err != nil {
				t.Fatal(err)
			}
			copy, _, err := GetBinding(db, "copy")
			if err != nil || copy.Confidence != tc.want {
				t.Fatalf("roundtrip=%+v err=%v", copy, err)
			}
		})
	}
}

func TestBindingConfidenceInvalid(t *testing.T) {
	for _, value := range []float64{-0.1, 1.1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := RecordBinding(nil, Binding{Confidence: value, ConfidenceSet: true}); err == nil {
			t.Fatalf("accepted %v", value)
		}
	}
	for _, raw := range []string{`{"confidence":null}`, `{"confidence":"0"}`} {
		var b Binding
		if err := json.Unmarshal([]byte(raw), &b); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestProcessInstanceRetainsExplicitZeroConfidence(t *testing.T) {
	db := resolutionDB(t, Binding{ID: "seed", RunID: "r", CgroupID: "cg", ConfidenceSet: true, StartedAt: "2026-10-17T00:00:00Z"})
	raw := RawIdentity{RunID: "r", PID: 42, CgroupID: "cg", ProcessInstanceID: "12345678-1234-1234-1234-123456789abc:42:100", Timestamp: "2026-10-17T00:00:01Z"}
	if err := ObserveProcessInstance(db, raw); err != nil {
		t.Fatal(err)
	}
	match, ok, err := Resolve(db, raw)
	if err != nil || !ok || match.Confidence != 0 {
		t.Fatalf("seed promoted: %+v ok=%v err=%v", match, ok, err)
	}
}
