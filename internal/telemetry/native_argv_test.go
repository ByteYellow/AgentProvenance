package telemetry

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNativeExecPreservesArgumentBoundariesAndCaptureLimit(t *testing.T) {
	for _, marker := range []any{true, false, nil, "true"} {
		raw := map[string]any{
			"event_type": "execve", "source": "agentprov_ebpf",
			"argv":    []any{"bash", "-c", "python3 -m unittest -v test_rep"},
			"command": "bash -c python3 -m unittest -v test_rep",
		}
		if marker != nil {
			raw["argv_truncated"] = marker
		}
		event, ok, err := mapNative(raw)
		if err != nil || !ok {
			t.Fatalf("map: %v, %v", ok, err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(payload["argv"], raw["argv"]) {
			t.Fatalf("lost source argument boundaries: %v", payload)
		}
		value, present := payload["argv_truncated"]
		want, known := marker.(bool)
		if present != known || (known && value != want) {
			t.Fatalf("capture limit changed: source=%v stored=%v", marker, payload)
		}
	}
}

func TestNativeExecKeepsEmptyArguments(t *testing.T) {
	want := []any{"/bin/printf", "%s", "", "  "}
	event, ok, err := mapNative(map[string]any{"event_type": "execve", "argv": want})
	if err != nil || !ok {
		t.Fatalf("map: %v, %v", ok, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload["argv"], want) {
		t.Fatalf("empty arguments changed: %v", payload)
	}
}
