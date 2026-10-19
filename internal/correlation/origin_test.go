package correlation

import (
	"strings"
	"testing"
)

func TestCaptureOriginContract(t *testing.T) {
	const boot = "01234567-89ab-cdef-0123-456789abcdef"
	base := map[string]any{"host_id": "host-a", "process_instance_id": boot + ":42:100"}
	want, valid := CaptureOrigin([]map[string]any{base}, 42)
	if !valid || want == "" {
		t.Fatal("missing origin")
	}
	for _, tc := range []struct {
		name   string
		fields map[string]any
		valid  bool
		same   bool
	}{
		{"same origin different birth", map[string]any{"host_id": "host-a", "process_instance_id": boot + ":42:900"}, true, true},
		{"canonical boot", map[string]any{"host_id": "host-a", "process_instance_id": strings.ToUpper(boot) + ":042:0100"}, true, true},
		{"same explicit boot", map[string]any{"host_id": "host-a", "boot_id": boot}, true, true},
		{"other host", map[string]any{"host_id": "host-b", "process_instance_id": boot + ":42:100"}, true, false},
		{"missing host", map[string]any{"process_instance_id": boot + ":42:100"}, true, false},
		{"other identity namespace", map[string]any{"node_name": "host-a", "process_instance_id": boot + ":42:100"}, true, false},
		{"wrong PID", map[string]any{"host_id": "host-a", "process_instance_id": boot + ":43:100"}, false, false},
		{"invalid lifetime", map[string]any{"host_id": "host-a", "process_instance_id": "invalid"}, false, false},
		{"invalid host type", map[string]any{"host_id": 42, "process_instance_id": boot + ":42:100"}, false, false},
		{"conflicting boot", map[string]any{"host_id": "host-a", "process_instance_id": boot + ":42:100", "boot_id": "11234567-89ab-cdef-0123-456789abcdef"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CaptureOrigin([]map[string]any{nil, tc.fields, nil}, 42)
			if ok != tc.valid || (got == want) != tc.same {
				t.Fatalf("origin=%s valid=%v, want same=%v valid=%v", got, ok, tc.same, tc.valid)
			}
		})
	}
	if got, ok := CaptureOrigin([]map[string]any{base, {"host_id": "host-b"}}, 42); ok || got != "" {
		t.Fatalf("contradictory envelopes: %s %v", got, ok)
	}
	if got, ok := CaptureOrigin(nil, 42); !ok || got != "" {
		t.Fatalf("absent identity: %s %v", got, ok)
	}
}

func TestNativeBindingsSeparateHostsAndCanonicalizeLifetime(t *testing.T) {
	const instance = "01234567-89ab-cdef-0123-456789abcdef:42:100"
	db := resolutionDB(t,
		Binding{ID: "a", RunID: "run-a", CgroupID: "cg-a", StartedAt: "2026-10-17T00:00:00Z"},
		Binding{ID: "b", RunID: "run-b", CgroupID: "cg-b", StartedAt: "2026-10-17T00:00:00Z"},
	)
	for _, host := range []string{"a", "b"} {
		if err := ObserveProcessInstance(db, RawIdentity{HostID: "host-" + host, ProcessInstanceID: instance, PID: 42, CgroupID: "cg-" + host, Timestamp: "2026-10-17T00:00:01Z"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := CloseBindingByPID(db, 42, "2026-10-17T00:00:01.5Z"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a", "b", "unknown", ""} {
		hostID := ""
		if host != "" {
			hostID = "host-" + host
		}
		match, ok, err := Resolve(db, RawIdentity{HostID: hostID, ProcessInstanceID: strings.ToUpper(instance), PID: 42, Timestamp: "2026-10-17T00:00:02Z"})
		want := host == "a" || host == "b"
		if err != nil || ok != want || (want && (match.RunID != "run-"+host || match.ToolCallID != "")) {
			t.Fatalf("host=%q match=%+v ok=%v err=%v", host, match, ok, err)
		}
	}
	if err := CloseProcessInstance(db, RawIdentity{HostID: "host-a", ProcessInstanceID: instance, PID: 42, Timestamp: "2026-10-17T00:00:03Z"}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a", "b"} {
		match, ok, err := Resolve(db, RawIdentity{HostID: "host-" + host, ProcessInstanceID: instance, PID: 42, Timestamp: "2026-10-17T00:00:04Z"})
		if err != nil || ok != (host == "b") {
			t.Fatalf("exit closed another host: %+v %v %v", match, ok, err)
		}
	}
}
