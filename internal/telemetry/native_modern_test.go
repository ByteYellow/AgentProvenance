package telemetry

import (
	"encoding/json"
	"testing"
)

func TestNativeModernMetadataSurvivesMapping(t *testing.T) {
	for _, input := range []map[string]any{
		{"event_type": "network_connect", "dst_ip": "fe80::1", "dst_port": "443", "scope_id": 4, "address_family": "AF_INET6"},
		{"event_type": "file_open", "path": ".env", "mode": "read", "syscall_name": "openat2", "dirfd": 7, "open_flags": "0", "open_resolve": "8"},
		{"event_type": "execve", "path": "/dev/fd/7", "command": "fixture run", "syscall_name": "execveat", "exec_flags": 4096, "dirfd": 7},
		{"event_type": "syscall_result", "syscall_name": "execveat", "operation": "process_exec", "syscall_outcome": "failure", "syscall_result": -9, "dirfd": -1},
	} {
		event, ok, err := mapNative(input)
		if err != nil || !ok {
			t.Fatalf("%+v %v", event, err)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(event.Payload), &got); err != nil {
			t.Fatal(err)
		}
		for k, v := range input {
			if k == "event_type" {
				continue
			}
			if k == "dst_port" {
				k = "port"
			}
			if n, ok := v.(int); ok {
				v = float64(n)
			}
			if got[k] != v {
				t.Fatalf("%s: got %v want %v", k, got[k], v)
			}
		}
	}
}
