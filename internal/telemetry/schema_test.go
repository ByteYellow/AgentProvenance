package telemetry

import "testing"

func TestCorrelationClass(t *testing.T) {
	cases := []struct {
		name        string
		source      string
		method      string
		containerID string
		confidence  float64
		want        string
	}{
		{"mode1 process sample", "record_process_sample", "zero_sdk_process_tree", "agentprov-record-attempt-1", 0.9, "self_observed"},
		{"mode1 file diff", "record_file_diff", "container_time_window:container_id+time", "agentprov-record-attempt-1", 0.92, "self_observed"},
		{"falco kernel correlated", "falco_jsonl", "container_time_window:container_id+time", "7b9c4f6a", 0.92, "kernel_correlated"},
		{"own sensor kernel correlated", "agentprov_ebpf", "cgroup_time_window:cgroup_id+time", "abcd", 0.98, "kernel_correlated"},
		{"caller asserted context", "filtered_telemetry", "provided_context", "", 1.0, "context_asserted"},
		{"unresolved", "falco_jsonl", "unresolved", "", 0, "uncorrelated"},
		{"empty method", "falco_jsonl", "", "", 0, "uncorrelated"},
	}
	for _, tc := range cases {
		if got := CorrelationClass(tc.source, tc.method, tc.containerID, tc.confidence); got != tc.want {
			t.Errorf("%s: CorrelationClass(%q,%q,%q,%v) = %q, want %q", tc.name, tc.source, tc.method, tc.containerID, tc.confidence, got, tc.want)
		}
	}
}
