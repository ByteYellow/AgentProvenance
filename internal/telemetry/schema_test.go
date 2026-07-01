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
		{"direct record event", "record", "", "agentprov-record-attempt-1", 0, "self_observed"},
		{"falco kernel correlated", "falco_jsonl", "container_time_window:container_id+time", "7b9c4f6a", 0.92, "kernel_correlated"},
		{"own sensor kernel correlated", "agentprov_ebpf", "cgroup_time_window:cgroup_id+time", "abcd", 0.98, "kernel_correlated"},
		// Option 2 regression: an independently-witnessed sensor event that
		// merely MATCHED a record-launched binding (synthetic agentprov-record-
		// container id) must stay kernel_correlated -- it is not self_observed
		// just because the scope was record-launched. The old string-prefix
		// hack mislabeled this as self_observed.
		{"sensor matched record binding", "agentprov_ebpf", "cgroup_time_window:cgroup_id+time", "agentprov-record-attempt-1", 0.98, "kernel_correlated"},
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

func TestSelfLaunched(t *testing.T) {
	cases := []struct {
		name          string
		source        string
		bindingSource string
		want          bool
	}{
		{"direct record event", "record", "", true},
		{"record process sample", "record_process_sample", "", true},
		// The make-or-break case: a kernel sensor event carries self_launched
		// via the matched binding's source, so the UI can show it as both
		// kernel_correlated AND self_launched.
		{"sensor matched record binding", "agentprov_ebpf", "zero_sdk_record", true},
		{"sensor matched descendant binding", "agentprov_ebpf", "zero_sdk_record_descendant", true},
		{"sensor matched control_exec binding", "agentprov_ebpf", "control_exec", true},
		{"sensor matched rollout binding", "agentprov_ebpf", "rollout_docker", true},
		// Ambiguous / externally-anchored binds must NOT claim self_launched.
		{"ai asserted binding", "agentprov_ebpf", "ai_asserted", false},
		{"generic control_plane default", "agentprov_ebpf", "control_plane", false},
		{"external falco event", "falco_jsonl", "", false},
	}
	for _, tc := range cases {
		if got := SelfLaunched(tc.source, tc.bindingSource); got != tc.want {
			t.Errorf("%s: SelfLaunched(%q,%q) = %v, want %v", tc.name, tc.source, tc.bindingSource, got, tc.want)
		}
	}
}
