package adapter

import (
	"fmt"
	"sort"
	"strings"
)

type Capability struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
	Level     string `json:"level"`
	Notes     string `json:"notes"`
}

type Adapter struct {
	Name         string       `json:"name"`
	Kind         string       `json:"kind"`
	Status       string       `json:"status"`
	Available    bool         `json:"available"`
	Boundary     string       `json:"boundary"`
	Inputs       []string     `json:"inputs"`
	Outputs      []string     `json:"outputs"`
	IdentityKeys []string     `json:"identity_keys"`
	Capabilities []Capability `json:"capabilities"`
	QBSImpact    []string     `json:"qbs_impact"`
	Notes        string       `json:"notes"`
}

func List() []Adapter {
	items := []Adapter{
		{
			Name:      "zero-sdk-record",
			Kind:      "agent",
			Status:    "available",
			Available: true,
			Boundary:  "wraps an arbitrary command and infers an execution scope from cwd, root process, time window, and file diff",
			Inputs:    []string{"command", "workdir", "run_id"},
			Outputs:   []string{"run", "attempt", "tool_call", "process", "record_manifest", "file_diff_events"},
			IdentityKeys: []string{
				"run_id", "attempt_id", "tool_call_id", "process_id", "root_pid", "cwd", "time_window",
			},
			Capabilities: []Capability{
				capability("execution_scope", true, "mvp", "creates a deterministic zero-SDK ToolCallScope for a command"),
				capability("file_diff", true, "mvp", "captures changed files relative to a base directory snapshot"),
				capability("process_tree", true, "shallow", "captures root process identity; deeper async descendants need hardening"),
				capability("llm_trace", false, "none", "white-box agent SDK trace is a separate future adapter"),
			},
			QBSImpact: []string{"execution cadence", "file diff volume", "process scope ambiguity"},
			Notes:     "Primary zero-SDK entry point for Phase 1.",
		},
		{
			Name:      "docker",
			Kind:      "sandbox",
			Status:    "available",
			Available: true,
			Boundary:  "creates and controls Docker-backed sandbox sessions and directory workspace state",
			Inputs:    []string{"image", "workspace", "network_mode", "cpu_request", "memory_mb"},
			Outputs:   []string{"container_id", "session_id", "workspace_path", "runtime_labels"},
			IdentityKeys: []string{
				"container_id", "session_id", "run_id", "lease_id",
			},
			Capabilities: []Capability{
				capability("create_session", true, "mvp", "Docker container lifecycle is active"),
				capability("exec", true, "mvp", "streaming exec is active"),
				capability("directory_snapshot", true, "mvp", "copy-based directory snapshot/fork/resume"),
				capability("memory_snapshot", false, "none", "Docker path does not claim memory-level snapshot or instant clone"),
				capability("isolation", true, "container", "namespace/cgroup/seccomp baseline, not a microVM boundary"),
			},
			QBSImpact: []string{"cold start latency", "copy-up I/O", "container density", "runtime identity quality"},
			Notes:     "Runtime substrate, not the product source of truth.",
		},
		{
			Name:      "filtered-jsonl",
			Kind:      "telemetry",
			Status:    "available",
			Available: true,
			Boundary:  "ingests filtered high-value runtime events and correlates them to execution context",
			Inputs:    []string{"raw_event_id", "container_id", "cgroup_id", "pid", "tgid", "ppid", "timestamp", "payload"},
			Outputs:   []string{"event", "runtime_edges", "correlation_method", "correlation_confidence"},
			IdentityKeys: []string{
				"process_id", "pid", "tgid", "ppid", "container_id", "cgroup_id", "timestamp",
			},
			Capabilities: []Capability{
				capability("exec_events", true, "mvp", "supports execve-style events"),
				capability("file_events", true, "mvp", "supports file_open/file_write-style events"),
				capability("network_events", true, "mvp", "supports network_connect-style events"),
				capability("jsonl_receivers", true, "mvp", "maps filtered Tetragon, Falco, and LoongCollector JSONL into normalized telemetry events"),
				capability("kernel_capture", false, "none", "does not run kernel probes; consumes already-filtered substrate output"),
				capability("kernel_filtering", false, "none", "expects upstream collectors to perform kernel-side filtering"),
			},
			QBSImpact: []string{"event volume", "correlation latency", "storage pressure", "query fanout"},
			Notes:     "Keeps raw runtime telemetry honest: raw events do not need tool_call_id.",
		},
		{
			Name:      "local-artifact",
			Kind:      "artifact",
			Status:    "available",
			Available: true,
			Boundary:  "references artifacts on the local filesystem and materializes content-addressed object metadata",
			Inputs:    []string{"path", "attempt_id", "tool_call_id"},
			Outputs:   []string{"artifact_ref", "sha256", "size_bytes", "provenance_object"},
			IdentityKeys: []string{
				"artifact_ref", "attempt_id", "tool_call_id", "sha256",
			},
			Capabilities: []Capability{
				capability("content_hash", true, "mvp", "computes sha256 during materialization"),
				capability("lineage", true, "mvp", "links artifact to attempt/tool_call/process through graph refs"),
				capability("remote_store", false, "none", "S3/object-store adapters are not implemented"),
			},
			QBSImpact: []string{"artifact count", "object-store writes", "diff/replay payload size"},
			Notes:     "Good enough for local demos and audit manifests.",
		},
		{
			Name:      "directory-copy",
			Kind:      "snapshot",
			Status:    "available",
			Available: true,
			Boundary:  "captures workspace state using directory copy semantics",
			Inputs:    []string{"workspace_path", "snapshot_name"},
			Outputs:   []string{"snapshot_id", "manifest_hash", "file_count", "bytes", "lineage"},
			IdentityKeys: []string{
				"snapshot_id", "manifest_hash", "parent_snapshot_id",
			},
			Capabilities: []Capability{
				capability("snapshot", true, "mvp", "directory snapshot is active"),
				capability("fork", true, "mvp", "fork creates independent attempt workspaces"),
				capability("resume", true, "mvp", "directory snapshot can resume into a running session"),
				capability("file_delta", true, "mvp", "diff/blame can compute file-level delta"),
				capability("cow_reflink", false, "none", "no reflink/overlay optimization is claimed"),
				capability("memory_snapshot", false, "none", "memory-level restore is not implemented"),
			},
			QBSImpact: []string{"copy I/O", "inode pressure", "snapshot storage bytes", "fanout cost"},
			Notes:     "Correctness-first state adapter; not a fast memory clone path.",
		},
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind == items[j].Kind {
			return items[i].Name < items[j].Name
		}
		return items[i].Kind < items[j].Kind
	})
	return items
}

func Inspect(name string) (Adapter, error) {
	for _, item := range List() {
		if item.Name == name {
			return item, nil
		}
	}
	return Adapter{}, fmt.Errorf("adapter %q is not registered", name)
}

func ListByKind(kind string) []Adapter {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return List()
	}
	var out []Adapter
	for _, item := range List() {
		if item.Kind == kind {
			out = append(out, item)
		}
	}
	return out
}

func capability(name string, supported bool, level, notes string) Capability {
	return Capability{Name: name, Supported: supported, Level: level, Notes: notes}
}
