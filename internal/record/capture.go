package record

import (
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/buildinfo"
)

const CaptureSchema = "agentprovenance.record_capture/v1"

// CaptureReport describes this recorder's polling and final file snapshots.
// A separate native collector retains its own capabilities and loss counters.
type CaptureReport struct {
	SchemaVersion    string              `json:"schema_version"`
	RunID            string              `json:"run_id"`
	AttemptID        string              `json:"attempt_id"`
	SessionID        string              `json:"session_id"`
	ToolCallID       string              `json:"tool_call_id"`
	ProcessID        string              `json:"process_id"`
	CgroupID         string              `json:"cgroup_id"`
	ScopeKind        string              `json:"scope_kind"`
	Producer         CaptureProducer     `json:"producer"`
	Boundary         string              `json:"boundary"`
	Status           string              `json:"status"`
	ObservedAt       string              `json:"observed_at"`
	StartedAt        string              `json:"started_at,omitempty"`
	EndedAt          string              `json:"ended_at,omitempty"`
	SampleIntervalMS int64               `json:"sample_interval_ms"`
	PostRootGraceMS  int64               `json:"post_root_grace_ms"`
	WorkspaceFiles   bool                `json:"workspace_files"`
	Sampling         *ProcessSampling    `json:"sampling,omitempty"`
	FileCapture      *FileCaptureSummary `json:"file_capture,omitempty"`
	BindingFailures  uint64              `json:"binding_failures"`
	EventFailures    uint64              `json:"event_failures"`
	Issues           []string            `json:"issues"`
}

type CaptureProducer struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Kernel       string `json:"kernel,omitempty"`
	BootID       string `json:"boot_id,omitempty"`
}

type ProcessSampling struct {
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at"`
	Attempts  uint64 `json:"attempts"`
	Failures  uint64 `json:"failures"`
}

type FileCaptureSummary struct {
	Status  string `json:"status"`
	Stored  int    `json:"stored"`
	Omitted int    `json:"omitted"`
	Failed  int    `json:"failed"`
}

func newCapture(scope ExecutionScope, snapshot bool, interval, grace time.Duration) CaptureReport {
	p := CaptureProducer{Name: "agentprov-record", Version: buildinfo.Version, Commit: buildinfo.Commit, OS: runtime.GOOS, Architecture: runtime.GOARCH}
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			p.Kernel = strings.TrimSpace(string(raw))
		}
		if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
			p.BootID = strings.TrimSpace(string(raw))
		}
	}
	return CaptureReport{SchemaVersion: CaptureSchema, RunID: scope.RunID, AttemptID: scope.AttemptID,
		SessionID: scope.SessionID, ToolCallID: scope.ToolCallID, ProcessID: scope.ProcessID, CgroupID: scope.CgroupID, ScopeKind: scope.ScopeKind,
		Producer: p, Boundary: "start", Status: "recording", ObservedAt: scope.StartedAt, StartedAt: scope.StartedAt,
		SampleIntervalMS: interval.Milliseconds(), PostRootGraceMS: grace.Milliseconds(), WorkspaceFiles: snapshot, Issues: []string{}}
}

func (c *CaptureReport) finish(at, boundary string, sampling *ProcessSampling, files *ArtifactCaptureReport) {
	c.ObservedAt, c.EndedAt, c.Boundary, c.Status = time.Now().UTC().Format(time.RFC3339Nano), at, boundary, "stopped"
	c.Sampling = sampling
	if sampling != nil && sampling.Failures > 0 {
		c.Issues = append(c.Issues, "process_table_read_failed")
	}
	if c.BindingFailures > 0 {
		c.Issues = append(c.Issues, "sample_binding_write_failed")
	}
	if c.EventFailures > 0 {
		c.Issues = append(c.Issues, "sample_event_write_failed")
	}
	if files != nil {
		c.FileCapture = &FileCaptureSummary{Status: files.Status, Stored: files.Stored, Omitted: files.Omitted, Failed: files.Failed}
		if files.Status == "partial" || files.Status == "failed" {
			c.Issues = append(c.Issues, "file_capture_"+files.Status)
		}
	}
	if len(c.Issues) > 0 {
		c.Status = "partial"
	}
}
