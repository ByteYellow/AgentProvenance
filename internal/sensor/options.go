package sensor

import (
	"context"
	"io"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// Options configures the native sensor. Optional probe failures are reported as
// degraded coverage; OnReady only promises the required syscall probes and the
// ring-buffer reader are active, not that every TLS implementation is covered.
type Options struct {
	SSLLib   string
	LibcLib  string
	GoTLSBin string
	Context  context.Context
	OnReady  func()
	// AutoTLS scans visible processes, including container mount namespaces,
	// for mapped OpenSSL libraries and Go TLS executables. Bounded event-driven
	// discovery supplements polling; first use can still precede attachment.
	AutoTLS         bool
	TLSScanInterval time.Duration
	TLSMaxTargets   int
	TLSMaxProcesses int
	// State readers use procfs independently of eBPF. Snapshots are timestamped
	// observations of a task, never syscall verdicts or kernel lifetime aliases.
	AppArmorState bool
	SeccompState  bool
	// Diagnostics receives capability changes as JSON prefixed with
	// "agentprov-sensor: capabilities ". Nil defaults to stderr.
	Diagnostics io.Writer
	// Language controls additional human diagnostics. Protocol lines and the
	// capability callback remain unchanged, including their original reasons.
	Language i18n.Locale
	// OnCapabilities receives bounded snapshots on state changes. Callbacks must
	// return promptly; callers may persist the latest snapshot for health APIs.
	OnCapabilities func(CapabilityReport)
}

type ProbeCapability struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Target   string `json:"target,omitempty"`
	Required bool   `json:"required"`
	Status   string `json:"status"` // attached, detached, failed, disabled, or unsupported
	Reason   string `json:"reason,omitempty"`
}

type TLSDiscoveryReport struct {
	Enabled                bool                     `json:"enabled"`
	ScanIntervalMS         int64                    `json:"scan_interval_ms"`
	MaxTargets             int                      `json:"max_targets"`
	MaxProcessesPerScan    int                      `json:"max_processes_per_scan"`
	ActiveTargets          int                      `json:"active_targets"`
	ScanComplete           bool                     `json:"scan_complete"`
	ProcessesScanned       int                      `json:"processes_scanned"`
	UnreadableProcesses    int                      `json:"unreadable_processes"`
	UnresolvedMounts       int                      `json:"unresolved_mounts"`
	TruncatedMaps          int                      `json:"truncated_maps"`
	SkippedTargets         int                      `json:"skipped_targets"`
	UnsupportedExecutables int                      `json:"unsupported_executables"`
	Reason                 string                   `json:"reason,omitempty"`
	Limitations            []string                 `json:"limitations"`
	SweepPasses            uint64                   `json:"sweep_passes"`
	EventDiscovery         *TLSEventDiscoveryReport `json:"event_discovery,omitempty"`
}

type TLSEventDiscoveryReport struct {
	QueueCapacity          int    `json:"queue_capacity"`
	Pending                int    `json:"pending"`
	Hints                  uint64 `json:"hints"`
	Coalesced              uint64 `json:"coalesced"`
	QueueDrops             uint64 `json:"queue_drops"`
	ProcessScans           uint64 `json:"process_scans"`
	RetryScans             uint64 `json:"retry_scans"`
	ExitedProcesses        uint64 `json:"exited_processes"`
	ChangedProcesses       uint64 `json:"changed_processes"`
	UnreadableProcesses    uint64 `json:"unreadable_processes"`
	UnresolvedMounts       uint64 `json:"unresolved_mounts"`
	TruncatedMaps          uint64 `json:"truncated_maps"`
	UnsupportedExecutables uint64 `json:"unsupported_executables"`
	SkippedTargets         uint64 `json:"skipped_targets"`
	AttachedTargets        uint64 `json:"attached_targets"`
	LastAttachLatencyMS    int64  `json:"last_attach_latency_ms"`
	MaxAttachLatencyMS     int64  `json:"max_attach_latency_ms"`
}

// HasGaps includes discovery failures, not normal process exits or PID/exec
// changes. Counters in EventDiscovery cover the sensor lifetime.
func (d TLSDiscoveryReport) HasGaps() bool {
	if !d.Enabled {
		return false
	}
	if d.Reason != "" || d.SkippedTargets > 0 || d.UnreadableProcesses > 0 || d.UnresolvedMounts > 0 || d.TruncatedMaps > 0 || d.UnsupportedExecutables > 0 {
		return true
	}
	e := d.EventDiscovery
	return e != nil && (e.QueueDrops > 0 || e.UnreadableProcesses > 0 || e.UnresolvedMounts > 0 || e.TruncatedMaps > 0 || e.SkippedTargets > 0 || e.UnsupportedExecutables > 0)
}

type CapabilityReport struct {
	SchemaVersion      string                     `json:"schema_version"`
	UpdatedAt          string                     `json:"updated_at"`
	Ready              bool                       `json:"ready"`
	Status             string                     `json:"status"` // starting, ready, degraded, stopped, or failed
	Reason             string                     `json:"reason,omitempty"`
	Probes             []ProbeCapability          `json:"probes"`
	TLSDiscovery       TLSDiscoveryReport         `json:"tls_discovery"`
	AccessControlState *StateCollectionCapability `json:"access_control_state,omitempty"`
}

type StateCollectionCapability struct {
	AppArmor      bool   `json:"apparmor_collection_enabled"`
	Seccomp       bool   `json:"seccomp_collection_enabled"`
	Mode          string `json:"mode"`
	QueueCapacity int    `json:"queue_capacity"`
	CacheCapacity int    `json:"cache_capacity"`
	MinIntervalMS int64  `json:"min_interval_ms"`
}
