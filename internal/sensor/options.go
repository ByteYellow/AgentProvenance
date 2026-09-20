package sensor

import (
	"context"
	"io"
	"time"
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
	// for mapped OpenSSL libraries and Go TLS executables. Polling cannot capture
	// a process that starts and exits entirely between scans.
	AutoTLS         bool
	TLSScanInterval time.Duration
	TLSMaxTargets   int
	TLSMaxProcesses int
	// Diagnostics receives capability changes as JSON prefixed with
	// "agentprov-sensor: capabilities ". Nil defaults to stderr.
	Diagnostics io.Writer
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
	Enabled                bool     `json:"enabled"`
	ScanIntervalMS         int64    `json:"scan_interval_ms"`
	MaxTargets             int      `json:"max_targets"`
	MaxProcessesPerScan    int      `json:"max_processes_per_scan"`
	ActiveTargets          int      `json:"active_targets"`
	ScanComplete           bool     `json:"scan_complete"`
	ProcessesScanned       int      `json:"processes_scanned"`
	UnreadableProcesses    int      `json:"unreadable_processes"`
	UnresolvedMounts       int      `json:"unresolved_mounts"`
	TruncatedMaps          int      `json:"truncated_maps"`
	SkippedTargets         int      `json:"skipped_targets"`
	UnsupportedExecutables int      `json:"unsupported_executables"`
	Reason                 string   `json:"reason,omitempty"`
	Limitations            []string `json:"limitations"`
}

type CapabilityReport struct {
	SchemaVersion string             `json:"schema_version"`
	UpdatedAt     string             `json:"updated_at"`
	Ready         bool               `json:"ready"`
	Status        string             `json:"status"` // starting, ready, degraded, stopped, or failed
	Reason        string             `json:"reason,omitempty"`
	Probes        []ProbeCapability  `json:"probes"`
	TLSDiscovery  TLSDiscoveryReport `json:"tls_discovery"`
}
