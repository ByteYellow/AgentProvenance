package sensor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/ids"
)

type capabilityReporter struct {
	mu             sync.Mutex
	opts           Options
	base           []ProbeCapability
	tls            []ProbeCapability
	discovery      TLSDiscoveryReport
	procfs         *ProcfsIdentityReport
	ready          bool
	previous       string
	terminalStatus string
	terminalReason string
	producer       CapabilityProducer
	collectorID    string
	state          string
	revision       uint64
	changedAt      string
}

func newCapabilityReporter(opts Options) *capabilityReporter {
	placement, basis := opts.Placement, "operator_configuration"
	if placement == "" || placement == "local_kernel" {
		placement, basis = "local_kernel", "local_kernel_only"
	}
	p := CapabilityProducer{Name: "agentprov-sensor", Version: buildinfo.Version, Commit: buildinfo.Commit,
		OS: runtime.GOOS, Architecture: runtime.GOARCH, Placement: placement, PlacementBasis: basis}
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			p.Kernel = strings.TrimSpace(string(raw))
		}
		if raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
			p.BootID = strings.TrimSpace(string(raw))
		}
	}
	id := ids.New("sensor")
	if opts.Checkpointer != nil {
		id = opts.Checkpointer.epoch
	}
	return &capabilityReporter{opts: opts, producer: p, collectorID: id}
}

func ValidatePlacement(placement string) error {
	switch placement {
	case "", "local_kernel", "host_kernel", "guest_kernel":
		return nil
	default:
		return fmt.Errorf("sensor placement must be local_kernel, host_kernel or guest_kernel")
	}
}

func (r *capabilityReporter) add(probe ProbeCapability) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.base = append(r.base, probe)
}

func (r *capabilityReporter) publish(ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = ready
	r.publishLocked()
}

func (r *capabilityReporter) updateTLS(probes []ProbeCapability, discovery TLSDiscoveryReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tls, r.discovery = probes, discovery
	r.publishLocked()
}

func (r *capabilityReporter) finish(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = false
	r.terminalStatus = "stopped"
	if err != nil {
		r.terminalStatus = "failed"
		r.terminalReason = err.Error()
	}
	r.publishLocked()
}

func (r *capabilityReporter) updateProcfs(report ProcfsIdentityReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.procfs = &report
	r.publishLocked()
}

func (r *capabilityReporter) publishLocked() {
	report := CapabilityReport{
		SchemaVersion:     "agentprovenance.sensor_capabilities/v1",
		ObservationLimits: NativeObservationLimits(),
		Ready:             r.ready, Status: "starting", TLSDiscovery: r.discovery,
		Probes: append(append([]ProbeCapability{}, r.base...), r.tls...),
	}
	producer := r.producer
	report.Producer, report.CollectorID = &producer, r.collectorID
	if r.opts.RingBufferMiB > 0 {
		report.CaptureBuffers = &CaptureBufferReport{RingBytes: r.opts.RingBufferMiB << 20, QueueEvents: sensorQueueCapacity, QueueBytes: sensorQueueCapacity * sensorEventBytes}
	}
	report.AccessControlState = &StateCollectionCapability{AppArmor: r.opts.AppArmorState, Seccomp: r.opts.SeccompState,
		Mode: "event_triggered_procfs_snapshot", QueueCapacity: stateQueueCapacity, CacheCapacity: stateCacheCapacity, MinIntervalMS: stateInterval.Milliseconds()}
	if r.procfs != nil {
		copy := *r.procfs
		report.ProcfsIdentity = &copy
	}
	sort.Slice(report.Probes, func(i, j int) bool {
		a, b := report.Probes[i], report.Probes[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Name < b.Name
	})
	if r.ready {
		report.Status = "ready"
	}
	for _, p := range report.Probes {
		if p.Status == "failed" || p.Status == "unsupported" {
			if r.ready {
				report.Status = "degraded"
			}
			if p.Required {
				report.Ready = false
				report.Status = "degraded"
			}
		}
	}
	if r.discovery.HasGaps() {
		report.Status = "degraded"
	}
	if r.procfs != nil && r.procfs.LookupMisses > 0 {
		report.Status = "degraded"
	}
	if r.terminalStatus != "" {
		report.Ready = false
		report.Status = r.terminalStatus
		report.Reason = r.terminalReason
		for i := range report.Probes {
			if report.Probes[i].Status == "attached" {
				report.Probes[i].Status = "detached"
			}
		}
		report.TLSDiscovery.ActiveTargets = 0
	}
	encoded, _ := json.Marshal(report)
	if string(encoded) == r.previous {
		return
	}
	r.previous = string(encoded)
	report.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	state, _ := capabilityState(report)
	if string(state) != r.state {
		r.revision++
		r.changedAt, r.state = report.UpdatedAt, string(state)
	}
	report.Revision, report.ChangedAt = r.revision, r.changedAt
	encoded, _ = json.Marshal(report)
	out := r.opts.Diagnostics
	if out == nil {
		out = os.Stderr
	}
	if out != io.Discard {
		_, _ = fmt.Fprintf(out, "agentprov-sensor: capabilities %s\n", encoded)
		if r.opts.Language == i18n.Chinese {
			PrintCapabilities(out, report, r.opts.Language)
		}
	}
	if r.opts.OnCapabilities != nil {
		r.opts.OnCapabilities(report)
	}
}

// Counters remain in live snapshots and capture boundaries. A new history
// revision describes a capability change, not each increment of a counter.
func capabilityState(report CapabilityReport) ([]byte, error) {
	d := report.TLSDiscovery
	report.UpdatedAt, report.ChangedAt, report.Revision = "", "", 0
	report.TLSDiscovery = TLSDiscoveryReport{Enabled: d.Enabled, ScanIntervalMS: d.ScanIntervalMS,
		MaxTargets: d.MaxTargets, MaxProcessesPerScan: d.MaxProcessesPerScan,
		ScanComplete: d.ScanComplete, Reason: d.Reason, Limitations: d.Limitations}
	if d.HasGaps() {
		report.TLSDiscovery.SkippedTargets = 1
	}
	if p := report.ProcfsIdentity; p != nil {
		copy := *p
		copy.TranslatedEvents, copy.OutsideNamespace, copy.LookupMisses = 0, 0, 0
		if p.LookupMisses > 0 {
			copy.LookupMisses = 1
		}
		report.ProcfsIdentity = &copy
	}
	return json.Marshal(report)
}
