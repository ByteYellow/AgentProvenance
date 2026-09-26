package sensor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

type capabilityReporter struct {
	mu             sync.Mutex
	opts           Options
	base           []ProbeCapability
	tls            []ProbeCapability
	discovery      TLSDiscoveryReport
	ready          bool
	previous       string
	terminalStatus string
	terminalReason string
}

func newCapabilityReporter(opts Options) *capabilityReporter {
	return &capabilityReporter{opts: opts}
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

func (r *capabilityReporter) publishLocked() {
	report := CapabilityReport{
		SchemaVersion: "agentprovenance.sensor_capabilities/v1",
		Ready:         r.ready, Status: "starting", TLSDiscovery: r.discovery,
		Probes: append(append([]ProbeCapability{}, r.base...), r.tls...),
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
	if r.discovery.Enabled && (r.discovery.Reason != "" || r.discovery.SkippedTargets > 0 || r.discovery.UnreadableProcesses > 0 || r.discovery.TruncatedMaps > 0 || r.discovery.UnsupportedExecutables > 0) {
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
