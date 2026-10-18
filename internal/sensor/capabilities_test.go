package sensor

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestCapabilityReadyDoesNotHideOptionalFailure(t *testing.T) {
	var reports []CapabilityReport
	r := newCapabilityReporter(Options{Diagnostics: io.Discard, OnCapabilities: func(report CapabilityReport) { reports = append(reports, report) }})
	r.add(ProbeCapability{Name: "exec", Category: "syscall", Required: true, Status: "attached"})
	r.add(ProbeCapability{Name: "SSL_read_ex", Category: "tls", Status: "failed", Reason: "symbol missing"})
	r.publish(true)
	if len(reports) != 1 || !reports[0].Ready || reports[0].Status != "degraded" {
		t.Fatalf("optional failure hidden: %+v", reports)
	}
	if reports[0].Probes[1].Reason != "symbol missing" {
		t.Fatal("missing degradation reason")
	}
	r.publish(true)
	if len(reports) != 1 {
		t.Fatal("unchanged capability report was emitted repeatedly")
	}
}

func TestStateCapabilityReportsCollectionRatherThanKernelMode(t *testing.T) {
	var report CapabilityReport
	r := newCapabilityReporter(Options{AppArmorState: true, SeccompState: false, Diagnostics: io.Discard,
		OnCapabilities: func(got CapabilityReport) { report = got }})
	r.publish(true)
	if state := report.AccessControlState; state == nil || !state.AppArmor || state.Seccomp || state.QueueCapacity != stateQueueCapacity || state.CacheCapacity != stateCacheCapacity || state.MinIntervalMS != stateInterval.Milliseconds() {
		t.Fatalf("state reader settings missing: %+v", report)
	}
	raw, err := json.Marshal(report.AccessControlState)
	if err != nil || !strings.Contains(string(raw), `"apparmor_collection_enabled":true`) || !strings.Contains(string(raw), `"seccomp_collection_enabled":false`) || strings.Contains(string(raw), "enforce") {
		t.Fatalf("state collection confused with kernel policy: %s %v", raw, err)
	}
}

func TestCapabilityRequiredFailurePreventsReady(t *testing.T) {
	var report CapabilityReport
	r := newCapabilityReporter(Options{Diagnostics: io.Discard, OnCapabilities: func(got CapabilityReport) { report = got }})
	r.add(ProbeCapability{Name: "exec", Required: true, Status: "failed", Reason: "tracepoint missing"})
	r.publish(true)
	if report.Ready || report.Status != "degraded" {
		t.Fatalf("failed required probe reported ready: %+v", report)
	}
}

func TestCapabilityShutdownClearsReadyAndAttachedState(t *testing.T) {
	var report CapabilityReport
	r := newCapabilityReporter(Options{Diagnostics: io.Discard, OnCapabilities: func(got CapabilityReport) { report = got }})
	r.add(ProbeCapability{Name: "exec", Required: true, Status: "attached"})
	r.publish(true)
	r.finish(nil)
	if report.Ready || report.Status != "stopped" || report.Probes[0].Status != "detached" {
		t.Fatalf("stale ready report persisted: %+v", report)
	}
}
