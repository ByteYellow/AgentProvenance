package sensor

import (
	"io"
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
