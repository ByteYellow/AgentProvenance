package producer

import (
	"strings"
	"testing"
)

func TestProfileCapabilitiesAreDeclaredHonestly(t *testing.T) {
	// Every profile must declare all three layers so the capability report never
	// leaves a layer's coverage unstated.
	for _, p := range Profiles() {
		if p.Status != ProfileValidated && p.Status != ProfilePlanned {
			t.Fatalf("profile %q has invalid status %q", p.Name, p.Status)
		}
		for _, layer := range []Layer{LayerSystemTelemetry, LayerModelIntent, LayerAppContext} {
			cap, ok := p.Layers[layer]
			if !ok {
				t.Fatalf("profile %q does not declare layer %q", p.Name, layer)
			}
			if cap.Coverage != CoverageFull && cap.Note == "" {
				t.Errorf("profile %q layer %q is %q but gives no note explaining the limit", p.Name, layer, cap.Coverage)
			}
		}
	}
}

func TestK8sDaemonsetIsHonestAboutModelIntentAndScope(t *testing.T) {
	p := K8sDaemonset()
	if p.ScopeMode != ScopeModeCgroup {
		t.Fatalf("k8s-daemonset scope mode = %q, want %q", p.ScopeMode, ScopeModeCgroup)
	}
	if got := p.Layers[LayerModelIntent].Coverage; got != CoveragePartial {
		t.Errorf("k8s-daemonset model_intent = %q, want %q (TLS-stack dependent)", got, CoveragePartial)
	}
	if got := p.Layers[LayerSystemTelemetry].Coverage; got != CoverageFull {
		t.Errorf("k8s-daemonset system_telemetry = %q, want full (shared node kernel)", got)
	}
	// Passive cgroup scope must read as less certain than a record-launched one.
	if p.ScopeConfidence() != 0.8 {
		t.Errorf("k8s-daemonset scope confidence = %v, want 0.8", p.ScopeConfidence())
	}
}

func TestValidatedProfilesDescribeArchitectureSpecificTLSAndKVM(t *testing.T) {
	if !strings.Contains(LocalRecord().SensorPlacement, "KVM guest") {
		t.Fatal("local-record must include validated KVM guests")
	}
	for _, p := range []Profile{LocalRecord(), K8sDaemonset()} {
		note := p.Layers[LayerModelIntent].Note
		for _, required := range []string{"OpenSSL", "_ex", "amd64/arm64", "reads on amd64 Go 1.23-1.26", "HTTP/2/HPACK"} {
			if !strings.Contains(note, required) {
				t.Errorf("%s TLS note omits %q: %s", p.Name, required, note)
			}
		}
	}
	if strings.Contains(MicrovmGuestInit().Layers[LayerSystemTelemetry].Note, "no guest-init runner or live KVM acceptance") {
		t.Fatal("reserved guest-init profile must not misreport KVM support")
	}
}

func TestLocalRecordIsKernelVerifiedBaseline(t *testing.T) {
	p := LocalRecord()
	if p.Status != ProfileValidated || p.ScopeMode != ScopeModeRecord || p.ScopeConfidence() != 1 {
		t.Fatalf("local-record must be a kernel-verified baseline: mode=%q confidence=%v", p.ScopeMode, p.ScopeConfidence())
	}
}

func TestMicroVMProfileCannotReportUnvalidatedCapabilities(t *testing.T) {
	p := MicrovmGuestInit()
	if p.Status != ProfilePlanned || p.ScopeConfidence() != 0 {
		t.Fatalf("microvm profile status=%q confidence=%v, want planned/0", p.Status, p.ScopeConfidence())
	}
	for layer, capability := range p.Layers {
		if capability.Coverage != CoverageNone {
			t.Fatalf("planned microvm layer %q reports %q coverage", layer, capability.Coverage)
		}
		if capability.Note == "" {
			t.Fatalf("planned microvm layer %q must explain why it is unavailable", layer)
		}
	}
}

func TestCapabilityReportsExposeValidationAndConfidence(t *testing.T) {
	reports := CapabilityReports()
	if len(reports) != 3 {
		t.Fatalf("reports=%d, want 3", len(reports))
	}
	for _, report := range reports {
		if report.Name == "microvm-guest-init" && (report.Status != ProfilePlanned || report.ScopeConfidence != 0) {
			t.Fatalf("microvm report=%+v, want planned with zero confidence", report)
		}
	}
}
