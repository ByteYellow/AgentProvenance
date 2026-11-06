//go:build linux && (amd64 || arm64)

package sensor

import (
	"errors"
	"io"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
	"github.com/cilium/ebpf"
)

func TestProcfsMappingKeepsKernelEvidenceAndTaskLifetime(t *testing.T) {
	e := sensorbpfSensorEvent{Kind: eventOpen, Pid: 9001, Tid: 9002, ThreadStartNs: 200, ProcessStartNs: 100}
	r := &procfsResolver{report: ProcfsIdentityReport{PIDNamespace: "pid:[123]"}, lookup: func(key procTaskKey) (procTaskIDs, error) {
		if key.Start != 200 || key.PIDTGID != uint64(9001)<<32|9002 {
			t.Fatalf("lost task lifetime: %+v", key)
		}
		return procTaskIDs{PID: 41, TID: 42}, nil
	}}
	ids := r.resolve(e)
	if ids.PID != 41 || ids.TID != 42 || r.report.TranslatedEvents != 1 {
		t.Fatalf("mapping: %+v %+v", ids, r.report)
	}
	for _, m := range []map[string]any{normalize(e, newCgroupResolver(), ids), tlsMessageMap(tlsintent.Message{}, e, newCgroupResolver(), ids)} {
		if m["pid"] != uint32(9001) || m["tid"] != uint32(9002) || m["procfs_pid"] != uint32(41) || m["procfs_tid"] != uint32(42) || m["procfs_pid_namespace"] != "pid:[123]" {
			t.Fatalf("kernel identity changed or procfs identity missing: %+v", m)
		}
	}
	// The same numeric IDs with a different lifetime must not hit the old entry.
	r.lookup = func(key procTaskKey) (procTaskIDs, error) {
		return procTaskIDs{}, errors.New("evicted or different lifetime")
	}
	e.ThreadStartNs++
	if ids = r.resolve(e); ids.PID != 0 || ids.TID != 0 || r.report.LookupMisses != 1 {
		t.Fatal("missing mapping fell back to a numeric kernel PID")
	}
	m := normalize(e, newCgroupResolver(), ids)
	if _, ok := m["procfs_pid"]; ok {
		t.Fatal("invented procfs identity")
	}
	var report CapabilityReport
	reporter := newCapabilityReporter(Options{Diagnostics: io.Discard, OnCapabilities: func(v CapabilityReport) { report = v }})
	reporter.publish(true)
	r.publish(reporter, true)
	if report.Status != "degraded" || report.ProcfsIdentity.LookupMisses != 1 {
		t.Fatal("mapping gap hidden")
	}
}

func TestProcfsOutsideNamespaceIsExplicit(t *testing.T) {
	r := &procfsResolver{lookup: func(procTaskKey) (procTaskIDs, error) { return procTaskIDs{}, nil }}
	ids := r.resolve(sensorbpfSensorEvent{Pid: 51, Tid: 51, ThreadStartNs: 10})
	if ids.PID != 0 || r.report.OutsideNamespace != 1 || r.report.LookupMisses != 0 {
		t.Fatalf("outside namespace: %+v", r.report)
	}
}

func TestProcfsObjectMapIsBoundedAndLifetimeKeyed(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("sensorbpf_x86_bpfel.o")
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["proc_tasks"]
	if m == nil || m.Type != ebpf.LRUHash || m.MaxEntries != 16384 || m.KeySize != 16 || m.ValueSize != 8 {
		t.Fatalf("unsafe procfs map: %+v", m)
	}
	if err := spec.RewriteConstants(map[string]interface{}{"proc_pidns_ino": uint64(123)}); err != nil {
		t.Fatal(err)
	}
}

func TestProcfsCacheBoundsAndExitEviction(t *testing.T) {
	lookups := 0
	r := &procfsResolver{lookup: func(k procTaskKey) (procTaskIDs, error) { lookups++; return procTaskIDs{PID: 1, TID: 2}, nil }}
	e := sensorbpfSensorEvent{Pid: 1, Tid: 2, ThreadStartNs: 10}
	r.resolve(e)
	r.resolve(e)
	if lookups != 1 {
		t.Fatalf("repeated task lookup=%d", lookups)
	}
	e.Kind = eventThreadExit
	r.resolve(e)
	if len(r.cache) != 0 {
		t.Fatal("exited thread retained")
	}
	e.Kind = eventOpen
	for i := uint64(1); i <= 10000; i++ {
		e.ThreadStartNs = i
		r.resolve(e)
		if len(r.cache) > 4096 {
			t.Fatal("unbounded task cache")
		}
	}
	e.ThreadStartNs = 0
	r.resolve(e)
	if _, ok := r.cache[procTaskKey{0, uint64(1)<<32 | 2}]; ok {
		t.Fatal("cached incomplete identity")
	}
}
