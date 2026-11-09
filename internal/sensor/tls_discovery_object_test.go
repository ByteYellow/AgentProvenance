package sensor

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestTLSDiscoveryObjectsBoundHintsAndAllowDisabling(t *testing.T) {
	for _, arch := range []string{"arm64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("sensorbpf_" + arch + "_bpfel.o")
			if err != nil {
				t.Fatal(err)
			}
			m := spec.Maps["tls_discovery_seen"]
			if m == nil || m.Type != ebpf.LRUHash || m.KeySize != 16 || m.ValueSize != 8 || m.MaxEntries != 4096 {
				t.Fatalf("unbounded or PID-only discovery hints: %+v", m)
			}
			for _, enabled := range []uint32{0, 1} {
				if err := spec.Copy().RewriteConstants(map[string]interface{}{"tls_auto_discovery": enabled}); err != nil {
					t.Fatalf("automatic discovery setting %d: %v", enabled, err)
				}
			}
		})
	}
}
