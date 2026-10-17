package sensor

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestOpenSSLReadObjectUsesThreadStacks(t *testing.T) {
	for _, arch := range []string{"arm64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("sensorbpf_" + arch + "_bpfel.o")
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ssl_read_bufs", "ssl_read_ex_bufs"} {
				m := spec.Maps[name]
				if m == nil || m.Type != ebpf.Hash || m.KeySize != 8 || m.ValueSize != 176 || m.MaxEntries != 4096 {
					t.Fatalf("%s must hold bounded, lifetime-aware stacks keyed by pid_tgid: %+v", name, m)
				}
			}
			m := spec.Maps["ssl_epochs"]
			if m == nil || m.Type != ebpf.LRUHash || m.KeySize != 24 || m.ValueSize != 8 || m.MaxEntries != 16384 {
				t.Fatalf("missing bounded OpenSSL lifetime map: %+v", m)
			}
			for _, name := range []string{"handle_ssl_read_enter", "handle_ssl_read_exit", "handle_ssl_read_ex_enter", "handle_ssl_read_ex_exit", "handle_exit", "handle_exec", "handle_ssl_new", "handle_ssl_reset", "handle_ssl_release", "handle_go_tls_write"} {
				if spec.Programs[name] == nil {
					t.Errorf("missing probe %s", name)
				}
			}
		})
	}
}
