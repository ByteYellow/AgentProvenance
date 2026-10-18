package sensor

import (
	"github.com/cilium/ebpf"
	"testing"
)

func TestSyscallResultObjectsHaveBoundedThreadState(t *testing.T) {
	for _, arch := range []string{"arm64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("sensorbpf_" + arch + "_bpfel.o")
			if err != nil {
				t.Fatal(err)
			}
			m := spec.Maps["syscall_calls"]
			if m == nil || m.Type != ebpf.Hash || m.KeySize != 8 || m.MaxEntries != 4096 || m.ValueSize > 512 {
				t.Fatalf("unbounded or process-only syscall state: %+v", m)
			}
			for _, probe := range []string{"handle_connect", "handle_connect_return", "handle_openat", "handle_open_return", "handle_exit", "handle_exec"} {
				if spec.Programs[probe] == nil {
					t.Errorf("missing %s", probe)
				}
			}
		})
	}
}
