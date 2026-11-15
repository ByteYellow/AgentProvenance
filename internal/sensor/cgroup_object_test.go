package sensor

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestCgroupIdentityObjectsRetainBoundedKernelNames(t *testing.T) {
	for _, arch := range []string{"arm64", "x86"} {
		t.Run(arch, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("sensorbpf_" + arch + "_bpfel.o")
			if err != nil {
				t.Fatal(err)
			}
			m := spec.Maps["cgroup_names"]
			if m == nil || m.Type != ebpf.LRUHash || m.KeySize != 8 || m.ValueSize != 3*96 || m.MaxEntries != 16384 {
				t.Fatalf("missing bounded kernel cgroup identity map: %+v", m)
			}
			for _, probe := range []string{"handle_fork", "handle_exec", "handle_exit", "handle_openat", "handle_open_return", "handle_connect", "handle_connect_return"} {
				program := spec.Programs[probe]
				if program == nil {
					t.Errorf("missing probe %s", probe)
					continue
				}
				found := false
				for _, instruction := range program.Instructions {
					if instruction.Reference() == "cgroup_names" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s does not capture kernel cgroup identity", probe)
				}
			}
		})
	}
}
