package sensor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func configureProcfsNamespace(spec *ebpf.CollectionSpec) (*procfsResolver, error) {
	// A proc mount from another PID namespace would use different addresses.
	// Reject that configuration instead of opening a coincidentally equal PID.
	self, err := os.Readlink("/proc/self")
	if err != nil || strings.TrimSpace(self) != strconv.Itoa(os.Getpid()) {
		return nil, fmt.Errorf("procfs PID namespace does not match the collector")
	}
	f, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		return nil, fmt.Errorf("pin procfs PID namespace: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err == nil {
		// Numeric equality alone can be accidental after PID reuse. PID 1's
		// namespace identifies the proc mount's view independently of our PID.
		var view unix.Stat_t
		err = unix.Stat("/proc/1/ns/pid", &view)
		if err == nil && (view.Dev != st.Dev || view.Ino != st.Ino) {
			err = fmt.Errorf("proc mount and collector PID namespaces differ")
		}
		if err == nil {
			err = spec.RewriteConstants(map[string]interface{}{"proc_pidns_ino": st.Ino})
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("configure procfs identity: %w", err)
	}
	return &procfsResolver{namespace: f, report: ProcfsIdentityReport{
		Mode: "kernel_namespace_mapping", PIDNamespace: fmt.Sprintf("pid:[%d]", st.Ino), MapCapacity: 16384,
	}}, nil
}

func bindProcfsResolver(r *procfsResolver, objs *sensorbpfObjects) {
	r.lookup = func(key procTaskKey) (procTaskIDs, error) {
		var value struct{ PID, TID uint32 }
		err := objs.ProcTasks.Lookup(key, &value)
		return procTaskIDs{PID: value.PID, TID: value.TID}, err
	}
}
