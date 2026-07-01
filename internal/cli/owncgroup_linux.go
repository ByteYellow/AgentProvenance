//go:build linux

package cli

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ownCgroupID returns this process's cgroup v2 id -- the cgroup directory inode,
// which is exactly the value the eBPF sensor emits (bpf_get_current_cgroup_id).
// The sensor stream uses it to exclude its own process's activity from capture.
// Returns "" if it cannot be determined (correlation simply won't self-exclude
// by cgroup, and the path-based data-dir exclusion still applies).
func ownCgroupID() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// cgroup v2 unified line: "0::<path>".
		fields := strings.SplitN(line, ":", 3)
		if len(fields) == 3 && fields[0] == "0" {
			rel = fields[2]
			break
		}
	}
	if rel == "" {
		return ""
	}
	info, err := os.Stat("/sys/fs/cgroup" + rel)
	if err != nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(st.Ino, 10)
}
