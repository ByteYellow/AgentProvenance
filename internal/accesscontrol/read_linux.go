//go:build linux

package accesscontrol

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type procTask struct{ fd int }

func (p procTask) read(path string) ([]byte, error) {
	fd, err := unix.Openat(p.fd, path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if len(raw) > 16384 {
		return nil, errStateTooLarge
	}
	return raw, err
}

func (p procTask) link(path string) (string, error) {
	buf := make([]byte, 256)
	n, err := unix.Readlinkat(p.fd, path, buf)
	if n < 0 || n >= len(buf) {
		return "", errStateTooLarge
	}
	return string(buf[:n]), err
}

func (p procTask) cgroupID(path string) (string, error) {
	if filepath.Clean(path) != path || !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("invalid cgroup path")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return "", fmt.Errorf("host cgroup v2 mount unavailable")
	}
	var stat unix.Stat_t
	if err := unix.Stat("/sys/fs/cgroup"+path, &stat); err != nil {
		return "", err
	}
	return strconv.FormatUint(stat.Ino, 10), nil
}

// ReadTask pins a procfs task directory for the duration of the read, avoiding
// reopening a reused numeric PID between files. Its identity is procfs-native;
// it is deliberately not rewritten into a kernel-event lifetime ID.
func ReadTask(pid, tid int, opts Options) Snapshot {
	s := newSnapshot(pid, tid, opts)
	s.BootID = readSourceID("/proc/sys/kernel/random/boot_id", true)
	s.HostID = readSourceID("/proc/1/root/etc/machine-id", false)
	if pid < 1 || tid < 1 {
		s.Identity.Reason = "invalid_task_id"
		s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return s
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/task/%d", pid, tid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		s.Identity.Reason = readFailure(err)
		for _, state := range []*State{&s.AppArmor, &s.Seccomp} {
			if state.Status != "disabled" {
				state.Reason = s.Identity.Reason
			}
		}
		s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return s
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		s.Identity.Reason = "procfs_unavailable"
		s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return s
	}
	return readTask(procTask{fd}, s)
}

func readSourceID(path string, uuid bool) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(raw) > 256 {
		return ""
	}
	id := strings.ToLower(strings.TrimSpace(string(raw)))
	compact := id
	if uuid {
		if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			return ""
		}
		compact = strings.ReplaceAll(id, "-", "")
	}
	if len(compact) != 32 || compact == strings.Repeat("0", 32) {
		return ""
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return ""
	}
	return id
}
