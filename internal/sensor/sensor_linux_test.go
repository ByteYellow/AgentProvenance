//go:build linux

package sensor

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestCgroupResolverResolvesByInode verifies the race-free path: a container's
// cgroup directory inode (== the kernel cgroup id) resolves to the 64-hex
// container id parsed from the dir name, independent of any live process.
func TestCgroupResolverResolvesByInode(t *testing.T) {
	root := t.TempDir()
	const cid = "8975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	dir := filepath.Join(root, "system.slice", "docker-"+cid+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	cgroupID := uint64(st.Ino)

	r := &cgroupResolver{root: root, byID: map[uint64]string{}}
	if got := r.resolve(cgroupID); got != cid {
		t.Fatalf("resolve(%d) = %q, want %q", cgroupID, got, cid)
	}
	// Unknown cgroup id and zero resolve to empty (caller falls back to /proc).
	if got := r.resolve(cgroupID + 999999); got != "" {
		t.Fatalf("resolve(unknown) = %q, want empty", got)
	}
	if got := r.resolve(0); got != "" {
		t.Fatalf("resolve(0) = %q, want empty", got)
	}
}

func TestCgroupResolverRefreshesOnInterval(t *testing.T) {
	root := t.TempDir()
	r := &cgroupResolver{root: root, byID: map[uint64]string{}, refreshInterval: time.Hour}
	if got := r.resolve(123); got != "" {
		t.Fatalf("resolve before container = %q, want empty", got)
	}

	const cid = "1975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	dir := filepath.Join(root, "kubepods.slice", "cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if got := r.resolve(uint64(st.Ino)); got != "" {
		t.Fatalf("resolve before refresh interval = %q, want empty", got)
	}

	r.mu.Lock()
	r.lastRefresh = time.Now().Add(-2 * time.Hour)
	r.mu.Unlock()
	if got := r.resolve(uint64(st.Ino)); got != cid {
		t.Fatalf("resolve after refresh interval = %q, want %q", got, cid)
	}
}

func TestCgroupResolverRetainsDepartedIdentityWithinBoundedTTL(t *testing.T) {
	root := t.TempDir()
	const cid = "8975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	dir := filepath.Join(root, "cri-containerd-"+cid+".scope")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := uint64(info.Sys().(*syscall.Stat_t).Ino)
	r := &cgroupResolver{root: root, byID: map[uint64]string{}, retention: time.Minute, maxEntries: 2}
	r.refresh()
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	r.refresh()
	if got := r.resolve(id); got != cid {
		t.Fatalf("departed identity lost before delayed drain: %q", got)
	}
	r.mu.Lock()
	r.seenAt[id] = time.Now().Add(-2 * time.Minute)
	r.mu.Unlock()
	r.refresh()
	if got := r.resolve(id); got != "" {
		t.Fatalf("expired identity retained forever: %q", got)
	}
}

func TestCgroupResolverUsesCapturedKernelNameAfterProcessAndDirectoryExit(t *testing.T) {
	const cid = "8975174628cc0b9585d08bae7dfc65d661e8d307fa01f9d905685139cc0135ab"
	calls := 0
	r := &cgroupResolver{root: t.TempDir(), maxEntries: 2, kernelName: func(id uint64) string {
		calls++
		if id == 42 {
			return "cri-containerd-" + cid + ".scope"
		}
		return "system.slice"
	}}
	if got := r.resolve(42); got != cid {
		t.Fatalf("kernel-captured identity ignored: %q", got)
	}
	if got := r.resolve(42); got != cid || calls != 1 {
		t.Fatalf("resolved identity not cached: %q calls=%d", got, calls)
	}
	if got := r.resolve(43); got != "" {
		t.Fatalf("host cgroup attributed as container: %q", got)
	}
	for id := uint64(100); id < 110; id++ {
		r.remember(id, cid)
	}
	if len(r.byID) > 2 || len(r.seenAt) > 2 {
		t.Fatalf("kernel fallback grew unbounded: %d %d", len(r.byID), len(r.seenAt))
	}
}

type fixedDropMap uint64

func (m fixedDropMap) Lookup(_ any, out any) error { *(out.(*uint64)) = uint64(m); return nil }

func TestDropWatcherReportsFinalDropsBeforeFiveSecondTick(t *testing.T) {
	done := make(chan struct{})
	close(done)
	var emitted []map[string]any
	watchDrops(fixedDropMap(7), func(value any) { emitted = append(emitted, value.(map[string]any)) }, done)
	if len(emitted) != 1 || emitted[0]["dropped_delta"] != uint64(7) {
		t.Fatalf("shutdown silently lost kernel drops: %+v", emitted)
	}
}
