//go:build linux

package sensor

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
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
