//go:build linux && (amd64 || arm64)

package sensor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLSOverlayResolvesSharedLowerAndDistinctCopyUp(t *testing.T) {
	root := t.TempDir()
	lower := filepath.Join(root, "lower")
	upper := filepath.Join(root, "upper")
	proc := filepath.Join(root, "proc")
	visible := filepath.Join(root, "mapped")
	for _, d := range []string{filepath.Join(lower, "lib"), filepath.Join(upper, "lib"), proc} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(lower, "lib/libssl.so.3")
	if err := os.WriteFile(base, []byte("shared"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(base, visible); err != nil {
		t.Fatal(err)
	}
	mounts := "1 0 0:99 / / rw - overlay overlay rw,lowerdir=" + lower + ",upperdir=" + upper + "\n"
	if err := os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(mounts), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := tlsBackingPath(proc, visible, "/lib/libssl.so.3")
	if err != nil || got != base {
		t.Fatalf("lower identity: %s %v", got, err)
	}
	copyUp := filepath.Join(upper, "lib/libssl.so.3")
	if err := os.WriteFile(copyUp, []byte("copied"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(visible); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(copyUp, visible); err != nil {
		t.Fatal(err)
	}
	got, err = tlsBackingPath(proc, visible, "/lib/libssl.so.3")
	if err != nil || got != copyUp {
		t.Fatalf("copy-up incorrectly shares lower probe: %s %v", got, err)
	}
}

func TestTLSOverlayHonorsMountRootAndRejectsUnknownIdentity(t *testing.T) {
	root := t.TempDir()
	lower := filepath.Join(root, "lower")
	proc := filepath.Join(root, "proc")
	visible := filepath.Join(root, "mapped")
	for _, d := range []string{filepath.Join(lower, "subroot"), proc} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(lower, "subroot/libssl.so.3")
	if err := os.WriteFile(base, []byte("same bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(base, visible); err != nil {
		t.Fatal(err)
	}
	mounts := "1 0 0:99 /subroot /opt rw - overlay overlay rw,lowerdir=" + lower + "\n"
	if err := os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(mounts), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := tlsBackingPath(proc, visible, "/opt/libssl.so.3")
	if err != nil || got != base {
		t.Fatalf("mount root ignored: %s %v", got, err)
	}
	if err := os.Remove(visible); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(visible, []byte("same bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsBackingPath(proc, visible, "/opt/libssl.so.3"); err == nil || !strings.Contains(err.Error(), "backing inode") {
		t.Fatalf("unrelated copied file deduplicated by content: %v", err)
	}
}

func TestTLSOverlayDoesNotFallThroughShadowingUpperFile(t *testing.T) {
	root := t.TempDir()
	lower := filepath.Join(root, "lower")
	upper := filepath.Join(root, "upper")
	proc := filepath.Join(root, "proc")
	visible := filepath.Join(root, "mapped")
	for _, d := range []string{lower, upper, proc} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(lower, "libssl.so.3")
	if err := os.WriteFile(base, []byte("shared"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(base, visible); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(upper, "libssl.so.3"), []byte("shared"), 0644); err != nil {
		t.Fatal(err)
	}
	mounts := "1 0 0:99 / / rw - overlay overlay rw,lowerdir=" + lower + ",upperdir=" + upper + "\n"
	if err := os.WriteFile(filepath.Join(proc, "mountinfo"), []byte(mounts), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsBackingPath(proc, visible, "/libssl.so.3"); err == nil || !strings.Contains(err.Error(), "shadowed") {
		t.Fatalf("attached hidden lower layer: %v", err)
	}
}
