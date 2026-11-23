package companion

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseMatchedSiblingOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentprov-tools")
	data := []byte("tools fixture")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if _, err := verify(dir, digest); !errors.Is(err, Required) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	if v, err := verify(dir, digest); err != nil || v != path {
		t.Fatalf("valid sibling: %s %v", v, err)
	}
	if _, err := verify(dir, ""); !errors.Is(err, Required) {
		t.Fatal("unbound source build used a sibling")
	}
	if err := os.WriteFile(path, []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(dir, digest); err == nil {
		t.Fatal("replacement accepted")
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(dir, digest); err == nil {
		t.Fatal("link accepted")
	}
}
