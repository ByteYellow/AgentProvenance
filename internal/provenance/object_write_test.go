package provenance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObjectWriteKeepsExistingBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "object.json")
	if err := writeObjectFile(path, []byte("saved")); err != nil {
		t.Fatal(err)
	}
	prior, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := writeObjectFile(path, []byte("saved")); err != nil {
		t.Fatalf("reuse immutable object: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(prior, after) || prior.ModTime() != after.ModTime() {
		t.Fatalf("unchanged object was rewritten: %v", err)
	}
	if err := writeObjectFile(path, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "replacement" {
		t.Fatalf("replacement: %q %v", raw, err)
	}
	blocked := filepath.Join(dir, "directory")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeObjectFile(blocked, []byte("replacement")); err == nil {
		t.Fatal("expected rename failure")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".object-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary objects leaked: %v %v", leftovers, err)
	}
}
