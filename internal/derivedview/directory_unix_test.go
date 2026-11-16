//go:build darwin || linux

package derivedview

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDescriptorRelativeOpenRejectsReplacedAncestors(t *testing.T) {
	files, _, _, _ := fixture(t)
	root := writeDirectory(t, files)
	fsys, closeRoot, err := openDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRoot()
	if err := os.Rename(filepath.Join(root, "reader"), filepath.Join(root, "old-reader")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "old-reader"), filepath.Join(root, "reader")); err != nil {
		t.Fatal(err)
	}
	if f, err := fsys.Open("reader/assets/app.js"); err == nil {
		f.Close()
		t.Fatal("followed a substituted directory symlink")
	}
}

func TestNativeFIFOIsRejectedWithoutBlocking(t *testing.T) {
	files, _, _, policy := fixture(t)
	root := writeDirectory(t, files)
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), root, policy, Limits{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	fsys, closeRoot, err := openDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRoot()
	if f, err := openChecked(fsys, "fifo", nil); err == nil {
		f.Close()
		t.Fatal("opened nonregular data")
	}
}
