//go:build !darwin && !linux

package derivedview

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Non-Unix hosts use the same immutable-snapshot FS contract as VerifyFS.
func openDirectory(root string) (fs.FS, func() error, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode().Type() != fs.ModeDir {
		return nil, nil, fmt.Errorf("%w: root must be a non-symlink directory", ErrUnsafe)
	}
	return os.DirFS(root), func() error { return nil }, nil
}
