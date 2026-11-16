//go:build darwin || linux

package derivedview

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Resolve each component relative to a pinned descriptor. O_NONBLOCK prevents
// a concurrently substituted FIFO from hanging before the regular-file check.
type directoryFS struct{ root *os.File }

func openDirectory(root string) (fs.FS, func() error, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open directory: %v", ErrUnsafe, err)
	}
	f := os.NewFile(uintptr(fd), root)
	return directoryFS{root: f}, f.Close, nil
}

func (d directoryFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, fs.ErrInvalid
	}
	parent := int(d.root.Fd())
	var owned int = -1
	defer func() {
		if owned >= 0 {
			unix.Close(owned)
		}
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 || name == "." {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, part, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: open %q: %v", ErrUnsafe, name, err)
		}
		if owned >= 0 {
			unix.Close(owned)
		}
		if i == len(parts)-1 {
			owned = -1
			return os.NewFile(uintptr(fd), filepath.Join(d.root.Name(), filepath.FromSlash(name))), nil
		}
		parent, owned = fd, fd
	}
	return nil, fs.ErrInvalid
}
