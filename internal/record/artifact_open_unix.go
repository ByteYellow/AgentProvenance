//go:build linux || darwin

package record

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Open each component relative to its already-open directory, without following
// links. NONBLOCK avoids hanging on a FIFO substituted by an agent process.
func openArtifactFile(root, path string) (*os.File, error) {
	if !filepath.IsLocal(path) || filepath.Clean(path) == "." {
		return nil, fmt.Errorf("invalid artifact path")
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
