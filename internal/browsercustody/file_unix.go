//go:build linux || darwin

package browsercustody

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// Walk from descriptors, following the B01 receiver-file boundary. Both the
// immediate parent and file must be private and owned by the current receiver.
func readPrivate(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, i18n.Errorf("browser custody config requires a clean absolute path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	dir := os.NewFile(uintptr(fd), filepath.Dir(path))
	defer dir.Close()
	private := func(info os.FileInfo, directory bool) bool {
		if info == nil {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && st.Nlink == 1))
	}
	info, err := dir.Stat()
	if err != nil || !private(info, true) {
		return nil, i18n.Errorf("browser custody config directory is not receiver-private")
	}
	fd, err = unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !private(before, false) || before.Size() <= 0 || before.Size() > 64<<10 {
		return nil, i18n.Errorf("browser custody config is not a private bounded regular file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !private(after, false) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != before.Size() {
		return nil, i18n.Errorf("browser custody config changed during read")
	}
	current, err := os.Lstat(path)
	canonical, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || resolveErr != nil || canonical != path || !private(current, false) || !os.SameFile(before, current) {
		return nil, i18n.Errorf("browser custody config was replaced during read")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}
