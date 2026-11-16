//go:build linux || darwin

package agentcontext

import (
	"context"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func openBrowserOwnedDirectory(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, browserImportError("directory_unavailable")
	}
	// Walk relative to open descriptors; even intermediate symlinks are rejected.
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, browserImportError("directory_unavailable")
		}
		fd = next
	}
	directory := os.NewFile(uintptr(fd), path)
	info, err := directory.Stat()
	if err != nil || !privateBrowserFile(info, true) {
		directory.Close()
		return nil, browserImportError("directory_not_private")
	}
	return directory, nil
}

func privateBrowserFile(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o077 == 0 &&
		((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && stat.Nlink == 1))
}

func checkBrowserOwnedDirectory(original *os.File, path string) error {
	current, err := openBrowserOwnedDirectory(path)
	if err != nil {
		return err
	}
	defer current.Close()
	a, ea := original.Stat()
	b, eb := current.Stat()
	if ea != nil || eb != nil || !os.SameFile(a, b) || !privateBrowserFile(a, true) {
		return browserImportError("directory_changed")
	}
	return nil
}

type browserContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r browserContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func readBrowserOwnedFile(ctx context.Context, dir *os.File, name string, prefix, limit int64) ([]byte, error) {
	open := func() (*os.File, error) {
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, browserImportError("file_unavailable")
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	file, err := open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !privateBrowserFile(before, false) {
		return nil, browserImportError("file_not_private_regular")
	}
	want := prefix
	if want == 0 {
		want = before.Size()
	}
	if want <= 0 || want > limit || before.Size() < want {
		return nil, browserImportError("file_size_invalid")
	}
	raw, err := io.ReadAll(browserContextReader{ctx, io.NewSectionReader(file, 0, want)})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, browserImportError("file_read_failed")
	}
	after, err := file.Stat()
	if err != nil || !privateBrowserFile(after, false) || int64(len(raw)) != want || !os.SameFile(before, after) ||
		after.Size() < want || (prefix == 0 && (after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()))) {
		return nil, browserImportError("file_changed")
	}
	current, err := open()
	if err != nil {
		return nil, err
	}
	defer current.Close()
	info, err := current.Stat()
	if err != nil || !privateBrowserFile(info, false) || !os.SameFile(before, info) {
		return nil, browserImportError("file_replaced")
	}
	return raw, nil
}
