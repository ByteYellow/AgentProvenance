//go:build linux || darwin

package handoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func acquirePublication(ctx context.Context, root string, exclusive bool) (*publicationLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(rfd), root)
	fd, err := unix.Openat(rfd, ".publication.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		dir.Close()
		return nil, err
	}
	lease := &publicationLease{dir: dir, lock: os.NewFile(uintptr(fd), ".publication.lock")}
	info, err := lease.lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		lease.Close()
		return nil, errors.Join(err, fmt.Errorf("publication lock is not a regular file"))
	}
	mode := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		mode = unix.LOCK_EX | unix.LOCK_NB
	}
	for {
		err = unix.Flock(fd, mode)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			lease.Close()
			return nil, err
		}
		if exclusive {
			lease.Close()
			return nil, errPublicationBusy
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			lease.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Staging owns a private tree, including its frozen database. Resolve children
// relative to the held directory; do not follow links or cross mounted devices.
func removePublicationStaging(ctx context.Context, parent *os.File, name string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	pfd := int(parent.Fd())
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	var original, base unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil {
		return 0, err
	}
	if err := unix.Fstat(pfd, &base); err != nil {
		return 0, err
	}
	if original.Dev != base.Dev {
		return 0, fmt.Errorf("publication staging crosses a mounted device")
	}
	var removed int64
	for {
		entries, err := dir.ReadDir(64)
		if err != nil && !errors.Is(err, io.EOF) {
			return removed, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return removed, err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return removed, err
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				n, err := removePublicationStaging(ctx, dir, entry.Name())
				removed += n
				if err != nil {
					return removed, err
				}
			case unix.S_IFREG:
				if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil {
					return removed, err
				}
				removed += stat.Size
			default:
				return removed, fmt.Errorf("unexpected publication staging entry: %s", entry.Name())
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return removed, err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(pfd, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return removed, err
	}
	if current.Dev != original.Dev || current.Ino != original.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return removed, fmt.Errorf("publication staging changed during cleanup")
	}
	if err := unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR); err != nil {
		return removed, err
	}
	return removed, unix.Fsync(pfd)
}
