//go:build linux || darwin

package telemetry

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openAuditLog(path string) (*os.File, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		f.Close()
		return nil, "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, "", fmt.Errorf("audit source must be a regular append-only file")
	}
	return f, fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

func lockAuditReader(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit reader is already active or its lock is unavailable: %w", err)
	}
	return f, nil
}
