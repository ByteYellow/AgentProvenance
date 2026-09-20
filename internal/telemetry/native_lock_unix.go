//go:build linux || darwin

package telemetry

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func nativeStreamRunning(path string) (bool, error) {
	f, err := lockNativeStream(path)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, f.Close()
}

func lockNativeStream(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("native collector already owns this store: %w", err)
	}
	return f, nil
}

func syncNativeDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
