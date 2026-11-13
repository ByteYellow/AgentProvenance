//go:build linux || darwin

package handoff

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockExecutor(root string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(root, ".execution.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("execution store already has an owner: %w", err)
	}
	return f, nil
}
