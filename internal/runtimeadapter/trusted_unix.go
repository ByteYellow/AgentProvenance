//go:build linux || darwin

package runtimeadapter

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// ValidateTrustedPath rejects symlinks and writable ancestors. Execution
// configuration and runtime state must be outside caller-controlled mounts.
func ValidateTrustedPath(name string, directory bool) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return fmt.Errorf("trusted runtime path must be clean and absolute")
	}
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime configuration and state require root-owned, non-writable, non-symlink paths")
		}
		wantDir := current != name || directory
		if wantDir && !info.IsDir() || !wantDir && !info.Mode().IsRegular() {
			return fmt.Errorf("invalid trusted runtime path type")
		}
		if current == "/" {
			return nil
		}
	}
}

func ReadTrustedFile(name string, limit int64) ([]byte, error) {
	f, err := openTrustedFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(raw)) > limit {
		return nil, fmt.Errorf("runtime configuration file exceeds limit")
	}
	return raw, err
}

func readTrustedTail(name string, limit int64) ([]byte, error) {
	f, err := openTrustedFile(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := max(int64(0), info.Size()-limit)
	return io.ReadAll(io.NewSectionReader(f, start, info.Size()-start))
}

func openTrustedFile(name string) (*os.File, error) {
	if err := ValidateTrustedPath(name, false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		f.Close()
		return nil, fmt.Errorf("untrusted runtime configuration file")
	}
	return f, nil
}

// The parent directory was created 0700 by this invocation inside the trusted
// state directory. Reject a runtime-written symlink or special file as well.
func readPrivatePID(name string) ([]byte, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 64 {
		return nil, fmt.Errorf("invalid runtime task PID file")
	}
	return io.ReadAll(io.LimitReader(f, 65))
}
