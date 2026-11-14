//go:build linux || darwin

package handoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/store"
	"golang.org/x/sys/unix"
)

func removeDeliveryPackage(ctx context.Context, paths store.Paths, bundle string) (int64, error) {
	root, err := filepath.Abs(filepath.Join(paths.Artifacts, "execution-deliveries"))
	if err != nil {
		return 0, err
	}
	dir := filepath.Dir(bundle)
	name := filepath.Base(dir)
	if !filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle || filepath.Base(bundle) != "bundle.json" ||
		filepath.Dir(dir) != root || !strings.HasPrefix(name, "package-") || name == "package-" {
		return 0, fmt.Errorf("delivery package is outside its owned transfer directory")
	}
	rfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	rootDir := os.NewFile(uintptr(rfd), root)
	defer rootDir.Close()
	return removeDeliveryPackageAt(ctx, rootDir, name)
}

func removeDeliveryPackageAt(ctx context.Context, root *os.File, name string) (int64, error) {
	rfd := int(root.Fd())
	fd, err := unix.Openat(rfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, unix.Fsync(rfd)
	}
	if err != nil {
		return 0, err
	}
	directory := os.NewFile(uintptr(fd), name)
	defer directory.Close()
	entries, err := directory.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	for _, entry := range entries {
		if (entry.Name() != "bundle.json" && entry.Name() != "manifest.dsse.json") || !entry.Type().IsRegular() {
			return 0, fmt.Errorf("unexpected entry in delivery package: %s", entry.Name())
		}
	}
	var original unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil {
		return 0, err
	}
	var removed int64
	for _, file := range []string{"bundle.json", "manifest.dsse.json"} {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		var stat unix.Stat_t
		err := unix.Fstatat(fd, file, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return removed, err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return removed, fmt.Errorf("delivery package entry is not a regular file")
		}
		err = unix.Unlinkat(fd, file, 0)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return removed, err
		}
		if err == nil {
			removed += stat.Size
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return removed, err
	}
	var current unix.Stat_t
	err = unix.Fstatat(rfd, name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if current.Dev != original.Dev || current.Ino != original.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
			return removed, fmt.Errorf("delivery directory changed during cleanup")
		}
		err = unix.Unlinkat(rfd, name, unix.AT_REMOVEDIR)
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return removed, err
	}
	return removed, unix.Fsync(rfd)
}
