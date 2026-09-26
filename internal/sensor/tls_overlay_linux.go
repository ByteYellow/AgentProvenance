//go:build linux && (amd64 || arm64)

package sensor

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"golang.org/x/sys/unix"
)

// overlay mounts can expose distinct virtual device IDs for the SAME lower
// inode. Global uprobes resolve that lower inode, so attaching once per virtual
// device duplicates plaintext. Resolve the mapped file to its actual backing
// inode, retaining distinct copied-up files and distinct executable copies.
func tlsBackingPath(procBase, visiblePath, namespacePath string) (string, error) {
	f, err := os.Open(filepath.Join(procBase, "mountinfo"))
	if err != nil {
		return "", i18n.Errorf("read TLS target mount identity: %w", err)
	}
	defer f.Close()
	reader := &io.LimitedReader{R: f, N: 1 << 20}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	namespacePath = strings.TrimSuffix(namespacePath, " (deleted)")
	bestMount, bestRoot, bestType, bestOptions := "", "", "", ""
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		mount := mountUnescape(left[4])
		if namespacePath != mount && !strings.HasPrefix(namespacePath, strings.TrimSuffix(mount, "/")+"/") {
			continue
		}
		if len(mount) < len(bestMount) {
			continue
		}
		bestMount, bestRoot, bestType, bestOptions = mount, mountUnescape(left[3]), right[0], right[2]
	}
	if scanner.Err() != nil || reader.N == 0 {
		return "", i18n.Errorf("TLS mountinfo exceeded bounded scan")
	}
	if bestMount == "" {
		return "", i18n.Errorf("TLS file mount identity was not found")
	}
	if bestType != "overlay" {
		return visiblePath, nil
	}
	info, err := os.Stat(visiblePath)
	if err != nil {
		return "", err
	}
	mapped, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", i18n.Errorf("TLS file has no Linux inode identity")
	}
	var upper string
	var lower []string
	for _, option := range strings.Split(bestOptions, ",") {
		if strings.HasPrefix(option, "upperdir=") {
			upper = mountUnescape(strings.TrimPrefix(option, "upperdir="))
		}
		if strings.HasPrefix(option, "lowerdir=") {
			for _, dir := range strings.Split(strings.TrimPrefix(option, "lowerdir="), ":") {
				lower = append(lower, mountUnescape(dir))
			}
		}
		// With metacopy the upper metadata inode can refer to lower data; do
		// not guess which object the kernel's uprobe implementation will use.
		if option == "metacopy=on" {
			return "", i18n.Errorf("overlay metacopy TLS backing identity unsupported")
		}
	}
	if len(lower) > 128 {
		return "", i18n.Errorf("overlay TLS lower-layer count exceeds 128")
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(namespacePath, bestMount), "/")
	relative = filepath.Join(strings.TrimPrefix(bestRoot, "/"), relative)
	layers := append([]string{}, lower...)
	if upper != "" {
		layers = append([]string{upper}, layers...)
	}
	for _, layer := range layers {
		if !filepath.IsAbs(layer) {
			continue
		}
		backing := filepath.Join(layer, relative)
		// A sensor DaemonSet shares host PIDs but not necessarily its mount
		// namespace. PID1's root makes host containerd snapshot paths visible.
		readableLayer := false
		for _, candidate := range []string{filepath.Join("/proc/1/root", backing), backing} {
			layerRoot := layer
			if strings.HasPrefix(candidate, "/proc/1/root/") {
				layerRoot = filepath.Join("/proc/1/root", layer)
			}
			layerInfo, err := os.Stat(layerRoot)
			if err != nil {
				continue
			}
			if !layerInfo.IsDir() {
				return "", i18n.Errorf("overlay TLS layer is not a directory")
			}
			readableLayer = true
			candidateInfo, statErr := os.Stat(candidate)
			// /proc/1/root may be inaccessible to an unprivileged host caller;
			// try the same host snapshot path in this mount namespace then.
			if os.IsPermission(statErr) {
				continue
			}
			if statErr != nil && !os.IsNotExist(statErr) {
				return "", i18n.Errorf("read overlay TLS backing layer: %w", statErr)
			}
			if err := checkOverlayMetadata(candidate, layerRoot); err != nil {
				return "", err
			}
			if statErr != nil {
				continue
			}
			st, ok := candidateInfo.Sys().(*syscall.Stat_t)
			if !ok || !candidateInfo.Mode().IsRegular() {
				return "", i18n.Errorf("overlay TLS backing object is not a regular file")
			}
			// Exact inode equality is conservative: unfamiliar xino/metacopy
			// layouts degrade explicitly instead of guessing by content hash
			// and conflating independently copied executable files.
			if st.Ino != mapped.Ino || candidateInfo.Size() != info.Size() || !candidateInfo.ModTime().Equal(info.ModTime()) {
				return "", i18n.Errorf("overlay TLS backing inode mismatch in visible layer; refusing shadowed lower attachment")
			}
			return candidate, nil
		}
		if !readableLayer {
			return "", i18n.Errorf("overlay TLS backing layer inaccessible; refusing to guess a lower inode")
		}
	}
	return "", i18n.Errorf("cannot resolve overlay TLS backing inode; refusing duplicate global attachments")
}

func mountUnescape(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				result.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		result.WriteByte(s[i])
	}
	return result.String()
}

// Directory redirects, opaque directories and metacopy need overlay-specific
// interpretation. Refuse those cases instead of attaching a shadowed file.
func checkOverlayMetadata(path, root string) error {
	var value [256]byte
	for depth := 0; depth < 64; depth++ {
		for _, name := range []string{"trusted.overlay.opaque", "user.overlay.opaque", "trusted.overlay.redirect", "user.overlay.redirect", "trusted.overlay.metacopy", "user.overlay.metacopy"} {
			n, err := unix.Getxattr(path, name, value[:])
			if err == nil && n > 0 && string(value[:n]) != "n" {
				return i18n.Errorf("overlay TLS %s metadata unsupported", name)
			}
			if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTSUP) {
				return i18n.Errorf("inspect overlay TLS metadata: %w", err)
			}
		}
		if path == root {
			return nil
		}
		next := filepath.Dir(path)
		if next == path {
			return nil
		}
		path = next
	}
	return i18n.Errorf("overlay TLS path exceeds 64 metadata levels")
}
