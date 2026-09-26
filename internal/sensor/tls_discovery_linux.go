//go:build linux && (amd64 || arm64)

package sensor

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

const maxProcessMapsBytes = 1 << 20
const maxELFSymbolBytes = 16 << 20

type tlsTarget struct{ Key, Path, Kind, Reason string }
type executableKind struct {
	kind        string
	unsupported bool
}

type tlsProcessScanner struct {
	root                     string
	maxProcesses, maxTargets int
	dir                      *os.File
	// A sweep may span multiple ticks. Keep only the configured maximum targets
	// and executable classifications so process churn cannot grow memory.
	seen  map[string]tlsTarget
	cache map[string]executableKind
	stats TLSDiscoveryReport
}

func newTLSProcessScanner(root string, maxProcesses, maxTargets int) *tlsProcessScanner {
	return &tlsProcessScanner{root: root, maxProcesses: maxProcesses, maxTargets: maxTargets, seen: map[string]tlsTarget{}, cache: map[string]executableKind{}}
}

func (s *tlsProcessScanner) close() {
	if s.dir != nil {
		_ = s.dir.Close()
		s.dir = nil
	}
}

func (s *tlsProcessScanner) scan() (map[string]tlsTarget, TLSDiscoveryReport) {
	if s.dir == nil {
		var err error
		s.dir, err = os.Open(s.root)
		s.seen = map[string]tlsTarget{}
		s.stats = TLSDiscoveryReport{}
		if err != nil {
			s.stats.Reason = "read process directory: " + err.Error()
			return s.seen, s.stats
		}
	}
	// The directory cursor remains open across bounded scans. This avoids
	// starving later PIDs when a node has more processes than the scan budget.
	for remaining := s.maxProcesses; remaining > 0; {
		n := remaining
		if n > 128 {
			n = 128
		}
		names, err := s.dir.Readdirnames(n)
		remaining -= len(names)
		for _, name := range names {
			pid, parseErr := strconv.Atoi(name)
			if parseErr != nil || pid <= 0 || (s.root == "/proc" && pid == os.Getpid()) {
				continue
			}
			s.stats.ProcessesScanned++
			s.scanProcess(name)
		}
		if err != nil {
			if err != io.EOF {
				s.stats.Reason = "enumerate processes: " + err.Error()
			}
			s.stats.ScanComplete = err == io.EOF
			s.close()
			break
		}
	}
	return s.seen, s.stats
}

func (s *tlsProcessScanner) add(path, kind string) {
	key, err := tlsFileIdentity(path)
	if err != nil {
		return
	} // The process or its mount may have already gone.
	key = kind + ":" + key
	if _, exists := s.seen[key]; exists {
		s.seen[key] = tlsTarget{Key: key, Path: path, Kind: kind}
		return
	}
	if len(s.seen) >= s.maxTargets {
		s.stats.SkippedTargets++
		return
	}
	s.seen[key] = tlsTarget{Key: key, Path: path, Kind: kind}
}

func (s *tlsProcessScanner) scanProcess(pid string) {
	base := filepath.Join(s.root, pid)
	maps, err := os.Open(filepath.Join(base, "maps"))
	if err != nil {
		// Normal exit races are not a permissions degradation.
		if !os.IsNotExist(err) {
			s.stats.UnreadableProcesses++
		}
	} else {
		limited := &io.LimitedReader{R: maps, N: maxProcessMapsBytes + 1}
		lines := bufio.NewScanner(limited)
		lines.Buffer(make([]byte, 4096), 64<<10)
		for lines.Scan() {
			fields := strings.Fields(lines.Text())
			if len(fields) < 6 || !strings.Contains(fields[1], "x") {
				continue
			}
			path := strings.Join(fields[5:], " ")
			deleted := strings.HasSuffix(path, " (deleted)")
			path = strings.TrimSuffix(path, " (deleted)")
			name := filepath.Base(path)
			if !strings.HasPrefix(name, "libssl.so") && !strings.HasPrefix(name, "libssl-") {
				continue
			}
			if !strings.HasPrefix(path, "/") {
				continue
			}
			candidate := filepath.Join(base, "root", path)
			if deleted {
				candidate = filepath.Join(base, "map_files", fields[0])
			}
			backing, err := tlsBackingPath(base, candidate, path)
			if err != nil {
				s.stats.UnresolvedMounts++
				s.stats.Reason = capabilityFailure(err)
				continue
			}
			s.add(backing, "openssl")
		}
		if limited.N == 0 || lines.Err() != nil {
			s.stats.TruncatedMaps++
		}
		_ = maps.Close()
	}
	path := filepath.Join(base, "exe")
	namespacePath, err := os.Readlink(path)
	if err != nil {
		return
	}
	backing, err := tlsBackingPath(base, path, namespacePath)
	if err != nil {
		s.stats.UnresolvedMounts++
		s.stats.Reason = capabilityFailure(err)
		return
	}
	path = backing
	key, err := tlsFileIdentity(path)
	if err != nil {
		return
	}
	kind, cached := s.cache[key]
	if !cached {
		kind = classifyTLSExecutable(path)
		// Eviction affects performance only; every process is still revisited.
		if len(s.cache) >= s.maxProcesses {
			for old := range s.cache {
				delete(s.cache, old)
				break
			}
		}
		s.cache[key] = kind
	}
	if kind.unsupported {
		s.stats.UnsupportedExecutables++
	}
	if kind.kind != "" {
		s.add(path, kind.kind)
	}
}

// Inode and device identify the object to which uprobes attach. Size and mtime
// distinguish replaced/rebuilt files. PID, pathname and container ID alone do
// not: many containers share one mapped inode, and PIDs/pathnames are reused.
func tlsFileIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return "", i18n.Errorf("not a regular Linux file")
	}
	return fmt.Sprintf("%x:%x:%d:%d", st.Dev, st.Ino, info.Size(), info.ModTime().UnixNano()), nil
}

func classifyTLSExecutable(path string) executableKind {
	if err := validateELFMetadata(path); err != nil {
		return executableKind{unsupported: true}
	}
	f, err := elf.Open(path)
	if err != nil {
		return executableKind{}
	}
	defer f.Close()
	for _, section := range f.Sections {
		if (section.Type == elf.SHT_SYMTAB || section.Type == elf.SHT_DYNSYM) && section.Size > maxELFSymbolBytes {
			return executableKind{unsupported: true}
		}
	}
	syms, symErr := f.Symbols()
	if dyn, err := f.DynamicSymbols(); err == nil {
		syms = append(syms, dyn...)
	}
	for _, symbol := range syms {
		if symbol.Section == elf.SHN_UNDEF || symbol.Value == 0 || elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
			continue
		}
		if symbol.Name == "crypto/tls.(*Conn).Write" {
			return executableKind{kind: "go"}
		}
		if symbol.Name == "SSL_write" || symbol.Name == "SSL_write_ex" {
			return executableKind{kind: "openssl"}
		}
	}
	if symErr != nil {
		if _, err := buildinfo.ReadFile(path); err == nil {
			return executableKind{kind: "go", unsupported: true}
		}
	}
	return executableKind{}
}
