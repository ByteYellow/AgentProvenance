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
	s.scanAt(base)
}

func (s *tlsProcessScanner) scanAt(base string) {
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

// The kernel hint selects a PID to inspect, not an execution attribution. Read
// one pinned proc directory and check its independently observed identity on
// both sides of the scan. Attachment still verifies the discovered file inode.
func (s *tlsProcessScanner) scanPID(pid uint32, previous tlsProcessIdentity) (map[string]tlsTarget, TLSDiscoveryReport, tlsProcessIdentity, error) {
	base := filepath.Join(s.root, strconv.FormatUint(uint64(pid), 10))
	dir, err := os.Open(base)
	if err != nil {
		return nil, TLSDiscoveryReport{}, previous, err
	}
	defer dir.Close()
	pinned := fmt.Sprintf("/proc/self/fd/%d", dir.Fd())
	before, err := tlsProcIdentity(pinned, pid)
	if err != nil {
		return nil, TLSDiscoveryReport{}, previous, err
	}
	if previous.ticks != "" && previous != before {
		return nil, TLSDiscoveryReport{}, before, errTLSProcessChanged
	}
	part := &tlsProcessScanner{root: s.root, maxProcesses: s.maxProcesses, maxTargets: s.maxTargets,
		seen: map[string]tlsTarget{}, cache: s.cache}
	part.scanAt(pinned)
	after, err := tlsProcIdentity(pinned, pid)
	if err != nil {
		return nil, part.stats, before, err
	}
	if before != after {
		return nil, part.stats, after, errTLSProcessChanged
	}
	for key, target := range part.seen {
		target.Path = strings.Replace(target.Path, pinned+"/", base+"/", 1)
		part.seen[key] = target
	}
	return part.seen, part.stats, before, nil
}

var errTLSProcessChanged = fmt.Errorf("TLS discovery process changed during observation")

func tlsProcIdentity(base string, pid uint32) (tlsProcessIdentity, error) {
	f, err := os.Open(filepath.Join(base, "stat"))
	if err != nil {
		return tlsProcessIdentity{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	_ = f.Close()
	if err != nil {
		return tlsProcessIdentity{}, err
	}
	left, right := strings.IndexByte(string(raw), '('), strings.LastIndexByte(string(raw), ')')
	if len(raw) > 8192 || left <= 0 || right <= left || strings.TrimSpace(string(raw[:left])) != strconv.FormatUint(uint64(pid), 10) {
		return tlsProcessIdentity{}, errTLSProcessChanged
	}
	fields := strings.Fields(string(raw[right+1:]))
	if len(fields) < 20 {
		return tlsProcessIdentity{}, errTLSProcessChanged
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return tlsProcessIdentity{}, errTLSProcessChanged
	}
	exe, err := tlsFileIdentity(filepath.Join(base, "exe"))
	if err != nil {
		return tlsProcessIdentity{}, err
	}
	return tlsProcessIdentity{ticks: fields[19], executable: exe}, nil
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
		if offsets, err := opensslDynamicOffsets(path); err == nil && (offsets["SSL_write"] != 0 || offsets["SSL_write_ex"] != 0) {
			return executableKind{kind: "openssl"}
		}
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
