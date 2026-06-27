//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	eventExec    = 1
	eventConnect = 2
	eventOpen    = 3
	eventExit    = 4
	eventSSL     = 5
	eventSSLRead = 6
)

// Options configures optional sensor probes beyond the always-on syscall set.
type Options struct {
	// SSLLib, when set, attaches the PoC SSL_write uprobe to this libssl path to
	// capture TLS plaintext (the agent's LLM request body) zero-instrumentation.
	SSLLib string
}

// Run loads the eBPF probes (exec/connect/openat), reads events from the ring
// buffer, enriches each with a container id derived from the task's cgroup, and
// writes one normalized telemetry event per line (JSONL) to out. It blocks until
// SIGINT/SIGTERM. Requires root or CAP_BPF + CAP_PERFMON.
func Run(out io.Writer) error {
	return RunWithOptions(out, Options{})
}

// RunWithOptions is Run with optional extra probes (see Options).
func RunWithOptions(out io.Writer, opts Options) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	defer tpExec.Close()
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_execve: %w", err)
	}
	defer tpExecve.Close()
	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_connect: %w", err)
	}
	defer tpConnect.Close()
	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach sys_enter_openat: %w", err)
	}
	defer tpOpen.Close()
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exit: %w", err)
	}
	defer tpExit.Close()
	if opts.SSLLib != "" {
		ex, err := link.OpenExecutable(opts.SSLLib)
		if err != nil {
			return fmt.Errorf("open ssl lib %s: %w", opts.SSLLib, err)
		}
		upSSL, err := ex.Uprobe("SSL_write", objs.HandleSslWrite, nil)
		if err != nil {
			return fmt.Errorf("attach SSL_write uprobe on %s: %w", opts.SSLLib, err)
		}
		defer upSSL.Close()
		upReadEnter, err := ex.Uprobe("SSL_read", objs.HandleSslReadEnter, nil)
		if err != nil {
			return fmt.Errorf("attach SSL_read uprobe on %s: %w", opts.SSLLib, err)
		}
		defer upReadEnter.Close()
		upReadExit, err := ex.Uretprobe("SSL_read", objs.HandleSslReadExit, nil)
		if err != nil {
			return fmt.Errorf("attach SSL_read uretprobe on %s: %w", opts.SSLLib, err)
		}
		defer upReadExit.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	resolver := newCgroupResolver()
	enc := json.NewEncoder(out)
	var encMu sync.Mutex
	emit := func(v any) {
		encMu.Lock()
		_ = enc.Encode(v)
		encMu.Unlock()
	}

	// Surface ring-buffer drops as a coverage-gap event so a loaded sensor is
	// never silently blind.
	done := make(chan struct{})
	defer close(done)
	go watchDrops(objs.Drops, emit, done)

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}
		var e sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		emit(normalize(e, resolver))
	}
}

// watchDrops polls the kernel drop counter and emits a resource_pressure event
// whenever it grows, so downstream sees a coverage gap rather than missing data.
func watchDrops(m dropLookuper, emit func(any), done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			var n uint64
			if err := m.Lookup(uint32(0), &n); err != nil || n <= last {
				continue
			}
			emit(map[string]any{
				"source":        "agentprov_ebpf",
				"event_type":    "resource_pressure",
				"resource":      "sensor_ringbuf",
				"signal":        "event_drop",
				"dropped":       n,
				"dropped_delta": n - last,
				"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
			})
			last = n
		}
	}
}

// dropLookuper is the subset of *ebpf.Map used to read the drop counter (kept as
// an interface so the poller is unit-testable without a live map).
type dropLookuper interface {
	Lookup(key, valueOut any) error
}

// cgroupResolver maps the kernel-reported cgroup id (race-free, captured in
// kernel via bpf_get_current_cgroup_id) to a container id by directory inode.
// The container's cgroup directory outlives its short-lived processes, so this
// survives a process whose /proc entry is already gone by the time userspace
// drains the ring buffer - the failure mode of the previous /proc-only lookup.
type cgroupResolver struct {
	root string
	mu   sync.RWMutex
	byID map[uint64]string
}

func newCgroupResolver() *cgroupResolver {
	return &cgroupResolver{root: "/sys/fs/cgroup", byID: map[uint64]string{}}
}

// resolve returns the container id for a kernel cgroup id, refreshing the cache
// once on a miss (a newly seen container's cgroup dir appears between scans).
func (r *cgroupResolver) resolve(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	r.mu.RLock()
	id, ok := r.byID[cgroupID]
	r.mu.RUnlock()
	if ok {
		return id
	}
	r.refresh()
	r.mu.RLock()
	id = r.byID[cgroupID]
	r.mu.RUnlock()
	return id
}

// refresh walks the cgroup v2 hierarchy and maps each container cgroup
// directory's inode (== the kernel cgroup id) to the 64-hex container id parsed
// from its name (docker-<id>.scope, cri-containerd-<id>.scope, kubepods/<id>...).
func (r *cgroupResolver) refresh() {
	next := map[uint64]string{}
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		m := dockerCgroupRe.FindString(d.Name())
		if m == "" {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			next[uint64(st.Ino)] = m
		}
		return nil
	})
	r.mu.Lock()
	r.byID = next
	r.mu.Unlock()
}

// normalize maps a raw kernel event to the normalized telemetry schema consumed
// by `telemetry ingest` (container_id, cgroup_id, pid/tgid/ppid, source,
// event_type, payload). container_id is best-effort from /proc/<pid>/cgroup.
func normalize(e sensorbpfSensorEvent, resolver *cgroupResolver) map[string]any {
	// Prefer the race-free cgroup-id -> container-id resolution; the /proc lookup
	// is a fallback for the live process and for hosts where the cgroup dir name
	// does not carry the id.
	containerID := resolver.resolve(e.CgroupId)
	if containerID == "" {
		containerID = containerIDForPID(e.Pid)
	}
	ev := map[string]any{
		"source":       "agentprov_ebpf",
		"pid":          e.Pid,
		"tgid":         e.Tgid,
		"ppid":         e.Ppid,
		"cgroup_id":    strconv.FormatUint(e.CgroupId, 10),
		"container_id": containerID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
		"comm":         cstr(e.Comm[:]),
	}
	switch e.Kind {
	case eventExec:
		ev["event_type"] = "execve"
		ev["path"] = cstr(e.Path[:])
		if command := joinArgs(e.Args[:]); command != "" {
			ev["command"] = command
		}
	case eventConnect:
		ev["event_type"] = "network_connect"
		ev["dst_ip"] = ipv4(e.Daddr)
		ev["dst_port"] = ntohs(e.Dport)
	case eventOpen:
		ev["event_type"] = "file_open"
		ev["path"] = cstr(e.Path[:])
	case eventExit:
		ev["event_type"] = "process_exit"
		ev["exit_code"] = e.ExitCode
	case eventSSL:
		ev["event_type"] = "tls_write"
		ev["data"] = cstr(e.Path[:]) // plaintext preview (first path[] bytes)
		ev["length"] = e.ExitCode
	case eventSSLRead:
		ev["event_type"] = "tls_read"
		ev["data"] = cstr(e.Path[:])
		ev["length"] = e.ExitCode
	default:
		ev["event_type"] = "unknown"
	}
	return ev
}

// dockerCgroupRe extracts a 64-hex container id from a cgroup path line.
var dockerCgroupRe = regexp.MustCompile(`[0-9a-f]{64}`)

func containerIDForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	if m := dockerCgroupRe.Find(data); m != nil {
		return string(m)
	}
	return ""
}

func ipv4(addr uint32) string {
	// addr is network byte order (big-endian) as read from the kernel.
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ntohs(p uint16) uint16 {
	return (p<<8)&0xff00 | p>>8
}

// joinArgs rejoins the fixed-size argv slots emitted by the eBPF side (MAX_ARGS
// slots of ARG_SLOT bytes, each a NUL-terminated, possibly truncated arg) into a
// single space-separated command line, stopping at the first empty slot. These
// constants must match exec.c (ARG_SLOT, MAX_ARGS).
func joinArgs(b []uint8) string {
	const slot = 32
	const maxArgs = 16
	parts := make([]string, 0, maxArgs)
	for i := 0; i < maxArgs; i++ {
		start := i * slot
		if start >= len(b) {
			break
		}
		end := start + slot
		if end > len(b) {
			end = len(b)
		}
		s := cstr(b[start:end])
		if s == "" {
			break
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func cstr(b []uint8) string {
	if i := bytes.IndexByte(byteSlice(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(byteSlice(b))
}

func byteSlice(b []uint8) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = byte(v)
	}
	return out
}
