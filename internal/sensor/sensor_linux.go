//go:build linux && (amd64 || arm64)

package sensor

import (
	"bytes"
	"context"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/tlsintent"
	"github.com/cilium/ebpf"
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
	eventSetuid  = 7
	eventPtrace  = 8
	eventRename  = 9
	eventUnlink  = 10
	eventDNS     = 11
)

type sensorTracepoint struct {
	group, name string
	prog        *ebpf.Program
}

// RunWithOptions loads the configured eBPF probes and writes normalized JSONL
// telemetry until SIGINT/SIGTERM. It requires root or CAP_BPF + CAP_PERFMON.
func RunWithOptions(out io.Writer, opts Options) (runErr error) {
	reporter := newCapabilityReporter(opts)
	defer func() { reporter.finish(runErr) }()
	if err := rlimit.RemoveMemlock(); err != nil {
		return i18n.Errorf("remove memlock: %w", err)
	}

	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		return i18n.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	var links []link.Link
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	attach := func(p sensorTracepoint, required bool, category string) error {
		probe := ProbeCapability{Name: p.group + "/" + p.name, Category: category, Required: required, Status: "attached"}
		tp, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			probe.Status = "failed"
			probe.Reason = capabilityFailure(err)
		} else {
			links = append(links, tp)
		}
		reporter.add(probe)
		return err
	}
	for _, p := range []sensorTracepoint{
		{"sched", "sched_process_exec", objs.HandleExec},
		{"syscalls", "sys_enter_execve", objs.HandleExecve},
		{"syscalls", "sys_enter_connect", objs.HandleConnect},
		{"syscalls", "sys_enter_openat", objs.HandleOpenat},
		{"sched", "sched_process_exit", objs.HandleExit},
	} {
		if err := attach(p, true, "syscall"); err != nil {
			reporter.publish(false)
			return i18n.Errorf("attach %s: %w", p.name, err)
		}
	}
	for _, p := range append([]sensorTracepoint{
		{"syscalls", "sys_enter_setuid", objs.HandleSetuid},
		{"syscalls", "sys_enter_setgid", objs.HandleSetgid},
		{"syscalls", "sys_enter_ptrace", objs.HandlePtrace},
		{"syscalls", "sys_enter_renameat2", objs.HandleRename},
		{"syscalls", "sys_enter_renameat", objs.HandleRename},
		{"syscalls", "sys_enter_rename", objs.HandleRenamePlain},
		{"syscalls", "sys_enter_unlinkat", objs.HandleUnlink},
		{"syscalls", "sys_enter_sendto", objs.HandleSendto},
	}, archTracepoints(&objs)...) {
		category := "syscall"
		if p.name == "sys_enter_sendto" {
			category = "dns"
		}
		_ = attach(p, false, category)
	}
	// DNS through libc is independent from the UDP syscall path. Record both
	// capabilities: a working sendto probe does not prove libc coverage.
	dns := ProbeCapability{Name: "getaddrinfo", Category: "dns", Status: "failed"}
	var dnsErrors []string
	for _, libc := range libcCandidates(opts.LibcLib) {
		ex, err := link.OpenExecutable(libc)
		if err == nil {
			var up link.Link
			up, err = ex.Uprobe("getaddrinfo", objs.HandleGetaddrinfo, nil)
			if err == nil {
				links = append(links, up)
				dns.Status = "attached"
				dns.Target = libc
				break
			}
		}
		dnsErrors = append(dnsErrors, libc+": "+capabilityFailure(err))
	}
	if dns.Status != "attached" {
		dns.Reason = strings.Join(dnsErrors, "; ")
	}
	reporter.add(dns)
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return i18n.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	parent := opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopReader := make(chan struct{})
	defer close(stopReader)
	go func() {
		select {
		case <-ctx.Done():
			_ = rd.Close()
		case <-stopReader:
		}
	}()
	// Run discovery separately from ring-buffer consumption. Its bounded first
	// pass attaches configured targets before the workload readiness callback.
	tlsCtx, stopTLS := context.WithCancel(ctx)
	tlsDone := make(chan struct{})
	initialized := make(chan struct{})
	tlsWake := make(chan struct{}, 1)
	go func() { defer close(tlsDone); runTLSDiscovery(tlsCtx, &objs, opts, reporter, initialized, tlsWake) }()
	defer func() { stopTLS(); <-tlsDone }()
	<-initialized
	if ctx.Err() != nil {
		return nil
	}
	reporter.publish(true)
	if opts.OnReady != nil {
		opts.OnReady()
	}

	resolver := newCgroupResolver()
	configureCgroupResolver(resolver, &objs)
	enc := json.NewEncoder(out)
	var encMu sync.Mutex
	var writeErr error
	emit := func(v any) {
		encMu.Lock()
		defer encMu.Unlock()
		if writeErr != nil {
			return
		}
		if err := enc.Encode(v); err != nil {
			writeErr = i18n.Errorf("write sensor event: %w", err)
			_ = rd.Close()
		}
	}

	// Surface ring-buffer drops as a coverage-gap event so a loaded sensor is
	// never silently blind.
	done := make(chan struct{})
	dropsDone := make(chan struct{})
	defer func() { close(done); <-dropsDone }()
	go func() { defer close(dropsDone); watchDrops(objs.Drops, emit, done) }()

	// The SSL_write/read probes emit ordered TLS-plaintext chunks; reassemble them
	// into complete HTTP/1.1 or HTTP/2/HPACK request/response messages before
	// emitting.
	reasm := tlsintent.NewReassembler()
	var tlsLoss tlsintent.CaptureLoss
	var lastTLSLossReport time.Time
	reportTLSLoss := func(force bool) {
		loss := reasm.TakeLoss()
		tlsLoss.Streams += loss.Streams
		tlsLoss.Bytes += loss.Bytes
		if tlsLoss.Streams == 0 && tlsLoss.Bytes == 0 {
			return
		}
		if !force && time.Since(lastTLSLossReport) < time.Second {
			return
		}
		emit(map[string]any{
			"source": "agentprov_ebpf", "event_type": "resource_pressure",
			"resource": "sensor_tls_reassembly", "signal": "reassembly_limit",
			"dropped_delta": tlsLoss.Streams, "dropped_bytes_delta": tlsLoss.Bytes,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		})
		tlsLoss = tlsintent.CaptureLoss{}
		lastTLSLossReport = time.Now()
	}
	defer reportTLSLoss(true)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				reportTLSLoss(true)
				encMu.Lock()
				err = writeErr
				encMu.Unlock()
				return err
			}
			return i18n.Errorf("read sensor ring buffer: %w", err)
		}
		var e sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		if opts.AutoTLS && e.Kind == eventExec {
			// Coalesce process-start wakeups. Discovery has its own bounded rate
			// and never blocks ring-buffer draining.
			select {
			case tlsWake <- struct{}{}:
			default:
			}
		}
		if e.Kind == eventSSL || e.Kind == eventSSLRead {
			dir := tlsintent.Request
			if e.Kind == eventSSLRead {
				dir = tlsintent.Response
			}
			n := int(e.Daddr) // valid bytes in this chunk's path[]
			if n < 0 || n > len(e.Path) {
				n = len(e.Path)
			}
			for _, msg := range reasm.Add(tlsintent.Chunk{
				PID: e.Pid, Conn: e.Conn, Direction: dir,
				Data: append([]byte(nil), e.Path[:n]...), Truncated: e.Dport == 1,
			}) {
				emit(tlsMessageMap(msg, e, resolver))
			}
			reportTLSLoss(false)
			continue
		}
		if e.Kind == eventExit {
			for _, msg := range reasm.FlushPID(e.Pid) {
				emit(tlsMessageMap(msg, e, resolver))
			}
			reportTLSLoss(false)
		}
		if m := normalize(e, resolver); m != nil {
			emit(m)
		}
	}
}

// tlsMessageMap turns a reassembled HTTP/1.1 LLM message into the normalized
// event map, reusing the last chunk's process/cgroup context.
func tlsMessageMap(msg tlsintent.Message, e sensorbpfSensorEvent, resolver *cgroupResolver) map[string]any {
	containerID := resolver.resolve(e.CgroupId)
	if containerID == "" {
		containerID = containerIDForPID(e.Pid)
	}
	etype := "tls_write"
	if msg.Direction == tlsintent.Response {
		etype = "tls_read"
	}
	ev := map[string]any{
		"source":       "agentprov_ebpf",
		"pid":          e.Pid,
		"tgid":         e.Tgid,
		"ppid":         e.Ppid,
		"cgroup_id":    strconv.FormatUint(e.CgroupId, 10),
		"container_id": containerID,
		"timestamp":    eventTimestamp(e),
		"comm":         cstr(e.Comm[:]),
		"event_type":   etype,
		"data":         string(msg.Body),
		"length":       len(msg.Body),
		"protocol":     msg.Protocol,
	}
	if msg.Truncated {
		ev["truncated"] = true
	}
	if msg.Model != "" {
		ev["model"] = msg.Model
	}
	if msg.Endpoint != "" {
		ev["endpoint"] = msg.Endpoint
	}
	if msg.Direction == tlsintent.Request {
		ev["method"], ev["path"], ev["host"] = msg.Method, msg.Path, msg.Host
	} else {
		ev["status"] = msg.Status
	}
	return ev
}

// watchDrops polls the kernel drop counter and emits a resource_pressure event
// whenever it grows, so downstream sees a coverage gap rather than missing data.
func watchDrops(m dropLookuper, emit func(any), done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last uint64
	poll := func() {
		var n uint64
		if err := m.Lookup(uint32(0), &n); err != nil || n <= last {
			return
		}
		emit(map[string]any{
			"source": "agentprov_ebpf", "event_type": "resource_pressure",
			"resource": "sensor_ringbuf", "signal": "event_drop",
			"dropped": n, "dropped_delta": n - last,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		})
		last = n
	}
	for {
		select {
		case <-done:
			poll()
			return
		case <-ticker.C:
			poll()
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
	root            string
	kernelName      func(uint64) string
	mu              sync.RWMutex
	refreshMu       sync.Mutex
	byID            map[uint64]string
	seenAt          map[uint64]time.Time
	retention       time.Duration
	maxEntries      int
	lastRefresh     time.Time
	refreshInterval time.Duration
}

func newCgroupResolver() *cgroupResolver {
	return &cgroupResolver{
		root: "/sys/fs/cgroup", byID: map[uint64]string{},
		refreshInterval: time.Second,
	}
}

// resolve returns the container id for a kernel cgroup id, refreshing the cache
// once on a miss (a newly seen container's cgroup dir appears between scans).
func (r *cgroupResolver) resolve(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	r.refreshIfDue()
	r.mu.RLock()
	id, ok := r.byID[cgroupID]
	r.mu.RUnlock()
	if ok {
		return id
	}
	if r.kernelName != nil {
		id = dockerCgroupRe.FindString(r.kernelName(cgroupID))
		if id != "" {
			r.remember(cgroupID, id)
		}
	}
	return id
}

// remember retains a kernel-captured container name even after its cgroup and
// process have disappeared, while preserving the same cache entry budget.
func (r *cgroupResolver) remember(cgroupID uint64, containerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = map[uint64]string{}
	}
	if r.seenAt == nil {
		r.seenAt = map[uint64]time.Time{}
	}
	limit := r.maxEntries
	if limit <= 0 {
		limit = 16384
	}
	if len(r.byID) >= limit {
		var oldest uint64
		var when time.Time
		for id, seen := range r.seenAt {
			if when.IsZero() || seen.Before(when) {
				oldest, when = id, seen
			}
		}
		delete(r.byID, oldest)
		delete(r.seenAt, oldest)
	}
	r.byID[cgroupID], r.seenAt[cgroupID] = containerID, time.Now()
}

// refreshIfDue bounds hierarchy scans. A node-wide sensor sees many host
// cgroups that can never map to a container; rescanning the complete hierarchy
// for every such event stalls ring-buffer consumption under normal K8s host
// activity. Unknown ids use the live /proc fallback until the next refresh.
func (r *cgroupResolver) refreshIfDue() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	interval := r.refreshInterval
	if interval <= 0 {
		interval = time.Second
	}
	r.mu.RLock()
	last := r.lastRefresh
	r.mu.RUnlock()
	if !last.IsZero() && time.Since(last) < interval {
		return
	}
	r.refresh()
}

// refresh walks the cgroup v2 hierarchy and maps each container cgroup
// directory's inode (== the kernel cgroup id) to the 64-hex container id parsed
// from its name (docker-<id>.scope, cri-containerd-<id>.scope, kubepods/<id>...).
func (r *cgroupResolver) refresh() {
	next := map[uint64]string{}
	limit := r.maxEntries
	if limit <= 0 {
		limit = 16384
	}
	visited := 0
	_ = filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		visited++
		if len(next) >= limit || visited > 131072 {
			return fs.SkipAll
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
	defer r.mu.Unlock()
	now := time.Now()
	retention := r.retention
	if retention <= 0 {
		retention = 10 * time.Minute
	}
	seen := make(map[uint64]time.Time, len(next))
	for id := range next {
		seen[id] = now
	}
	// Keep recently departed cgroup identities for ring-buffer drain and late
	// informer correlation, with an explicit TTL and entry cap.
	oldIDs := make([]uint64, 0, len(r.byID))
	for id := range r.byID {
		if _, current := next[id]; !current && now.Sub(r.seenAt[id]) < retention {
			oldIDs = append(oldIDs, id)
		}
	}
	sort.Slice(oldIDs, func(i, j int) bool { return r.seenAt[oldIDs[i]].After(r.seenAt[oldIDs[j]]) })
	for _, id := range oldIDs {
		if len(next) >= limit {
			break
		}
		next[id], seen[id] = r.byID[id], r.seenAt[id]
	}
	r.byID, r.seenAt = next, seen
	r.lastRefresh = now
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
		"timestamp":    eventTimestamp(e),
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
		path := cstr(e.Path[:])
		mode := "write"
		if e.ExitCode == 1 {
			mode = "read"
		}
		// The kernel already dropped noise-prefix reads; here we keep only
		// sensitive reads (writes always pass). Non-sensitive reads are dropped
		// so the store stays focused on credential/secret access.
		if mode == "read" && !sensitiveReadPath(path) {
			return nil
		}
		ev["event_type"] = "file_open"
		ev["path"] = path
		ev["mode"] = mode
	case eventExit:
		ev["event_type"] = "process_exit"
		ev["exit_code"] = e.ExitCode
	case eventSetuid:
		if e.Daddr == 1 {
			ev["event_type"] = "setgid"
			ev["gid"] = e.ExitCode
		} else {
			ev["event_type"] = "setuid"
			ev["uid"] = e.ExitCode
		}
	case eventPtrace:
		ev["event_type"] = "ptrace"
		ev["request"] = e.ExitCode
		ev["target_pid"] = e.Daddr
	case eventRename:
		ev["event_type"] = "file_rename"
		ev["path"] = cstr(e.Path[:])
	case eventUnlink:
		ev["event_type"] = "file_unlink"
		ev["path"] = cstr(e.Path[:])
	case eventDNS:
		ev["event_type"] = "dns_query"
		if e.ExitCode > 0 {
			// raw DNS query bytes (UDP path); parse the qname
			n := int(e.ExitCode)
			if n > len(e.Path) {
				n = len(e.Path)
			}
			ev["host"] = dnsQName(e.Path[:n])
		} else {
			ev["host"] = cstr(e.Path[:]) // getaddrinfo hostname (string)
		}
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

// sensitiveReadPath positively matches the small set of paths whose READ is
// security-relevant (credential/secret/key files). The kernel forwards reads
// coarsely (noise prefixes dropped); this is the precise filter that decides
// which reads reach the store. Mirrors the policy engine's secret patterns and
// adds key/cred file markers.
func sensitiveReadPath(p string) bool {
	for _, s := range []string{
		".ssh", ".aws", "id_rsa", "id_ed25519", "credentials", ".env",
		"secret", "/etc/shadow", "/etc/passwd", ".pem", ".kube/config", "_token",
	} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// libcCandidates returns libc paths to try for the getaddrinfo uprobe: the
// explicit override first, then the common multiarch/system locations.
func libcCandidates(override string) []string {
	c := []string{}
	if override != "" {
		c = append(c, override)
	}
	return append(c,
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/libc.so.6",
	)
}

// dnsQName parses the question name from a raw DNS query message (12-byte header
// then length-prefixed labels) into a dotted hostname, or "" if malformed.
func dnsQName(b []uint8) string {
	if len(b) < 13 {
		return ""
	}
	i := 12
	var sb strings.Builder
	for i < len(b) {
		l := int(b[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(b) {
			return ""
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for j := 0; j < l; j++ {
			c := b[i+j]
			if c < 0x20 || c > 0x7e {
				return "" // not a printable hostname
			}
			sb.WriteByte(byte(c))
		}
		i += l
	}
	if sb.Len() == 0 {
		return ""
	}
	return sb.String()
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
