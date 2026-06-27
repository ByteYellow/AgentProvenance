//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
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
)

// Run loads the eBPF probes (exec/connect/openat), reads events from the ring
// buffer, enriches each with a container id derived from the task's cgroup, and
// writes one normalized telemetry event per line (JSONL) to out. It blocks until
// SIGINT/SIGTERM. Requires root or CAP_BPF + CAP_PERFMON.
func Run(out io.Writer) error {
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

	enc := json.NewEncoder(out)
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
		_ = enc.Encode(normalize(e))
	}
}

// normalize maps a raw kernel event to the normalized telemetry schema consumed
// by `telemetry ingest` (container_id, cgroup_id, pid/tgid/ppid, source,
// event_type, payload). container_id is best-effort from /proc/<pid>/cgroup.
func normalize(e sensorbpfSensorEvent) map[string]any {
	containerID := containerIDForPID(e.Pid)
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
	case eventConnect:
		ev["event_type"] = "network_connect"
		ev["dst_ip"] = ipv4(e.Daddr)
		ev["dst_port"] = ntohs(e.Dport)
	case eventOpen:
		ev["event_type"] = "file_open"
		ev["path"] = cstr(e.Path[:])
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
