//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Run loads the eBPF probes, reads events from the ring buffer, and writes one
// normalized telemetry event per line (JSONL) to out. It blocks until SIGINT/
// SIGTERM. Requires root or CAP_BPF + CAP_PERFMON.
func Run(out io.Writer) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	defer tp.Close()

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
		var e sensorbpfExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		// v0 emits the raw exec event; normalized-schema mapping + container_id
		// derivation from the cgroup path is the next increment.
		_ = enc.Encode(map[string]any{
			"source":     "agentprov_ebpf",
			"event_type": "execve",
			"pid":        e.Pid,
			"ppid":       e.Ppid,
			"comm":       cstr(e.Comm[:]),
			"filename":   cstr(e.Filename[:]),
		})
	}
}

// cstr converts a NUL-terminated C char array to a Go string.
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
