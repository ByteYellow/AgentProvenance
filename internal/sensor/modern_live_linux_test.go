//go:build linux && (amd64 || arm64)

package sensor

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func TestLiveSyscallModernEntries(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OUTCOMES") != "1" {
		t.Skip("requires Linux BPF privileges and cc")
	}
	bin := buildTLSCFixture(t, "modern_syscalls.c")
	o := loadReadProbeObjects(t)
	for _, p := range []sensorTracepoint{
		{"syscalls", "sys_enter_connect", o.HandleConnect}, {"syscalls", "sys_exit_connect", o.HandleConnectReturn},
		{"syscalls", "sys_enter_openat2", o.HandleOpenat2}, {"syscalls", "sys_exit_openat2", o.HandleOpenat2Return},
		{"syscalls", "sys_enter_execveat", o.HandleExecveat}, {"syscalls", "sys_exit_execveat", o.HandleExecReturn},
	} {
		l, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	s, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rd, err := ringbuf.NewReader(o.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	port := s.Addr().(*net.TCPAddr).Port
	cmd := exec.Command(bin, strconv.Itoa(port))
	cmd.Dir = t.TempDir()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	if err := rd.Flush(); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	resolver := newCgroupResolver()
	var anchor uint32
	entries := map[string]bool{}
	for {
		r, err := rd.Read()
		if errors.Is(err, ringbuf.ErrFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		e, err := decodeSensorEvent(r.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == eventExec && cstr(e.Path[:]) == bin {
			anchor = e.Pid
		}
		if anchor == 0 || e.Pid != anchor {
			continue
		}
		v := normalize(e, resolver)
		if v == nil {
			continue
		}
		id, _ := v["operation_id"].(string)
		if e.SyscallKind == eventConnect || e.SyscallKind == eventOpen {
			switch v["observation_stage"] {
			case "attempt":
				entries[id] = id != ""
			case "result":
				if !entries[id] {
					t.Fatalf("unpaired result: %v", v)
				}
				delete(entries, id)
			}
		}
		switch e.SyscallNr {
		case unix.SYS_CONNECT:
			if v["dst_ip"] != "::1" || int(ntohs(e.Dport)) != port || v["address_family"] != "AF_INET6" {
				t.Fatal(v)
			}
			if v["syscall_outcome"] == "success" {
				counts["connect"]++
			}
		case unix.SYS_OPENAT2:
			if v["open_resolve"] != "8" || e.Dirfd < 0 {
				t.Fatal(v)
			}
			if e.Kind == eventSyscallResult || e.Kind == eventOpen && e.Dport == 1 {
				switch {
				case v["path"] == ".env-fixture" && v["syscall_outcome"] == "success":
					counts[v["mode"].(string)]++
				case v["path"] == ".env-missing" && e.SyscallResult == -int64(unix.ENOENT):
					counts["missing"]++
				default:
					t.Fatal(v)
				}
			}
		case unix.SYS_EXECVEAT:
			if e.OpFlags != unix.AT_EMPTY_PATH {
				t.Fatal(v)
			}
			switch e.Kind {
			case eventExec:
				if v["command"] != "fd-exec-fixture finished" || e.Dirfd < 0 {
					t.Fatal(v)
				}
				counts["exec"]++
			case eventSyscallResult:
				if e.SyscallResult != -int64(unix.EBADF) || e.Dirfd != -1 || id == "" {
					t.Fatal(v)
				}
				counts["failed_exec"]++
			default:
				t.Fatal(v)
			}
		}
	}
	for _, key := range []string{"connect", "write", "read", "missing", "exec", "failed_exec"} {
		if counts[key] != 1 {
			t.Fatalf("%s: %+v", key, counts)
		}
	}
	if len(entries) != 0 {
		t.Fatalf("unmatched entries: %v", entries)
	}
	t.Logf("independent fixture exits 0; captured %+v", counts)
}
