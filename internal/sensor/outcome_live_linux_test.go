//go:build linux && (amd64 || arm64)

package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func TestLiveSyscallOutcomes(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OUTCOMES") != "1" {
		t.Skip("set AGENTPROV_LIVE_OUTCOMES=1 on Linux with eBPF privileges and cc")
	}
	bin := buildTLSCFixture(t, "syscall_outcomes.c")
	objs := loadReadProbeObjects(t)
	for _, p := range []sensorTracepoint{
		{"syscalls", "sys_enter_openat", objs.HandleOpenat},
		{"syscalls", "sys_exit_openat", objs.HandleOpenReturn},
		{"syscalls", "sys_enter_connect", objs.HandleConnect},
		{"syscalls", "sys_exit_connect", objs.HandleConnectReturn},
	} {
		l, err := link.Tracepoint(p.group, p.name, p.prog, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Reserve an unused port without listen(), so refusals cannot race port reuse.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	addr, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	refused := addr.(*unix.SockaddrInet4).Port
	for _, mode := range []string{"concurrent", "leader-exit", "ordinary-permission", "seccomp-errno", "seccomp-log", "seccomp-kill"} {
		t.Run(mode, func(t *testing.T) {
			reader, err := ringbuf.NewReader(objs.Events)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			dir := t.TempDir()
			cmd := exec.CommandContext(ctx, bin, mode, dir, strconv.Itoa(server.Addr().(*net.TCPAddr).Port), strconv.Itoa(refused))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			var exit *exec.ExitError
			if ctx.Err() != nil || (err != nil && !errors.As(err, &exit)) {
				t.Fatalf("fixture: %v %s", err, stderr.String())
			}
			status := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if mode == "seccomp-kill" && status.Signal() != syscall.SIGSYS {
				t.Fatalf("fixture did not terminate with SIGSYS: %v %s", status, stderr.String())
			}
			if mode == "concurrent" && status.ExitStatus() != 7 {
				t.Fatalf("fixture failed: %v %s", status, stderr.String())
			}
			if (mode == "ordinary-permission" || mode == "seccomp-errno" || mode == "seccomp-log") && status.ExitStatus() != 0 {
				t.Fatalf("fixture failed: %v %s", status, stderr.String())
			}
			if err := reader.Flush(); err != nil {
				t.Fatal(err)
			}
			var events []sensorbpfSensorEvent
			var kernelPID uint32
			for {
				r, err := reader.Read()
				if errors.Is(err, ringbuf.ErrFlushed) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				var e sensorbpfSensorEvent
				if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &e); err != nil {
					t.Fatal(err)
				}
				if e.Kind == eventExec && cstr(e.Path[:]) == bin {
					if kernelPID != 0 && kernelPID != e.Pid {
						t.Fatal("ambiguous fixture process")
					}
					kernelPID = e.Pid
				}
				events = append(events, e)
			}
			if kernelPID == 0 {
				t.Fatal("missing fixture exec anchor")
			}
			sort.SliceStable(events, func(i, j int) bool { return events[i].KtimeNs < events[j].KtimeNs })
			attempts := map[string]sensorbpfSensorEvent{}
			results := map[string][]int64{}
			resultIDs := map[string]bool{}
			var lastResult, processExit, leaderExit uint64
			processExits := 0
			for _, e := range events {
				if e.Pid != kernelPID {
					continue
				}
				row := normalize(e, newCgroupResolver())
				if e.Kind == eventExit {
					processExits++
					processExit = e.KtimeNs
					if status.Signaled() {
						if row["exit_signal"] != uint32(status.Signal()) || row["exit_code"] != nil {
							t.Fatalf("lost signal outcome: %+v", row)
						}
					} else if row["exit_code"] != uint32(status.ExitStatus()) {
						t.Fatalf("exit mismatch: %+v wait=%v", row, status)
					}
				}
				if e.Kind == eventThreadExit && e.Pid == e.Tid {
					leaderExit = e.KtimeNs
				}
				if e.SyscallStartNs == 0 || row == nil {
					continue
				}
				if e.SyscallKind == eventOpen && !strings.HasPrefix(cstr(e.Path[:]), dir+"/") {
					continue
				}
				id, _ := row["operation_id"].(string)
				if id == "" || e.ThreadStartNs == 0 || e.ProcessStartNs == 0 {
					t.Fatalf("missing operation identity: %+v", row)
				}
				isResult := e.Kind == eventSyscallResult || e.Kind == eventOpen && e.Dport == 1
				if !isResult {
					if _, duplicate := attempts[id]; duplicate {
						t.Fatal("duplicate attempt id")
					}
					attempts[id] = e
					continue
				}
				if resultIDs[id] {
					t.Fatal("duplicate result id")
				}
				resultIDs[id] = true
				if e.Kind == eventSyscallResult {
					entry, ok := attempts[id]
					if !ok || entry.Tid != e.Tid || entry.ThreadStartNs != e.ThreadStartNs || entry.KtimeNs > e.KtimeNs {
						t.Fatalf("return paired to missing/wrong thread: %+v", row)
					}
				}
				key := fmt.Sprintf("%d/%s", e.Tid, row["operation"])
				results[key] = append(results[key], e.SyscallResult)
				lastResult = e.KtimeNs
			}
			if processExits != 1 || processExit < lastResult {
				t.Fatalf("premature/duplicate process exit: count=%d exit=%d last=%d", processExits, processExit, lastResult)
			}
			if (mode == "leader-exit" || mode == "seccomp-kill") && (leaderExit == 0 || leaderExit >= processExit) {
				t.Fatalf("leader/group exit conflated: %d %d", leaderExit, processExit)
			}
			oracle := map[string][]int64{}
			oracleCount := 0
			decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
			for decoder.More() {
				var row struct {
					PID       int
					TID       int
					Operation string
					Result    int64
				}
				if err := decoder.Decode(&row); err != nil {
					t.Fatal(err)
				}
				key := fmt.Sprintf("%d/%s", row.TID, row.Operation)
				oracle[key] = append(oracle[key], row.Result)
				oracleCount++
			}
			wantCount := map[string]int{"concurrent": 80, "leader-exit": 2, "ordinary-permission": 2, "seccomp-errno": 1, "seccomp-log": 1, "seccomp-kill": 0}[mode]
			if oracleCount != wantCount {
				t.Fatalf("fixture observed %d calls, want %d", oracleCount, wantCount)
			}
			if mode == "ordinary-permission" {
				for _, result := range oracle {
					if fmt.Sprint(result) != "[-13 -13]" {
						t.Fatalf("permission fixture did not fail with EACCES: %v", result)
					}
				}
			}
			if mode == "seccomp-log" {
				for _, result := range oracle {
					if fmt.Sprint(result) != "[0]" {
						t.Fatalf("LOG fixture did not connect: %v", result)
					}
				}
			}
			if mode == "seccomp-errno" {
				// Linux can reject this before sys_enter_connect. Keep the gap;
				// a standalone audit decision must not manufacture a probe event.
				if len(oracle) != 1 || len(results) != 0 || len(attempts) != 0 {
					t.Fatalf("filtered syscall unexpectedly fabricated entry/return: oracle=%v results=%v attempts=%v", oracle, results, attempts)
				}
				for _, result := range oracle {
					if fmt.Sprint(result) != "[-1]" {
						t.Fatalf("seccomp errno fixture failed: %v", result)
					}
				}
				oracle = map[string][]int64{}
				t.Log("seccomp ERRNO: fixture observed EPERM; no sys_enter/paired sys_exit record was fabricated")
			}
			if len(results) != len(oracle) {
				t.Fatalf("result groups=%d oracle=%d", len(results), len(oracle))
			}
			for key, want := range oracle {
				if fmt.Sprint(results[key]) != fmt.Sprint(want) {
					t.Fatalf("%s got %v want %v", key, results[key], want)
				}
			}
			it := objs.SyscallCalls.Iterate()
			var key uint64
			var value sensorbpfSyscallCtx
			for it.Next(&key, &value) {
				if uint32(key>>32) == kernelPID {
					t.Fatal("fixture left in-flight syscall state")
				}
			}
			if err := it.Err(); err != nil {
				t.Fatal(err)
			}
			if directory := os.Getenv("AGENTPROV_OUTCOME_EVIDENCE_DIR"); directory != "" {
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				var observations []map[string]any
				for _, e := range events {
					if e.Pid == kernelPID {
						if row := normalize(e, newCgroupResolver()); row != nil {
							observations = append(observations, row)
						}
					}
				}
				data, err := json.MarshalIndent(map[string]any{
					"mode": mode, "kernel_pid": kernelPID, "wait_status": uint32(status),
					"fixture_stdout": stdout.String(), "observations": observations,
				}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, mode+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("%s: %d result observations matched independent syscall returns; one final process exit; thread cleanup verified", mode, len(resultIDs))
		})
	}
}
