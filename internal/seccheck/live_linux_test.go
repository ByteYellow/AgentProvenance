//go:build linux && (amd64 || arm64)

package seccheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
)

// This test binary is bind-mounted read-only into an isolated, operator-supplied
// rootfs. It performs no workload operations in the test runner's namespace.
func TestSecCheckLiveWorkload(t *testing.T) {
	if os.Getenv("AGENTPROV_SECCHECK_CHILD") != "1" {
		t.Skip("gVisor child only")
	}
	var wg sync.WaitGroup
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-release
			errs <- os.WriteFile(fmt.Sprintf("/tmp/thread-%d", i), []byte("thread evidence"), 0o600)
		}(i)
	}
	<-ready
	<-ready
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/tmp/seccheck-result", []byte("SECCHECK_OK"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", "/bin/cat /tmp/seccheck-result").CombinedOutput()
	if err != nil || string(out) != "SECCHECK_OK" {
		t.Fatalf("cat: %q %v", out, err)
	}
	if _, err := os.Open("/tmp/absent-seccheck-file"); !os.IsNotExist(err) {
		t.Fatalf("missing file result: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			err = c.Close()
		}
		accepted <- err
	}()
	// Go's net.Dial uses a nonblocking socket, whose connect result is normally
	// EINPROGRESS. Use an actual blocking call to test a successful exit record.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: ln.Addr().(*net.TCPAddr).Port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	unix.Close(fd)
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	failedFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	failedErr := unix.Connect(failedFD, &unix.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}})
	unix.Close(failedFD)
	if failedErr != unix.ECONNREFUSED {
		t.Fatalf("blocking refusal: %v", failedErr)
	}
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:1", time.Second); err == nil {
		c.Close()
		t.Fatal("unexpected listener")
	}
	t.Log("SECCHECK_OK")
}

func testTraceConfig(socket string) map[string]any {
	contextFields := []string{"time", "thread_id", "task_start_time", "group_id", "thread_group_start_time", "container_id", "cwd", "process_name", "parent_thread_group_id", "is_exec_session"}
	points := []map[string]any{}
	for _, name := range []string{"container/start", "sentry/clone", "sentry/execve", "sentry/task_exit", "syscall/openat/enter", "syscall/openat/exit", "syscall/connect/enter", "syscall/connect/exit", "syscall/execve/enter", "syscall/execve/exit"} {
		point := map[string]any{"name": name, "context_fields": contextFields}
		if strings.HasPrefix(name, "syscall/openat/") {
			point["optional_fields"] = []string{"fd_path"}
		}
		points = append(points, point)
	}
	return map[string]any{"trace_session": map[string]any{"name": "Default", "points": points, "sinks": []any{map[string]any{"name": "remote", "config": map[string]any{"endpoint": socket}}}}}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSecCheckLiveRuntime(t *testing.T) {
	runsc, rootfs := os.Getenv("AGENTPROV_TEST_RUNSC"), os.Getenv("AGENTPROV_TEST_GVISOR_ROOTFS")
	if runsc == "" || rootfs == "" {
		t.Skip("set AGENTPROV_TEST_RUNSC and AGENTPROV_TEST_GVISOR_ROOTFS")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated runsc acceptance requires root")
	}
	version, err := exec.Command(runsc, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), RuntimeRelease) {
		t.Fatalf("runtime pin: %q %v", version, err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type instance struct {
		name     string
		receiver *testReceiver
		cmd      *exec.Cmd
		output   []byte
		err      error
	}
	instances := []*instance{}
	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("seccheck-live-%d", i)
		reg := testRegistration()
		reg.SandboxID, reg.ContainerID = name, name
		s := startTestReceiver(t, reg, nil)
		dir := t.TempDir()
		state := filepath.Join(dir, "state")
		t.Cleanup(func() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if out, err := exec.CommandContext(cleanupCtx, runsc, "--root="+state, "delete", "--force", name).CombinedOutput(); err != nil {
				t.Errorf("isolated container cleanup: %s %v", out, err)
			}
			if err := unix.Unmount(filepath.Join(state, "null-netns"), 0); err != nil && err != unix.ENOENT && err != unix.EINVAL {
				t.Errorf("isolated network namespace cleanup: %v", err)
			}
		})
		config := map[string]any{
			"ociVersion": "1.0.2", "hostname": "seccheck",
			"process": map[string]any{"user": map[string]int{"uid": 0, "gid": 0}, "terminal": false, "args": []string{"/acceptance", "-test.run=^TestSecCheckLiveWorkload$", "-test.v"}, "env": []string{"PATH=/bin:/usr/bin", "AGENTPROV_SECCHECK_CHILD=1"}, "cwd": "/", "noNewPrivileges": true},
			"root":    map[string]any{"path": rootfs, "readonly": true},
			"mounts": []any{
				map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
				map[string]any{"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
				map[string]any{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "nodev", "size=16m"}},
				map[string]any{"destination": "/acceptance", "type": "bind", "source": executable, "options": []string{"bind", "ro"}},
			},
			"linux": map[string]any{"namespaces": []any{map[string]string{"type": "pid"}, map[string]string{"type": "network"}, map[string]string{"type": "ipc"}, map[string]string{"type": "uts"}, map[string]string{"type": "mount"}}},
		}
		writeTestJSON(t, filepath.Join(dir, "config.json"), config)
		trace := filepath.Join(dir, "trace.json")
		writeTestJSON(t, trace, testTraceConfig(s.path))
		cmd := exec.CommandContext(ctx, runsc, "--root="+filepath.Join(dir, "state"), "--platform=systrap", "--network=none", "--pod-init-config="+trace, "run", "--bundle="+dir, name)
		instances = append(instances, &instance{name: name, receiver: s, cmd: cmd})
	}
	var wg sync.WaitGroup
	for _, item := range instances {
		wg.Add(1)
		go func(item *instance) { defer wg.Done(); item.output, item.err = item.cmd.CombinedOutput() }(item)
	}
	wg.Wait()
	roots := map[string]bool{}
	for _, item := range instances {
		if item.err != nil || !bytes.Contains(item.output, []byte("SECCHECK_OK")) {
			t.Fatalf("%s: %q %v", item.name, item.output, item.err)
		}
		rows := item.receiver.wait(t, func(rows []Record) bool { return len(rows) > 1 && rows[len(rows)-1].Reason == "disconnected" })
		counts := map[string]int{}
		threads := map[string]bool{}
		openOK, openFailed, connectOK, connectFailed, connectPending, childClone := false, false, false, false, false, false
		for _, r := range rows {
			if r.Kind != "event" {
				if r.Reason != "connected" && r.Reason != "disconnected" {
					t.Fatalf("unexpected stream diagnostic: %+v", r)
				}
				continue
			}
			if r.DroppedDelta == nil || *r.DroppedDelta != 0 {
				t.Fatalf("live loss: %+v", r)
			}
			counts[wire.MessageType(r.Packet.Header.MessageType).String()]++
			if r.Identity.ThreadGroupID == 1 {
				roots[r.Identity.Process] = true
				threads[r.Identity.Task] = true
			}
			switch m := r.Packet.Message.(type) {
			case *wire.Open:
				if m.Pathname == "/tmp/seccheck-result" && m.Exit != nil && m.Exit.Errorno == 0 {
					openOK = true
				}
				if m.Pathname == "/tmp/absent-seccheck-file" && m.Exit != nil && m.Exit.Errorno == 2 {
					openFailed = true
				}
			case *wire.Connect:
				if m.Exit != nil && m.Exit.Errorno == 0 {
					connectOK = true
				}
				if m.Exit != nil && m.Exit.Errorno == int64(unix.ECONNREFUSED) {
					connectFailed = true
				}
				if m.Exit != nil && m.Exit.Errorno == int64(unix.EINPROGRESS) {
					connectPending = true
				}
			case *wire.CloneInfo:
				if m.CreatedThreadId > 1 && m.CreatedThreadStartTimeNs > 0 {
					childClone = true
				}
			}
		}
		if !openOK || !openFailed || !connectOK || !connectFailed || !connectPending || !childClone || len(threads) < 2 || counts[wire.MessageType_MESSAGE_SENTRY_EXEC.String()] < 2 || counts[wire.MessageType_MESSAGE_SENTRY_TASK_EXIT.String()] < 2 {
			t.Fatalf("incomplete live assertions: open=%v/%v connect=%v/%v/pending=%v clone=%v threads=%d counts=%v", openOK, openFailed, connectOK, connectFailed, connectPending, childClone, len(threads), counts)
		}
		t.Logf("%s records=%d threads=%d counts=%v", item.name, len(rows), len(threads), counts)
		if out := os.Getenv("AGENTPROV_TEST_SECCHECK_OUTPUT"); out != "" {
			if err := os.MkdirAll(out, 0o700); err != nil {
				t.Fatal(err)
			}
			exported := []map[string]any{}
			for _, r := range rows {
				entry := map[string]any{"record": r}
				if r.Packet != nil {
					entry["header"], entry["packet_sha256"] = r.Packet.Header, r.Packet.SHA256
					if r.Packet.Message != nil {
						data, err := protojson.Marshal(r.Packet.Message)
						if err != nil {
							t.Fatal(err)
						}
						entry["payload"] = json.RawMessage(data)
					}
				}
				exported = append(exported, entry)
			}
			writeTestJSON(t, filepath.Join(out, item.name+".json"), exported)
		}
	}
	if len(roots) != 2 || roots[""] {
		t.Fatalf("two sandbox PID 1 identities collided: %v", roots)
	}
}
