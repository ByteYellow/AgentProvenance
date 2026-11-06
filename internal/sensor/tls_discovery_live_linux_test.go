//go:build linux && (amd64 || arm64)

package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privateTLSLibrary(t *testing.T) string {
	t.Helper()
	probe := buildTLSCFixture(t, "tls_capture_gap.c", "-lssl", "-lcrypto")
	linked, err := exec.Command("ldd", probe).CombinedOutput()
	if err != nil {
		t.Fatalf("ldd: %v %s", err, linked)
	}
	for _, line := range strings.Split(string(linked), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "libssl.so.3" || fields[1] != "=>" {
			continue
		}
		data, err := os.ReadFile(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "libssl.so.3")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Fatal("fixture has no dynamic OpenSSL")
	return ""
}

func TestLiveTLSDiscoveryShortClient(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for automatic TLS discovery acceptance")
	}
	bin := buildTLSCFixture(t, "tls_discovery_client.c", "-ldl")
	for _, mode := range []string{"automatic", "explicit", "explicit-no-auto", "delayed-load", "delayed-system-library", "concurrent", "warm-inode", "new-go-executable"} {
		t.Run(mode, func(t *testing.T) {
			goClient := os.Getenv("AGENTPROV_LIVE_TLS_CLIENT")
			if mode == "new-go-executable" && goClient == "" {
				t.Skip("set AGENTPROV_LIVE_TLS_CLIENT to an unstripped testdata/tls_client.go binary")
			}
			library := privateTLSLibrary(t)
			if mode == "delayed-system-library" {
				// Exercise the kernel's filtered /usr read path without changing
				// any installed library. The private copy is removed by cleanup.
				dir, err := os.MkdirTemp("/usr/lib", "agentprov-tls-discovery-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				data, err := os.ReadFile(library)
				if err != nil {
					t.Fatal(err)
				}
				library = filepath.Join(dir, "libssl.so.3")
				if err := os.WriteFile(library, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			received := make(chan string, 32)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.URL.Path
				w.Header().Set("Content-Length", "2")
				_, _ = io.WriteString(w, "ok")
			}))
			defer server.Close()
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			ctx, cancel := context.WithCancel(context.Background())
			ready, done := make(chan struct{}), make(chan error, 1)
			var output bytes.Buffer
			var capability CapabilityReport
			opts := Options{Context: ctx, AutoTLS: true, TLSScanInterval: 2 * time.Second,
				Diagnostics: io.Discard, OnReady: func() { close(ready) },
				OnCapabilities: func(report CapabilityReport) { capability = report }}
			if mode == "explicit" || mode == "explicit-no-auto" {
				opts.SSLLib = library
			}
			if mode == "explicit-no-auto" {
				opts.AutoTLS = false
			}
			go func() { done <- RunWithOptions(&output, opts) }()
			stopped := false
			defer func() {
				cancel()
				if !stopped {
					<-done
				}
			}()
			select {
			case <-ready:
			case err := <-done:
				stopped = true
				t.Fatalf("sensor startup: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("sensor readiness timed out")
			}
			clientCtx, stopClient := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopClient()
			n := 1
			if mode == "concurrent" {
				n = 8
			}
			wanted := map[int]string{}
			var commands []*exec.Cmd
			var stderr bytes.Buffer
			var cpuBefore, cpuAfter syscall.Rusage
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore)
			started := time.Now()
			startClient := func(delay string) *exec.Cmd {
				t.Helper()
				loadDelay := "0"
				if mode == "delayed-load" || mode == "delayed-system-library" {
					loadDelay = "700"
				}
				cmd := exec.CommandContext(clientCtx, bin, library, port, loadDelay, delay)
				if mode == "new-go-executable" {
					cmd = exec.CommandContext(clientCtx, goClient, "https://127.0.0.1:"+port+"/go-discovery", "PUBLIC-TLS-DISCOVERY-CANARY")
					cmd.Env = append(os.Environ(), "AGENTPROV_TLS_START_DELAY_MS=80")
				}
				// Each concurrent client has its own output buffer.
				cmd.Stderr = new(bytes.Buffer)
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				wanted[cmd.Process.Pid] = "/discovery/" + strconv.Itoa(cmd.Process.Pid)
				if mode == "new-go-executable" {
					wanted[cmd.Process.Pid] = "/go-discovery"
				}
				return cmd
			}
			for i := 0; i < n; i++ {
				commands = append(commands, startClient("80"))
			}
			for _, cmd := range commands {
				if err := cmd.Wait(); err != nil {
					stderr.Write(cmd.Stderr.(*bytes.Buffer).Bytes())
					t.Fatalf("TLS client: %v %s", err, stderr.String())
				}
			}
			elapsed := time.Since(started)
			if mode == "warm-inode" {
				// Complete a sweep with no process mapping the private inode.
				time.Sleep(2200 * time.Millisecond)
				cmd := startClient("0")
				if err := cmd.Wait(); err != nil {
					t.Fatalf("warm client: %v %s", err, cmd.Stderr)
				}
				n++
			}
			if len(received) != n {
				t.Fatalf("server received %d/%d requests", len(received), n)
			}
			// Let the consumer drain; no further TLS requests are sent.
			time.Sleep(100 * time.Millisecond)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			stopped = true
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter)
			decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
			requests, executions := map[int]int{}, map[int]int{}
			for decoder.More() {
				var event map[string]any
				if err := decoder.Decode(&event); err != nil {
					t.Fatal(err)
				}
				pid, _ := event["pid"].(float64)
				if _, ok := wanted[int(pid)]; !ok {
					continue
				}
				if event["event_type"] == "execve" {
					executions[int(pid)]++
				}
				if event["event_type"] == "tls_write" && event["path"] == wanted[int(pid)] {
					requests[int(pid)]++
				}
			}
			cpuUS := cpuAfter.Utime.Nano() + cpuAfter.Stime.Nano() - cpuBefore.Utime.Nano() - cpuBefore.Stime.Nano()
			t.Logf("first requests captured=%d/%d; initial client wall=%s; test-process CPU=%s; discovery=%+v", len(requests), n, elapsed, time.Duration(cpuUS), capability.TLSDiscovery)
			for pid := range wanted {
				if executions[pid] == 0 || requests[pid] != 1 {
					t.Errorf("first request missing or duplicated for PID %d: exec=%d request=%d", pid, executions[pid], requests[pid])
				}
			}
			if mode == "explicit-no-auto" {
				if capability.TLSDiscovery.EventDiscovery != nil || capability.TLSDiscovery.Enabled {
					t.Fatal("disabled automatic discovery still reported active")
				}
			} else if e := capability.TLSDiscovery.EventDiscovery; e == nil || e.QueueDrops != 0 || e.ProcessScans == 0 {
				t.Errorf("event discovery stats missing or overloaded: %+v", e)
			} else {
				t.Logf("event discovery counters: %+v", *e)
			}
		})
	}
}
