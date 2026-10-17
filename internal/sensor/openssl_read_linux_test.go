package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Requires Linux root, BTF, cc and OpenSSL development headers. The synthetic
// ABI cases and real OpenSSL acceptance are intentionally reported separately.
func TestLiveOpenSSLReadPairing(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for real eBPF read-pairing acceptance")
	}
	bin := buildTLSCFixture(t, "ssl_read_pairing.c")
	objs := loadReadProbeObjects(t)
	attachOpenSSLReadProbes(t, bin, objs)
	cases := []struct {
		mode  string
		depth int
		ex    int
		reads int
		drops uint64
	}{
		{"normal", 1, 0, 2, 0}, {"normal", 1, 1, 2, 0},
		{"nested", 4, 0, 5, 0}, {"nested", 4, 1, 5, 0},
		{"overflow", 6, 0, 5, 2}, {"overflow", 6, 1, 5, 2},
		{"failure", 2, 0, 2, 0}, {"failure", 2, 1, 2, 0},
		{"oversize", 1, 0, 1, 1}, {"oversize", 1, 1, 1, 1},
		{"bad-out", 1, 1, 1, 1},
		{"exit", 1, 0, 0, 0}, {"exit", 1, 1, 0, 0},
		{"exec", 1, 0, 2, 0}, {"exec", 1, 1, 2, 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/ex=%d", tc.mode, tc.ex), func(t *testing.T) {
			before := readProbeDrops(t, objs)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, tc.mode, strconv.Itoa(tc.depth), strconv.Itoa(tc.ex))
			_, reads := compareReadProbeBytes(t, objs, cmd)
			if reads != tc.reads {
				t.Fatalf("captured read oracle count=%d, want %d", reads, tc.reads)
			}
			if drops := readProbeDrops(t, objs) - before; drops != tc.drops {
				t.Fatalf("capture drops=%d, want %d", drops, tc.drops)
			}
			assertReadContextsEmpty(t, objs)
		})
	}
}

func TestLiveOpenSSLReadConcurrent(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for real OpenSSL concurrency acceptance")
	}
	bin := buildTLSCFixture(t, "tls_read_concurrent.c", "-lssl", "-lcrypto")
	output, err := exec.Command("ldd", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("resolve fixture's OpenSSL: %v\n%s", err, output)
	}
	var libssl string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.HasPrefix(fields[0], "libssl.so") && fields[1] == "=>" {
			libssl = fields[2]
		}
	}
	if !filepath.IsAbs(libssl) {
		t.Fatalf("no dynamic OpenSSL library in ldd output: %s", output)
	}
	objs := loadReadProbeObjects(t)
	attachOpenSSLReadProbes(t, libssl, objs)
	for mode, name := range []string{"legacy", "ex", "mixed"} {
		t.Run(name, func(t *testing.T) {
			before := readProbeDrops(t, objs)
			var arrived atomic.Int32
			gate := make(chan struct{})
			concurrency := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if arrived.Add(1) == 32 {
					// Do not send any response until every client is in a read.
					concurrency <- waitForReadContexts(objs, 32, 5*time.Second)
					close(gate)
				}
				select {
				case <-gate:
				case <-time.After(10 * time.Second):
					http.Error(w, "client barrier timed out", http.StatusGatewayTimeout)
					return
				}
				id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/reply-"))
				_, _ = fmt.Fprintf(w, "%s:%s", r.URL.Path, strings.Repeat(string(rune('a'+id%26)), 30+id*17))
			}))
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			connections, _ := compareReadProbeBytes(t, objs, exec.CommandContext(ctx, bin, port, strconv.Itoa(mode)))
			if connections != 32 {
				t.Fatalf("connections=%d, want 32", connections)
			}
			select {
			case err := <-concurrency:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("not all 32 clients reached the server")
			}
			if drops := readProbeDrops(t, objs) - before; drops != 0 {
				t.Fatalf("capture drops=%d", drops)
			}
			assertReadContextsEmpty(t, objs)
			t.Log("32 simultaneously blocked TLS reads matched exact return bytes; zero drops and retained contexts")
		})
	}
}

func buildTLSCFixture(t *testing.T, source string, libraries ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), strings.TrimSuffix(source, ".c"))
	args := []string{"-O0", "-g", "-fno-optimize-sibling-calls", "-pthread", "-o", bin, filepath.Join("testdata", source)}
	args = append(args, libraries...)
	if output, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}
	return bin
}

func loadReadProbeObjects(t *testing.T) *sensorbpfObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		t.Fatalf("load sensor: %+v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	exit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exit.Close() })
	executed, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executed.Close() })
	return &objs
}

func attachOpenSSLReadProbes(t *testing.T, path string, objs *sensorbpfObjects) {
	t.Helper()
	executable, err := link.OpenExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		symbol string
		enter  *ebpf.Program
		exit   *ebpf.Program
	}{
		{"SSL_read", objs.HandleSslReadEnter, objs.HandleSslReadExit},
		{"SSL_read_ex", objs.HandleSslReadExEnter, objs.HandleSslReadExExit},
	} {
		entry, err := executable.Uprobe(probe.symbol, probe.enter, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = entry.Close() })
		ret, err := executable.Uretprobe(probe.symbol, probe.exit, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ret.Close() })
	}
}

func compareReadProbeBytes(t *testing.T, objs *sensorbpfObjects, cmd *exec.Cmd) (int, int) {
	t.Helper()
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, stderr.String())
	}
	if err := reader.Flush(); err != nil {
		t.Fatal(err)
	}
	captured := map[string][]byte{}
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var event sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			t.Fatal(err)
		}
		if event.Kind != eventSSLRead {
			continue
		}
		if event.Daddr == 0 || event.Daddr > uint32(len(event.Path)) || event.Dport != 0 {
			t.Fatalf("invalid TLS chunk: bytes=%d truncated=%d", event.Daddr, event.Dport)
		}
		key := fmt.Sprintf("%#x", event.Conn)
		captured[key] = append(captured[key], event.Path[:event.Daddr]...)
	}
	expected := map[string][]byte{}
	decoder := json.NewDecoder(&stdout)
	reads := 0
	for {
		var row struct{ Conn, Hex string }
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		data, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		expected[row.Conn] = append(expected[row.Conn], data...)
		reads++
	}
	for conn, data := range expected {
		if got := captured[conn]; !bytes.Equal(got, data) {
			t.Errorf("connection %s: captured=%q, returned=%q", conn, got, data)
		}
		delete(captured, conn)
	}
	if len(captured) != 0 {
		t.Fatalf("unexpected captured connections: %v", captured)
	}
	return len(expected), reads
}

func readProbeDrops(t *testing.T, objs *sensorbpfObjects) uint64 {
	t.Helper()
	var drops uint64
	if err := objs.Drops.Lookup(uint32(0), &drops); err != nil {
		t.Fatal(err)
	}
	return drops
}

func readContextCount(objs *sensorbpfObjects) (int, error) {
	count := 0
	for _, m := range []*ebpf.Map{objs.SslReadBufs, objs.SslReadExBufs} {
		var key uint64
		var value sensorbpfSslReadStack
		it := m.Iterate()
		for it.Next(&key, &value) {
			count++
		}
		if err := it.Err(); err != nil {
			return count, err
		}
	}
	return count, nil
}

func waitForReadContexts(objs *sensorbpfObjects, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		count, err := readContextCount(objs)
		if err != nil {
			return err
		}
		if count == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("simultaneous read contexts=%d, want %d", count, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertReadContextsEmpty(t *testing.T, objs *sensorbpfObjects) {
	t.Helper()
	if count, err := readContextCount(objs); err != nil || count != 0 {
		t.Fatalf("retained read contexts=%d, error=%v", count, err)
	}
}
