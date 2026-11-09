//go:build linux && (amd64 || arm64)

package sensor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
	"github.com/cilium/ebpf/ringbuf"
)

func TestLiveOpenSSLCaptureGapKeepalive(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for real TLS capture-limit acceptance")
	}
	bin := buildTLSCFixture(t, "tls_capture_gap.c", "-lssl", "-lcrypto")
	output, err := exec.Command("ldd", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("ldd: %v\n%s", err, output)
	}
	var library string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.HasPrefix(fields[0], "libssl.so") && fields[1] == "=>" {
			library = fields[2]
		}
	}
	if !filepath.IsAbs(library) {
		t.Fatal("fixture has no dynamic OpenSSL")
	}
	identity, err := tlsFileIdentity(library)
	if err != nil {
		t.Fatal(err)
	}
	objs := loadReadProbeObjects(t)
	attachment := attachTLSTarget(tlsTarget{Path: library, Key: "openssl:" + identity, Kind: "openssl"}, objs, nil)
	defer attachment.close()
	for _, probe := range attachment.probes {
		if probe.Status != "attached" {
			t.Fatalf("%s: %s %s", probe.Name, probe.Status, probe.Reason)
		}
	}
	for _, total := range []int{4095, 4096, 4097, 8192, 1048577} {
		for _, ex := range []int{0, 1} {
			t.Run(fmt.Sprintf("bytes=%d/ex=%d", total, ex), func(t *testing.T) {
				dropsBefore := readProbeDrops(t, objs)
				received := make(chan int, 2)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil {
						t.Error(err)
					}
					received <- int(n)
					w.Header().Set("Content-Length", "2")
					_, _ = io.WriteString(w, "ok")
				}))
				defer server.Close()
				_, port, err := net.SplitHostPort(server.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				events, stdout := captureLifecycleEvents(t, objs, bin, port, strconv.Itoa(total), strconv.Itoa(ex))
				wantBody, err := strconv.Atoi(strings.TrimSpace(string(stdout)))
				if err != nil || len(received) != 2 || <-received != wantBody || <-received != 0 {
					t.Fatalf("real server did not receive both exact requests: %s %v", stdout, err)
				}
				messages, loss := reassembleLifecycle(events, false)
				skipped := total > (1<<20) && ex == 1
				wantReason, wantFragments, wantDrops := tlsintent.GapCaptureLimit, 2, uint64(0)
				if skipped {
					wantReason, wantFragments, wantDrops = tlsintent.GapCallSequence, 1, 1
				}
				requests, responses, fragments := 0, 0, 0
				for _, m := range messages {
					if m.Direction == tlsintent.Response {
						if m.Truncated || string(m.Body) != "ok" {
							t.Fatalf("independent response capture regressed: %+v", m)
						}
						responses++
						continue
					}
					if total <= 4096 {
						if m.Truncated || (m.Path != "/large" && m.Path != "/after") {
							t.Fatalf("healthy keepalive changed: %+v", m)
						}
						requests++
					} else {
						if !m.Truncated || m.DataKind != tlsintent.DataTLSFragment || m.CaptureGap != wantReason || m.Method != "" {
							t.Fatalf("known capture gap yielded HTTP intent: %+v", m)
						}
						fragments++
					}
				}
				if responses != 2 || (total <= 4096 && (requests != 2 || loss.Streams != 0)) ||
					(total > 4096 && (requests != 0 || fragments != wantFragments || loss.Streams != 1)) || readProbeDrops(t, objs)-dropsBefore != wantDrops {
					t.Fatalf("requests=%d responses=%d fragments=%d loss=%+v drops=%d", requests, responses, fragments, loss, readProbeDrops(t, objs))
				}
				t.Logf("real HTTPS: total=%d ex=%d requests=%d responses=%d fragments=%d loss=%+v", total, ex, requests, responses, fragments, loss)
				if total == 4096 {
					assertTLSSequenceLossReplay(t, events)
				}
			})
		}
	}
}

func TestLiveOpenSSLRingLossSequence(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for ring-buffer exhaustion acceptance")
	}
	bin := buildTLSCFixture(t, "tls_capture_gap.c", "-lssl", "-lcrypto")
	linked, err := exec.Command("ldd", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("ldd: %v %s", err, linked)
	}
	var library string
	for _, line := range strings.Split(string(linked), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "libssl.so.3" && fields[1] == "=>" {
			library = fields[2]
		}
	}
	identity, err := tlsFileIdentity(library)
	if err != nil {
		t.Fatal(err)
	}
	// Eight KiB cannot hold the first call's 16 records, but holds the short
	// second exchange and closing checkpoints after the consumer drains it.
	objs := loadReadProbeObjectsWithRingSize(t, 8192)
	a := attachTLSTarget(tlsTarget{Path: library, Key: "openssl:" + identity, Kind: "openssl"}, objs, nil)
	defer a.close()
	for _, probe := range a.probes {
		if probe.Status != "attached" {
			t.Fatalf("%s: %s %s", probe.Name, probe.Status, probe.Reason)
		}
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	var events []sensorbpfSensorEvent
	drain := func() {
		t.Helper()
		if err := rd.Flush(); err != nil {
			t.Fatal(err)
		}
		for {
			record, err := rd.Read()
			if errors.Is(err, ringbuf.ErrFlushed) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var e sensorbpfSensorEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
	}
	received := make(chan int, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Error(err)
		}
		received <- int(n)
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, port, "4096", "1", "gated")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	barrier := func(want string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != want {
			t.Fatalf("barrier %s: %q %v", want, line, err)
		}
		drain()
		if _, err := io.WriteString(stdin, "x"); err != nil {
			t.Fatal(err)
		}
	}
	barrier("ready")
	// Do not consume while the first call fills the actual kernel ring buffer.
	barrier("first-complete")
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("fixture: %v %s", err, stderr.String())
	}
	drain()
	want, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || len(received) != 2 || <-received != want || <-received != 0 {
		t.Fatalf("real requests incomplete: %s %v", output, err)
	}
	var pid uint32
	for _, e := range events {
		if e.Kind == eventExec && string(bytes.TrimRight(e.Path[:], "\x00")) == bin {
			pid = e.Pid
		}
	}
	if pid == 0 {
		t.Fatal("fixture process not captured")
	}
	filtered := events[:0]
	for _, e := range events {
		if e.Pid == pid {
			filtered = append(filtered, e)
		}
	}
	got, loss := reassembleLifecycle(filtered, false)
	fragments := 0
	for _, m := range got {
		if m.Direction == tlsintent.Request {
			if !m.Truncated || m.Method != "" || m.Position == nil {
				t.Fatalf("real ring loss generated HTTP intent: %+v", m)
			}
			fragments++
		}
	}
	drops := readProbeDrops(t, objs)
	if drops == 0 || loss.Streams == 0 || fragments < 2 {
		t.Fatalf("fault did not exercise sequence detection: drops=%d loss=%+v fragments=%d", drops, loss, fragments)
	}
	t.Logf("actual ring exhaustion: kernel drops=%d sequence gaps=%d request fragments=%d, both requests reached server", drops, loss.Streams, fragments)
}

// Replay deliberate transport faults over actual kernel-produced call IDs and
// offsets. Ring-buffer exhaustion has its own live test below.
func assertTLSSequenceLossReplay(t *testing.T, events []sensorbpfSensorEvent) {
	t.Helper()
	first, second, checkpoint := 0, 0, false
	for _, e := range events {
		if e.Kind == eventSSL {
			if e.TlsStream == 0 || e.TlsCall == 0 || e.TlsOffset+e.Daddr > min(uint32(e.ExitCode), uint32(tlsintent.CallCaptureLimit)) {
				t.Fatalf("invalid producer position: %+v", tlsChunk(e).Position)
			}
			if e.TlsCall == 1 {
				first++
			}
			if e.TlsCall == 2 {
				second++
			}
		}
		checkpoint = checkpoint || (e.Kind == eventSSLCheckpoint && e.Dport == 0 && e.TlsCall == 2)
	}
	if first != 16 || second != 1 || !checkpoint {
		t.Fatalf("producer sequence or closing watermark missing: first=%d second=%d checkpoint=%v", first, second, checkpoint)
	}
	for _, fault := range []string{"middle", "first_call", "last_call", "last_chunk", "duplicate", "reorder"} {
		t.Run("transport_"+fault, func(t *testing.T) {
			var replay []sensorbpfSensorEvent
			for _, e := range events {
				if e.Kind == eventSSL {
					switch {
					case fault == "middle" && e.TlsCall == 1 && e.TlsOffset == 256,
						fault == "first_call" && e.TlsCall == 1,
						fault == "last_call" && e.TlsCall == 2,
						fault == "last_chunk" && e.TlsCall == 1 && e.TlsOffset == 3840:
						continue
					}
					if fault == "duplicate" {
						replay = append(replay, e)
					}
				}
				replay = append(replay, e)
			}
			if fault == "reorder" {
				var positions []int
				for i, e := range replay {
					if e.Kind == eventSSL && e.TlsCall == 1 {
						positions = append(positions, i)
					}
				}
				replay[positions[0]], replay[positions[1]] = replay[positions[1]], replay[positions[0]]
			}
			got, loss := reassembleLifecycle(replay, false)
			complete, responses, fragments := 0, 0, 0
			for _, m := range got {
				if m.Direction == tlsintent.Response {
					if m.Truncated || string(m.Body) != "ok" {
						t.Fatalf("independent response changed: %+v", m)
					}
					responses++
				} else if m.Truncated {
					if m.Method != "" || m.DataKind != tlsintent.DataTLSFragment || m.Position == nil {
						t.Fatalf("fragment lost position or acquired HTTP semantics: %+v", m)
					}
					fragments++
				} else {
					complete++
				}
			}
			wantComplete := 0
			if fault == "duplicate" {
				wantComplete = 2
			} else if fault == "last_call" {
				wantComplete = 1
			}
			if complete != wantComplete || responses != 2 || (fault != "duplicate" && (fragments == 0 || loss.Streams == 0)) ||
				(fault == "duplicate" && (fragments != 0 || loss.Streams != 0)) {
				t.Fatalf("complete=%d responses=%d fragments=%d loss=%+v", complete, responses, fragments, loss)
			}
			t.Logf("kernel capture fault replay: complete=%d responses=%d fragments=%d gaps=%d", complete, responses, fragments, loss.Streams)
		})
	}
}
