package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func TestLiveOpenSSLConnectionLifecycle(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1 for OpenSSL connection-lifetime acceptance")
	}
	bin := buildTLSCFixture(t, "tls_lifecycle.c", "-lssl", "-lcrypto")
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
		t.Fatal("fixture has no dynamic libssl")
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
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "7")
		_, _ = fmt.Fprintf(w, "reply-%s", strings.TrimPrefix(r.URL.Path, "/phase-"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	events, stdout := captureLifecycleEvents(t, objs, bin, port)
	msgs, loss := reassembleLifecycle(events, false)
	requests, responses := map[string]tlsintent.Message{}, map[string]tlsintent.Message{}
	for _, msg := range msgs {
		if msg.Truncated {
			t.Fatalf("complete fixture unexpectedly truncated: %+v", msg)
		}
		if msg.Direction == tlsintent.Request {
			requests[msg.Path] = msg
		} else {
			responses[string(msg.Body)] = msg
		}
	}
	if len(msgs) != 10 || len(requests) != 5 || len(responses) != 5 {
		t.Fatalf("expected 5 requests and 5 responses: %+v", msgs)
	}
	epochs := make([]uint64, 5)
	var address uint64
	for i := 0; i < 5; i++ {
		req, resp := requests[fmt.Sprintf("/phase-%d", i)], responses[fmt.Sprintf("reply-%d", i)]
		if req.Epoch == 0 || req.Epoch != resp.Epoch || req.Conn != resp.Conn || req.ProcessStartNS == 0 {
			t.Fatalf("request/response lifetime differs: %+v / %+v", req, resp)
		}
		if i > 0 && address != req.Conn {
			t.Fatal("fixture must reuse exactly one SSL object address")
		}
		address, epochs[i] = req.Conn, req.Epoch
	}
	if epochs[0] != epochs[1] || epochs[2] <= epochs[1] || epochs[3] <= epochs[2] || epochs[4] <= epochs[3] {
		t.Fatalf("keepalive/clear/BIO/release generations incorrect: %v", epochs)
	}
	var expected bytes.Buffer
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	for i := 0; i < 5; i++ {
		var row struct {
			Phase int
			Hex   string
		}
		if err := decoder.Decode(&row); err != nil || row.Phase != i {
			t.Fatalf("read oracle: %+v %v", row, err)
		}
		data, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		expected.Write(data)
	}
	var observed bytes.Buffer
	for _, e := range events {
		if e.Kind == eventSSLRead {
			observed.Write(e.Path[:e.Daddr])
		}
	}
	if !bytes.Equal(expected.Bytes(), observed.Bytes()) || loss != (tlsintent.CaptureLoss{}) || readProbeDrops(t, objs) != 0 {
		t.Fatalf("real TLS bytes/loss mismatch: expected=%d observed=%d loss=%+v drops=%d", expected.Len(), observed.Len(), loss, readProbeDrops(t, objs))
	}
	assertReadContextsEmpty(t, objs)
	t.Log("five HTTPS exchanges: keepalive stable; clear, BIO rebind and reference release isolated; exact response bytes, zero capture gaps")
}

func TestLiveOpenSSLLifetimePairing(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1")
	}
	bin := buildTLSCFixture(t, "ssl_lifecycle_pairing.c")
	objs := loadReadProbeObjects(t)
	executable, err := link.OpenExecutable(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct {
		name    string
		program *ebpf.Program
		ret     bool
	}{
		{"SSL_new", objs.HandleSslNew, true}, {"SSL_free", objs.HandleSslRelease, false},
		{"SSL_clear", objs.HandleSslReset, false}, {"SSL_write", objs.HandleSslWrite, false},
		{"SSL_read", objs.HandleSslReadEnter, false}, {"SSL_read", objs.HandleSslReadExit, true},
	} {
		var attached link.Link
		if probe.ret {
			attached, err = executable.Uretprobe(probe.name, probe.program, nil)
		} else {
			attached, err = executable.Uprobe(probe.name, probe.program, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = attached.Close() })
	}
	for _, mode := range []string{"reuse", "late-read"} {
		t.Run(mode, func(t *testing.T) {
			events, _ := captureLifecycleEvents(t, objs, bin, mode)
			for _, skipBoundary := range []bool{false, true} {
				msgs, _ := reassembleLifecycle(events, skipBoundary)
				var complete int
				var oldEpoch, newEpoch uint64
				for _, e := range events {
					if e.Kind == eventSSL {
						if oldEpoch == 0 {
							oldEpoch = e.ConnEpoch
						} else {
							newEpoch = e.ConnEpoch
						}
					}
					if e.Kind == eventSSLRead && e.ConnEpoch != oldEpoch {
						t.Fatal("late read was stamped with the new generation")
					}
				}
				if oldEpoch == 0 || newEpoch <= oldEpoch {
					t.Fatalf("address reuse did not change generation: %d/%d", oldEpoch, newEpoch)
				}
				for _, msg := range msgs {
					if msg.Truncated && mode == "reuse" && !skipBoundary && msg.Path == "/old" {
						continue
					}
					if msg.Path != "/new" || msg.Direction != tlsintent.Request || msg.Epoch != newEpoch {
						t.Fatalf("stale plaintext survived (skip=%v): %+v", skipBoundary, msg)
					}
					complete++
				}
				if complete != 1 {
					t.Fatalf("new request count=%d (skip=%v)", complete, skipBoundary)
				}
			}
			assertReadContextsEmpty(t, objs)
		})
	}
}

func TestLiveOpenSSLLifecycleAttachmentFailure(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("set AGENTPROV_LIVE_OPENSSL=1")
	}
	bin := buildTLSCFixture(t, "ssl_lifecycle_pairing.c")
	identity, err := tlsFileIdentity(bin)
	if err != nil {
		t.Fatal(err)
	}
	objs := loadReadProbeObjects(t)
	a := attachTLSTarget(tlsTarget{Path: bin, Key: "openssl:" + identity, Kind: "openssl"}, objs, nil)
	defer a.close()
	blocked := 0
	for _, probe := range a.probes {
		switch probe.Name {
		case "SSL_read", "SSL_read_ex", "SSL_write", "SSL_write_ex":
			if probe.Status != "failed" || !strings.Contains(probe.Reason, "connection-lifecycle") {
				t.Fatalf("partial lifecycle set enabled plaintext: %+v", probe)
			}
			blocked++
		}
	}
	if blocked != 4 {
		t.Fatalf("blocked plaintext probes=%d", blocked)
	}
}

func captureLifecycleEvents(t *testing.T, objs *sensorbpfObjects, bin string, args ...string) ([]sensorbpfSensorEvent, []byte) {
	t.Helper()
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, stderr.String())
	}
	if err := reader.Flush(); err != nil {
		t.Fatal(err)
	}
	var events []sensorbpfSensorEvent
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrFlushed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var e sensorbpfSensorEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			t.Fatal(err)
		}
		if e.Pid == uint32(cmd.Process.Pid) {
			events = append(events, e)
		}
	}
	return events, stdout.Bytes()
}

func reassembleLifecycle(events []sensorbpfSensorEvent, skipBoundary bool) ([]tlsintent.Message, tlsintent.CaptureLoss) {
	r := tlsintent.NewReassembler()
	var messages []tlsintent.Message
	for _, e := range events {
		c := tlsintent.Chunk{PID: e.Pid, Conn: e.Conn, ProcessStartNS: e.ProcessStartNs, Epoch: e.ConnEpoch}
		switch e.Kind {
		case eventSSL, eventSSLRead:
			c.Direction = tlsintent.Request
			if e.Kind == eventSSLRead {
				c.Direction = tlsintent.Response
			}
			c.Data, c.Truncated = e.Path[:e.Daddr], e.Dport == 1
			messages = append(messages, r.Add(c)...)
		case eventSSLReset:
			if !skipBoundary {
				r.Reset(c)
			}
		case eventSSLRelease:
			if !skipBoundary {
				messages = append(messages, r.Release(c)...)
			}
		case eventExit:
			messages = append(messages, r.EndProcess(e.Pid, e.ProcessStartNs, false)...)
		case eventExec:
			r.EndProcess(e.Pid, e.ProcessStartNs, true)
		}
	}
	return messages, r.TakeLoss()
}
