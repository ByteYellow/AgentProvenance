//go:build linux && (amd64 || arm64)

package sensor

import (
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

	"github.com/byteyellow/agentprovenance/internal/tlsintent"
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
	for _, total := range []int{4095, 4096, 4097, 8192} {
		for _, ex := range []int{0, 1} {
			t.Run(fmt.Sprintf("bytes=%d/ex=%d", total, ex), func(t *testing.T) {
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
						if !m.Truncated || m.DataKind != tlsintent.DataTLSFragment || m.CaptureGap != tlsintent.GapCaptureLimit || m.Method != "" {
							t.Fatalf("known capture gap yielded HTTP intent: %+v", m)
						}
						fragments++
					}
				}
				if responses != 2 || (total <= 4096 && (requests != 2 || loss.Streams != 0)) ||
					(total > 4096 && (requests != 0 || fragments != 2 || loss.Streams != 1)) || readProbeDrops(t, objs) != 0 {
					t.Fatalf("requests=%d responses=%d fragments=%d loss=%+v drops=%d", requests, responses, fragments, loss, readProbeDrops(t, objs))
				}
				t.Logf("real HTTPS: total=%d ex=%d requests=%d responses=%d fragments=%d loss=%+v", total, ex, requests, responses, fragments, loss)
			})
		}
	}
}
