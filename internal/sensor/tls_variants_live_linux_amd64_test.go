package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Accepts fixture paths prepared from upstream BoringSSL. No external server or
// credentials are used. Every first request begins immediately after readiness.
func TestLiveTLSKnownFirstRequest(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_OPENSSL") != "1" {
		t.Skip("opt-in live TLS acceptance")
	}
	for _, mode := range []string{"stripped-go", "stripped-go-pie", "boringssl-shared", "boringssl-static", "system-openssl"} {
		t.Run(mode, func(t *testing.T) {
			var target, bin string
			if strings.HasPrefix(mode, "stripped-go") {
				bin = filepath.Join(t.TempDir(), "tls-client")
				args := []string{"build", "-ldflags=-s -w", "-o", bin}
				if mode == "stripped-go-pie" {
					args = append(args, "-buildmode=pie")
				}
				args = append(args, "testdata/tls_client.go")
				if output, err := exec.Command("go", args...).CombinedOutput(); err != nil {
					t.Fatalf("build: %v %s", err, output)
				}
				target = bin
			} else if mode == "system-openssl" {
				bin = buildTLSCFixture(t, "tls_first_request.c", "-lssl", "-lcrypto")
			} else {
				prefix := os.Getenv("AGENTPROV_LIVE_BORINGSSL")
				if prefix == "" {
					t.Skip("set AGENTPROV_LIVE_BORINGSSL to fixture directory")
				}
				bin = filepath.Join(prefix, mode)
				target = bin
				if mode == "boringssl-shared" {
					target = filepath.Join(prefix, "libssl.so")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready, done := make(chan struct{}), make(chan error, 1)
			var out bytes.Buffer
			var capability CapabilityReport
			opts := Options{Context: ctx, AutoTLS: mode == "system-openssl", Diagnostics: io.Discard, OnReady: func() { close(ready) }, OnCapabilities: func(r CapabilityReport) { capability = r }}
			if target != "" {
				opts.TLSTargets = []string{target}
			}
			go func() { done <- RunWithOptions(&out, opts) }()
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
				t.Fatalf("start: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("readiness timeout")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprint(len("PUBLIC-FIRST-TLS-REPLY!!")))
				io.WriteString(w, "PUBLIC-FIRST-TLS-REPLY!!")
			}))
			defer server.Close()
			var cmd *exec.Cmd
			if strings.HasPrefix(mode, "stripped-go") {
				cmd = exec.Command(bin, server.URL+"/first-request", "PUBLIC-FIRST-TLS-REQUEST")
			} else {
				cmd = exec.Command(bin, server.Listener.Addr().String())
			}
			cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+os.Getenv("AGENTPROV_LIVE_BORINGSSL"), "AGENTPROV_TLS_START_DELAY_MS=0", "AGENTPROV_TLS_START_DELAY_SECONDS=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("client: %v %s", err, output)
			}
			time.Sleep(200 * time.Millisecond)
			cancel()
			err := <-done
			stopped = true
			if err != nil {
				t.Fatal(err)
			}
			request, response := false, false
			for _, line := range bytes.Split(out.Bytes(), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				var e map[string]any
				if err := json.Unmarshal(line, &e); err != nil {
					t.Fatal(err)
				}
				if e["event_type"] == "resource_pressure" {
					if mode != "system-openssl" {
						t.Fatalf("capture loss: %s", line)
					}
					t.Logf("node-wide pressure during automatic discovery: %s", line)
				}
				pid, _ := e["pid"].(float64)
				if local, ok := e["procfs_pid"].(float64); ok {
					pid = local
				}
				if int(pid) != cmd.Process.Pid {
					continue
				}
				if e["capture"] != nil {
					t.Fatalf("first request has a capture gap: %s", line)
				}
				if e["event_type"] == "tls_write" && bytes.Contains(line, []byte("first-request")) {
					request = true
				}
				if e["event_type"] == "tls_read" && e["data"] == "PUBLIC-FIRST-TLS-REPLY!!" {
					response = true
				}
			}
			for _, p := range capability.Probes {
				relevant := mode != "system-openssl" || strings.Contains(p.Target, "libssl.so")
				if relevant && p.Category == "tls" && (p.Status == "failed" || p.Status == "unsupported") {
					t.Errorf("TLS gap: %+v", p)
				}
			}
			if !request || !response {
				t.Fatalf("first request=%v response=%v capture=%s", request, response, out.String())
			}
			t.Log(fmt.Sprintf("%s: first request and response captured, no discovery delay, tested target has no gaps", mode))
		})
	}
}
