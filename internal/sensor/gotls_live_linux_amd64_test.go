package sensor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Run as root with AGENTPROV_LIVE_GOTLS=1 on a BTF-enabled amd64 Linux host.
// This compares every captured byte against the bytes actually returned to 32
// concurrent goroutines, with forced stack growth within their TLS reads.
func TestLiveGoTLSReadConcurrentStackGrowth(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_GOTLS") != "1" {
		t.Skip("set AGENTPROV_LIVE_GOTLS=1 for real eBPF Go TLS acceptance")
	}
	bin := filepath.Join(t.TempDir(), "go-tls-concurrent")
	if output, err := exec.Command("go", "build", "-o", bin, "testdata/go_tls_concurrent.go").CombinedOutput(); err != nil {
		t.Fatalf("build client: %v\n%s", err, output)
	}
	offsets, err := goTLSReadReturnOffsets(bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("attaching Read entry and %d decoded return sites", len(offsets))
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objs sensorbpfObjects
	if err := loadSensorbpfObjects(&objs, nil); err != nil {
		t.Fatalf("load sensor: %+v", err)
	}
	defer objs.Close()
	executable, err := link.OpenExecutable(bin)
	if err != nil {
		t.Fatal(err)
	}
	links, err := attachGoTLSRead(executable, bin, &objs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Distinct lengths and bytes make goroutine/context mix-ups observable.
		time.Sleep(2 * time.Millisecond)
		id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/reply-"))
		_, _ = fmt.Fprintf(w, "%s:%s", r.URL.Path, strings.Repeat(string(rune('a'+id%26)), 30+id*17))
	}))
	defer server.Close()
	cmd := exec.Command(bin, server.Listener.Addr().String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	events := make(chan []sensorbpfSensorEvent, 1)
	readErrors := make(chan error, 1)
	go func() {
		var captured []sensorbpfSensorEvent
		for {
			record, err := reader.Read()
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, ringbuf.ErrFlushed) {
				events <- captured
				return
			}
			if err != nil {
				readErrors <- err
				return
			}
			var event sensorbpfSensorEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				readErrors <- err
				return
			}
			// The probes target this test's unique temporary executable inode.
			// Kernel initial-namespace PIDs can differ from os/exec's PID in WSL.
			if event.Kind == eventSSLRead {
				captured = append(captured, event)
			}
		}
	}()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("client: %v\n%s", err, stderr.String())
	}
	// Drain queued records before stopping; Close could skip a final record.
	if err := reader.Flush(); err != nil {
		t.Fatal(err)
	}
	var captured []sensorbpfSensorEvent
	select {
	case captured = <-events:
	case err := <-readErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("ring reader did not finish")
	}
	byConnection := map[string][]byte{}
	for _, event := range captured {
		if event.Daddr == 0 || event.Daddr > uint32(len(event.Path)) || event.Dport != 0 {
			t.Fatalf("invalid captured chunk: bytes=%d truncated=%d", event.Daddr, event.Dport)
		}
		key := fmt.Sprintf("%#x", event.Conn)
		byConnection[key] = append(byConnection[key], event.Path[:event.Daddr]...)
	}
	decoder := json.NewDecoder(&stdout)
	count := 0
	for {
		var result struct {
			Conn string `json:"conn"`
			Data []byte `json:"data"`
		}
		if err := decoder.Decode(&result); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
		if got := byConnection[result.Conn]; !bytes.Equal(got, result.Data) {
			t.Errorf("connection %s: captured %d bytes, actual Read bytes %d", result.Conn, len(got), len(result.Data))
		}
		delete(byConnection, result.Conn)
	}
	if count != 32 || len(byConnection) != 0 {
		t.Fatalf("connections: actual=%d unexpected captured=%d", count, len(byConnection))
	}
	var drops uint64
	if err := objs.Drops.Lookup(uint32(0), &drops); err != nil || drops != 0 {
		t.Fatalf("capture drops=%d error=%v", drops, err)
	}
	var key sensorbpfGoReadKey
	var value sensorbpfGoReadCtx
	it := objs.GoReadBufs.Iterate()
	if it.Next(&key, &value) || it.Err() != nil {
		t.Fatalf("Read contexts were not reclaimed: key=%+v error=%v", key, it.Err())
	}
	t.Logf("32 concurrent TLS connections matched exact return bytes (%d chunks), zero drops, zero retained contexts", len(captured))
}
