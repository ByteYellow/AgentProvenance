//go:build linux && (amd64 || arm64)

package telemetry

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/proto"
)

func collectorTestConfig(t *testing.T) seccheck.CollectionConfig {
	t.Helper()
	dir, err := os.MkdirTemp("", "ap-scc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return seccheck.CollectionConfig{SchemaVersion: seccheck.CollectionConfigSchema, RuntimeRelease: seccheck.RuntimeRelease, Targets: []seccheck.Target{{RunID: "sentry-run", SocketPath: filepath.Join(dir, "events.sock"), Registration: seccheck.Registration{Namespace: "lab", InstanceID: "node", Generation: "1", SandboxID: "sandbox", ContainerID: "container", PeerUID: uint32(os.Geteuid())}}}}
}

func TestSecCheckCollectorConnectionRecoveryAndShutdown(t *testing.T) {
	db, paths := nativeTestStore(t)
	config := collectorTestConfig(t)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	var mu sync.Mutex
	var latest SecCheckCollectStatus
	done := make(chan error, 1)
	go func() {
		done <- CollectSecCheck(ctx, db, paths, config, SecCheckCollectOptions{StatusInterval: 100 * time.Millisecond, Stream: NativeStreamOptions{BatchEvents: 1}}, func(s SecCheckCollectStatus) error { mu.Lock(); latest = s; mu.Unlock(); return nil })
	}()
	joined := false
	defer func() {
		stop()
		if !joined {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	wait := func(check func(SecCheckCollectStatus) bool) SecCheckCollectStatus {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			mu.Lock()
			s := latest
			mu.Unlock()
			if check(s) {
				return s
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("collector state did not arrive")
		return SecCheckCollectStatus{}
	}
	wait(func(s SecCheckCollectStatus) bool { return s.State == "listening" })
	connectionIDs := map[string]bool{}
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: config.Targets[0].SocketPath, Net: "unixpacket"})
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write([]byte{8, 1}); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		var reply [256]byte
		if n, err := conn.Read(reply[:]); err != nil || n != 2 {
			conn.Close()
			t.Fatalf("handshake: %d %v", n, err)
		}
		c := secCheckTestContext()
		c.ThreadStartTimeNs = 0
		body, err := proto.Marshal(&wire.Open{ContextData: c, Pathname: "/tmp/report", Exit: &wire.Exit{Result: 3}})
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		header := make([]byte, 8)
		binary.LittleEndian.PutUint16(header, 8)
		binary.LittleEndian.PutUint16(header[2:], uint16(wire.MessageType_MESSAGE_SYSCALL_OPEN))
		binary.LittleEndian.PutUint32(header[4:], 3)
		if _, err = conn.Write(append(header, body...)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		s := wait(func(s SecCheckCollectStatus) bool {
			return len(s.Targets) == 1 && s.Targets[0].State == "disconnected" && s.Targets[0].AcceptedRecords >= uint64((attempt+1)*3)
		})
		connectionIDs[s.Targets[0].ConnectionID] = true
	}
	stop()
	err := <-done
	joined = true
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	final := latest
	mu.Unlock()
	if final.State != "stopped" || final.Spool.PendingEvents != 0 || final.Spool.QueuedBytes != 0 || final.Targets[0].ReportedDrops != 6 || final.Targets[0].IdentityGapRecords != 2 || len(connectionIDs) != 2 {
		t.Fatalf("final: %+v", final)
	}
	health, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "sentry-run"})
	if err != nil || health.SecCheckCapture.Counters["connected"] != 2 || health.SecCheckCapture.Counters["reported_dropped_events"] != 6 || health.Coverage.Complete {
		t.Fatalf("health: %+v %v", health, err)
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM events WHERE source='gvisor_seccheck' AND payload LIKE '%receiver_ready%'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	e, err := readSecCheckEvidence(payload)
	if err != nil || e.Capabilities == nil || e.Capabilities.IdentityDomain != "sentry" {
		t.Fatalf("saved capability: %+v %v", e, err)
	}
	if _, err := os.Stat(config.Targets[0].SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket retained: %v", err)
	}
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestSecCheckCollectorFailureReleasesAllListeners(t *testing.T) {
	for _, failure := range []string{"listener", "report", "queue"} {
		t.Run(failure, func(t *testing.T) {
			db, paths := nativeTestStore(t)
			config := collectorTestConfig(t)
			opts := SecCheckCollectOptions{DrainTimeout: time.Second, StatusInterval: 100 * time.Millisecond}
			if failure == "listener" {
				second := config.Targets[0]
				second.Registration.SandboxID = "other"
				second.SocketPath = filepath.Join(filepath.Dir(second.SocketPath), "missing", "other.sock")
				config.Targets = append(config.Targets, second)
			}
			if failure == "queue" {
				n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchBytes: 8192, MaxQueuedBytes: 8192})
				nativeWrite(t, n, "host", "/tmp/existing")
				opts.Stream = NativeStreamOptions{BatchBytes: 8192, MaxQueuedBytes: 8192}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := CollectSecCheck(ctx, db, paths, config, opts, func(s SecCheckCollectStatus) error {
				if failure == "report" && s.State == "listening" {
					return errors.New("status writer failed")
				}
				return nil
			})
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("failure hidden or timed out: %v", err)
			}
			if failure == "report" && !strings.Contains(err.Error(), "status writer failed") {
				t.Fatal(err)
			}
			for _, target := range config.Targets {
				if _, err := os.Stat(target.SocketPath); !os.IsNotExist(err) {
					t.Fatalf("listener retained: %v", err)
				}
			}
			s, err := NewSecCheckStream(db, paths, NativeStreamOptions{})
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
		})
	}
}
