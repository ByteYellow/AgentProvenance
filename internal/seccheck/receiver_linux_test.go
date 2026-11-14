//go:build linux && (amd64 || arm64)

package seccheck

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

type testReceiver struct {
	path    string
	cancel  context.CancelFunc
	done    chan error
	mu      sync.Mutex
	records []Record
}

func startTestReceiver(t *testing.T, reg Registration, fail error) *testReceiver {
	t.Helper()
	dir, err := os.MkdirTemp("", "ap-sc-")
	if err != nil {
		t.Fatal(err)
	}
	s := &testReceiver{path: filepath.Join(dir, "events.sock"), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	r := Receiver{SocketPath: s.path, Registration: reg, HandshakeTimeout: 100 * time.Millisecond, Sink: func(_ context.Context, r Record) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.records) >= 10000 {
			return errors.New("test event bound exceeded")
		}
		s.records = append(s.records, r)
		if fail != nil && r.Kind == "event" {
			return fail
		}
		return nil
	}}
	go func() { s.done <- r.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Error("receiver did not stop")
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if info, err := os.Stat(s.path); err == nil {
			if info.Mode().Perm() != 0o600 {
				time.Sleep(time.Millisecond)
				continue
			}
			return s
		}
		select {
		case err := <-s.done:
			s.done <- err
			t.Fatalf("receiver start: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("receiver did not listen")
	return nil
}

func (s *testReceiver) snapshot() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.records...)
}

func (s *testReceiver) wait(t *testing.T, check func([]Record) bool) []Record {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		rows := s.snapshot()
		if check(rows) {
			return rows
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("records not received: %+v", s.snapshot())
	return nil
}

func dialTest(t *testing.T, path string, handshake bool) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if handshake {
		if _, err := c.Write([]byte{8, 1}); err != nil {
			t.Fatal(err)
		}
		var b [256]byte
		n, err := c.Read(b[:])
		if err != nil || n != 2 || b[0] != 8 || b[1] != 1 {
			t.Fatalf("handshake: %x %v", b[:n], err)
		}
	}
	return c
}

func TestReceiverStreamLossAndReconnect(t *testing.T) {
	reg := testRegistration()
	reg.PeerUID = uint32(os.Geteuid())
	s := startTestReceiver(t, reg, nil)
	c := dialTest(t, s.path, true)
	for _, drop := range []uint32{4, 9, 1, 1} {
		if _, err := c.Write(packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: testContext()}, drop)); err != nil {
			t.Fatal(err)
		}
	}
	unknown := packetBytes(t, 65000, &wire.Open{}, 3)
	if _, err := c.Write(unknown); err != nil {
		t.Fatal(err)
	}
	foreign := testContext()
	foreign.ContainerId = "other"
	if _, err := c.Write(packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: foreign}, 3)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	rows := s.wait(t, func(r []Record) bool { return len(r) >= 8 })
	if rows[0].Reason != "connected" || rows[7].Reason != "disconnected" || rows[7].Identity.Task != "" {
		t.Fatalf("stream boundaries: %+v", rows)
	}
	if *rows[1].DroppedDelta != 4 || *rows[2].DroppedDelta != 5 || rows[3].DroppedDelta != nil || !rows[3].DropCounterDecreased || *rows[4].DroppedDelta != 0 {
		t.Fatal("invalid loss interpretation")
	}
	if rows[5].Reason != "unsupported_message_type" || rows[6].Reason != "container_identity_rejected" || rows[6].Packet.Message != nil {
		t.Fatal("unknown/foreign payload handling")
	}
	c2 := dialTest(t, s.path, true)
	c2.Write(packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: testContext()}, 1))
	c2.Close()
	rows = s.wait(t, func(r []Record) bool { return len(r) >= 11 })
	if rows[8].ConnectionID == rows[0].ConnectionID || rows[9].Sequence != 1 || *rows[9].DroppedDelta != 1 || rows[9].Identity.Task != rows[1].Identity.Task {
		t.Fatal("reconnect changed lifetime or reused transport identity")
	}
}

func TestReceiverPeerAndHandshakeRejection(t *testing.T) {
	reg := testRegistration()
	reg.PeerUID = uint32(os.Geteuid()) + 1
	s := startTestReceiver(t, reg, nil)
	c := dialTest(t, s.path, false)
	c.Write([]byte{8, 1})
	c.Close()
	s.wait(t, func(r []Record) bool { return len(r) == 1 && r[0].Reason == "peer_uid_rejected" })
	reg.PeerUID = uint32(os.Geteuid())
	for _, payload := range [][]byte{{8, 2}, {0xff}, make([]byte, MaxHandshakeBytes+1)} {
		s := startTestReceiver(t, reg, nil)
		c := dialTest(t, s.path, false)
		c.Write(payload)
		c.Close()
		s.wait(t, func(r []Record) bool { return len(r) == 1 && r[0].ProtocolVersion == 0 && r[0].Kind == "stream" })
	}
	s2 := startTestReceiver(t, reg, nil)
	c2 := dialTest(t, s2.path, false)
	s2.wait(t, func(r []Record) bool { return len(r) == 1 && r[0].Reason == "handshake_read_failed" })
	c2.Close()
}

func TestReceiverDoesNotReplaceLiveConnectionOrExistingPath(t *testing.T) {
	reg := testRegistration()
	reg.PeerUID = uint32(os.Geteuid())
	s := startTestReceiver(t, reg, nil)
	c := dialTest(t, s.path, true)
	other := dialTest(t, s.path, false)
	other.Write([]byte{8, 1})
	var b [10]byte
	if _, err := other.Read(b[:]); err == nil {
		t.Fatal("competing connection accepted")
	}
	c.Write(packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: testContext()}, 0))
	s.wait(t, func(r []Record) bool { return len(r) >= 2 && r[1].Kind == "event" })
	r := Receiver{SocketPath: s.path, Registration: reg, Sink: func(context.Context, Record) error { return nil }}
	if err := r.Serve(context.Background()); err == nil {
		t.Fatal("replaced active listener")
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestReceiverPersistenceFailureStopsStream(t *testing.T) {
	reg := testRegistration()
	reg.PeerUID = uint32(os.Geteuid())
	want := errors.New("storage full")
	s := startTestReceiver(t, reg, want)
	c := dialTest(t, s.path, true)
	c.Write(packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: testContext()}, 0))
	select {
	case err := <-s.done:
		s.done <- err
		if !errors.Is(err, want) {
			t.Fatalf("sink failure hidden: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver continued after persistence error")
	}
}

func TestReceiverPrivateDirectoryAndCancellation(t *testing.T) {
	reg := testRegistration()
	reg.PeerUID = uint32(os.Geteuid())
	r := Receiver{SocketPath: filepath.Join(t.TempDir(), "events.sock"), Registration: reg, Sink: func(context.Context, Record) error { return nil }}
	if err := os.Chmod(filepath.Dir(r.SocketPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.Serve(context.Background()); err == nil {
		t.Fatal("accepted public directory")
	}
	s := startTestReceiver(t, reg, nil)
	dialTest(t, s.path, true)
	s.cancel()
	select {
	case err := <-s.done:
		s.done <- err
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection blocked cancellation")
	}
}
