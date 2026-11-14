//go:build linux && (amd64 || arm64)

package seccheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"golang.org/x/sys/unix"
)

// Serve owns a private per-sandbox endpoint. Only one connection may be active;
// reconnects get new IDs while the externally registered lifetime stays fixed.
func (r Receiver) Serve(ctx context.Context) error {
	if err := r.Registration.Validate(); err != nil {
		return err
	}
	if r.Sink == nil {
		return fmt.Errorf("SecCheck sink is required")
	}
	if !filepath.IsAbs(r.SocketPath) || len(r.SocketPath) >= 108 {
		return fmt.Errorf("invalid SecCheck socket path")
	}
	dir, err := os.Lstat(filepath.Dir(r.SocketPath))
	if err != nil {
		return err
	}
	stat, ok := dir.Sys().(*syscall.Stat_t)
	if !dir.IsDir() || dir.Mode().Perm()&0o077 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("SecCheck socket directory must be private and owned by the receiver")
	}
	if r.HandshakeTimeout == 0 {
		r.HandshakeTimeout = 5 * time.Second
	}
	if r.HandshakeTimeout <= 0 || r.HandshakeTimeout > time.Minute {
		return fmt.Errorf("invalid SecCheck handshake timeout")
	}
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: r.SocketPath, Net: "unixpacket"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	defer ln.Close()
	socketInfo, err := os.Lstat(r.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		if now, err := os.Lstat(r.SocketPath); err == nil && os.SameFile(socketInfo, now) {
			_ = os.Remove(r.SocketPath)
		}
	}()
	if err := os.Chmod(r.SocketPath, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	var sinkMu sync.Mutex
	emit := func(rec Record) error {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		return r.Sink(ctx, rec)
	}
	active := make(chan struct{}, 1)
	fatal := make(chan error, 1)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				select {
				case err := <-fatal:
					return err
				default:
					return ctx.Err()
				}
			}
			cancel()
			return err
		}
		select {
		case active <- struct{}{}:
		default:
			_ = conn.Close()
			// The active stream is never replaced by a competing connection.
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-active }()
			defer conn.Close()
			if err := r.receive(ctx, conn, emit); err != nil {
				select {
				case fatal <- err:
				default:
				}
				cancel()
			}
		}()
	}
}

func (r Receiver) receive(ctx context.Context, conn *net.UnixConn, emit func(Record) error) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var credentials *unix.Ucred
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	rec := Record{Registration: r.Registration, ConnectionID: ids.New("secconn"), PeerPID: credentials.Pid}
	notice := func(reason string) error {
		rec.Kind, rec.Reason, rec.ReceivedAt = "stream", reason, time.Now().UTC()
		rec.Identity = Identity{}
		rec.Packet, rec.DroppedDelta, rec.DropCounterDecreased = nil, nil, false
		return emit(rec)
	}
	if credentials.Uid != r.Registration.PeerUID {
		return notice("peer_uid_rejected")
	}
	if err := conn.SetDeadline(time.Now().Add(r.HandshakeTimeout)); err != nil {
		return err
	}
	handshake := make([]byte, MaxHandshakeBytes)
	n, _, flags, _, err := conn.ReadMsgUnix(handshake, nil)
	if err != nil {
		return notice("handshake_read_failed")
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return notice("handshake_truncated")
	}
	reply, err := HandshakeReply(handshake[:n])
	if err != nil {
		return notice("handshake_rejected")
	}
	if n, err := conn.Write(reply); err != nil || n != len(reply) {
		return notice("handshake_write_failed")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	rec.ProtocolVersion = ProtocolVersion
	if err := notice("connected"); err != nil {
		return err
	}
	buffer := make([]byte, MaxPacketBytes)
	var previousDrops uint32
	for {
		n, _, flags, _, err = conn.ReadMsgUnix(buffer, nil)
		rec.Sequence++
		if err != nil {
			reason := "read_failed"
			if errors.Is(err, io.EOF) {
				reason = "disconnected"
			}
			if ctx.Err() != nil {
				return nil
			}
			return notice(reason)
		}
		if n == 0 {
			return notice("disconnected")
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return notice("packet_truncated")
		}
		p, err := DecodePacket(buffer[:n])
		if err != nil {
			if err := notice("invalid_packet"); err != nil {
				return err
			}
			continue
		}
		rec.Kind, rec.Reason, rec.ReceivedAt = "event", "", time.Now().UTC()
		rec.Identity = Identity{}
		rec.Packet, rec.DroppedDelta, rec.DropCounterDecreased = &p, nil, p.Header.DroppedCount < previousDrops
		if !rec.DropCounterDecreased {
			delta := uint64(p.Header.DroppedCount - previousDrops)
			rec.DroppedDelta = &delta
		}
		previousDrops = p.Header.DroppedCount
		if p.Message == nil {
			rec.Kind, rec.Reason = "stream", "unsupported_message_type"
		} else {
			id, err := IdentityFor(r.Registration, p.Context)
			if err != nil {
				rec.Kind, rec.Reason = "stream", "container_identity_rejected"
				// Retain only the digest/header, never foreign payload contents.
				p.Message, p.Context = nil, nil
			} else {
				rec.Identity = id
			}
		}
		if err := emit(rec); err != nil {
			return err
		}
	}
}
