//go:build linux && (amd64 || arm64)

package seccheck

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReceiverRecoversStaleEndpoint(t *testing.T) {
	dir, err := os.MkdirTemp("", "ap-sc-recover-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "events.sock")
	old, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ready, gap := false, false
	r := Receiver{SocketPath: path, Registration: testRegistration(), Ready: func() error { ready = true; cancel(); return nil }, Sink: func(_ context.Context, rec Record) error {
		if rec.Reason == "stale_endpoint_recovered" {
			gap = rec.Kind == "stream" && rec.ConnectionID != "" && !rec.ReceivedAt.IsZero() && rec.DroppedDelta == nil
		}
		return nil
	}}
	if err := r.Serve(ctx); !errors.Is(err, context.Canceled) || !ready || !gap {
		t.Fatalf("stale endpoint recovery: ready=%v gap=%v err=%v", ready, gap, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("recovered endpoint retained: %v", err)
	}
}

func TestReceiverPreservesExistingEndpoints(t *testing.T) {
	for _, kind := range []string{"active", "regular", "symlink", "lock-symlink", "locked", "gap-sink-failure"} {
		t.Run(kind, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "ap-sc-owned-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "events.sock")
			if kind == "active" || kind == "gap-sink-failure" {
				ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
				if err != nil {
					t.Fatal(err)
				}
				ln.SetUnlinkOnClose(false)
				defer ln.Close()
				if kind == "gap-sink-failure" {
					ln.Close()
				}
			} else if kind == "regular" {
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if kind == "locked" {
				lock, err := lockEndpoint(path + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			} else {
				target := filepath.Join(dir, "keep")
				if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				link := path
				if kind == "lock-symlink" {
					link += ".lock"
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(path)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			failure := errors.New("cannot persist restart gap")
			r := Receiver{SocketPath: path, Registration: testRegistration(), Sink: func(context.Context, Record) error { return failure }}
			err = r.Serve(ctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unsafe startup: %v", err)
			}
			if kind == "gap-sink-failure" {
				if !errors.Is(err, failure) {
					t.Fatalf("gap persistence failure hidden: %v", err)
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("failed listener retained: %v", err)
				}
			} else if before != nil {
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("existing endpoint replaced: %v", err)
				}
			}
		})
	}
}
