//go:build linux

package runtimeadapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

func probeGatedAdapter(t *testing.T, ctx context.Context, s Runsc, root, rootfs, executable string, records func() []seccheck.Record) {
	t.Helper()
	s.GateBinary, s.Options.AllowShell = executable, true
	r := testRequest()
	r.Target = s.Binding.Target
	r.OperationID, r.AttemptID = "gated-success", "gated-success-1"
	r.Command.Command = []string{"/bin/true"}
	persist := func(name string, e Execution) error {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.Write(raw); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		dir, err := os.Open(root)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	var checkpoint Execution
	result, err := s.Run(ctx, r, func(e Execution) error {
		checkpoint = e
		if e.SentryPID <= 0 || e.SentryStartNS <= 0 || e.GateReleased || e.Started {
			return errors.New("gate was not closed at identity checkpoint")
		}
		return persist("adapter-gate-checkpoint.json", e)
	})
	if err != nil || result.State != "succeeded" || !result.GateReleased || !result.Started || result.SentryStartNS != checkpoint.SentryStartNS {
		t.Fatalf("controlled adapter success: %+v %v", result, err)
	}
	if err := persist("adapter-gate-success.json", result); err != nil {
		t.Fatal(err)
	}
	matched := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, rec := range records() {
			if rec.Packet == nil || rec.Packet.Context == nil {
				continue
			}
			c := rec.Packet.Context
			if info, ok := rec.Packet.Message.(*wire.ExecveInfo); ok && len(info.Argv) > 0 && info.Argv[0] == "/bin/true" && c.ThreadGroupId == result.SentryPID && c.ThreadGroupStartTimeNs == result.SentryStartNS {
				matched = true
			}
		}
		if matched {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !matched {
		t.Fatal("controlled adapter identity did not reach the exact native exec")
	}
	marker := "/tmp/agentprov-denied-" + filepath.Base(root)
	r.OperationID, r.AttemptID = "gated-denied", "gated-denied-1"
	r.Command.Command = []string{"/bin/sh", "-c", "printf forbidden > " + marker}
	denied, err := s.Run(ctx, r, func(Execution) error { return errors.New("fixture checkpoint write failure") })
	if err == nil || denied.Started || denied.GateReleased || denied.State != "failed" {
		t.Fatalf("checkpoint failure launched workload: %+v %v", denied, err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, strings.TrimPrefix(marker, "/"))); !os.IsNotExist(err) {
		t.Fatal("denied workload wrote its file")
	}
	if err := persist("adapter-gate-denied.json", denied); err != nil {
		t.Fatal(err)
	}
	r.OperationID, r.AttemptID = "gated-cancel", "gated-cancel-1"
	r.Command.Command = []string{"/bin/sleep", "30"}
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	observer := make(chan bool, 1)
	cancelled, err := s.Run(cancelCtx, r, func(e Execution) error {
		if err := persist("adapter-gate-cancel-checkpoint.json", e); err != nil {
			return err
		}
		go func() {
			defer cancel()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				for _, rec := range records() {
					if rec.Packet == nil || rec.Packet.Context == nil {
						continue
					}
					c := rec.Packet.Context
					if info, ok := rec.Packet.Message.(*wire.ExecveInfo); ok && len(info.Argv) > 0 && info.Argv[0] == "/bin/sleep" && c.ThreadGroupId == e.SentryPID && c.ThreadGroupStartTimeNs == e.SentryStartNS {
						observer <- true
						return
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			observer <- false
		}()
		return nil
	})
	if err == nil || cancelled.State != "unknown" || !cancelled.GateReleased || !cancelled.Started || cancelled.ExitCode != nil {
		t.Fatalf("controlled cancellation: %+v %v", cancelled, err)
	}
	if !<-observer {
		t.Fatal("cancellation occurred before the controlled workload was observed")
	}
	if err := persist("adapter-gate-cancelled.json", cancelled); err != nil {
		t.Fatal(err)
	}
}
