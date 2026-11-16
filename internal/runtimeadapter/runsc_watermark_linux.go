//go:build linux

package runtimeadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimegate"
)

// ObserveProcesses uses the task set returned by `ps`, including zombies. The
// procfs dump alone omits exiting processes without an MM and is never used as
// absence evidence. A reused PID stays active unless its other birth is known.
func (s Runsc) ObserveProcesses(ctx context.Context, processes []SentryProcess) (ProcessDrain, error) {
	r := ProcessDrain{ObservedAt: time.Now().UTC(), Basis: "runsc_ps_root_taskset", Remaining: []SentryProcess{}}
	if len(processes) == 0 || len(processes) > 4096 {
		return r, fmt.Errorf("invalid command process scope")
	}
	before, err := readRunscLifecycle(s.Config.Root, s.Config.ContainerID)
	if err != nil || before.CreatedAt != s.Config.StateCreated {
		return r, fmt.Errorf("runtime lifecycle changed before task observation")
	}
	raw, err := s.control(ctx, "--root="+s.Config.Root, "ps", "--format=json", s.Config.ContainerID)
	if err != nil {
		return r, err
	}
	// The pinned OCI ps JSON format is a list of numeric PIDs, not process
	// objects (runsc/cmd/ps.go calls controlapi.PrintPIDsJSON).
	var live []int32
	if err := json.Unmarshal(raw, &live); err != nil || live == nil || len(live) > 8192 {
		return r, fmt.Errorf("invalid runtime task-set response")
	}
	pids := map[int32]bool{}
	for _, p := range live {
		if p <= 0 || pids[p] {
			return r, fmt.Errorf("invalid runtime task-set identity")
		}
		pids[p] = true
	}
	for _, p := range processes {
		if p.PID <= 0 || p.StartNS <= 0 {
			return r, fmt.Errorf("invalid owned process identity")
		}
		if pids[p.PID] {
			birth, err := s.processBirth(ctx, p.PID)
			if err != nil || birth == p.StartNS {
				r.Remaining = append(r.Remaining, p)
			}
		}
	}
	after, err := readRunscLifecycle(s.Config.Root, s.Config.ContainerID)
	if err != nil || after.CreatedAt != before.CreatedAt {
		return r, fmt.Errorf("runtime lifecycle changed during task observation")
	}
	r.Empty = len(r.Remaining) == 0
	return r, nil
}

// Barrier uses the same trusted executable FD and birth-before-release gate.
// Successful transport exit alone does not establish receiver ingestion.
func (s Runsc) Barrier(ctx context.Context, runID string) (RuntimeBarrier, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return RuntimeBarrier{}, err
	}
	id := hex.EncodeToString(nonce[:])
	marker := "/.agentprov-watermark-" + id
	r := Request{Target: s.Binding.Target, OperationID: "watermark-" + id, AttemptID: "watermark-" + id,
		Command: record.Request{RunID: runID, Command: []string{marker}, Workdir: s.Config.Workdir, DisableSnapshot: true}}
	if err := s.Admit(ctx, r); err != nil {
		return RuntimeBarrier{}, err
	}
	var barrier RuntimeBarrier
	_, err := s.runPrivateGate(ctx, r, func(e Execution) error {
		barrier = RuntimeBarrier{Process: SentryProcess{PID: e.SentryPID, StartNS: e.SentryStartNS}, Marker: marker}
		return nil
	}, runtimegate.WatermarkEntry)
	return barrier, err
}
