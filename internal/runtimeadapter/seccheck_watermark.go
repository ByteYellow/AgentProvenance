package runtimeadapter

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type CommandWatermark struct {
	Root            SentryProcess  `json:"root"`
	Drain           ProcessDrain   `json:"drain"`
	Barrier         RuntimeBarrier `json:"barrier"`
	BarrierEventRef string         `json:"barrier_event_ref"`
	BarrierSequence uint64         `json:"barrier_sequence"`
	CloneEventRefs  []string       `json:"clone_event_refs"`
	ProcessCount    int            `json:"process_count"`
	EventCount      int            `json:"event_count"`
	RootWaitStatus  int32          `json:"root_wait_status"`
	Basis           string         `json:"basis"`
}

func (s SecCheck) FinishCommand(ctx context.Context, request Request, execution Execution, start CapturePoint) CaptureReport {
	r := s.Finish(ctx, request.Target, start)
	if s.ReadEvents == nil || s.ObserveProcesses == nil || s.Barrier == nil {
		return r
	}
	if !execution.Matches(request) || !execution.GateReleased || execution.SentryPIDBasis != "private_exec_fd_gate_and_runsc_procfs" || execution.SentryPID <= 0 || execution.SentryStartNS <= 0 {
		return r
	}
	// The shared command identity is now known even if the receiver fails later.
	r.Gaps = []string{"command_capture_watermark_unavailable"}
	fail := func(gap string, err error) CaptureReport {
		r.Gaps = append(r.Gaps, gap)
		if err != nil {
			r.Error = err.Error()
		}
		return r
	}
	if start.Target != request.Target || start.Scope != s.Receiver || len(start.Status.Targets) != 1 {
		return fail("capture_target_mismatch", nil)
	}
	first := start.Status.Targets[0]
	if first.LastSequence == nil || *first.LastSequence == math.MaxUint64 {
		return fail("receiver_sequence_unavailable", nil)
	}
	root := SentryProcess{PID: execution.SentryPID, StartNS: execution.SentryStartNS}
	next := *first.LastSequence + 1
	var events []telemetry.EventRecord
	var pending *RuntimeBarrier
	var drain ProcessDrain
	var drainedProcesses []SentryProcess
	bytes := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fail("command_capture_deadline", err)
		}
		end, err := s.Probe(ctx, request.Target)
		if err != nil {
			return fail("receiver_unavailable", err)
		}
		r.End = &end
		last := end.Status.Targets[0]
		if end.Status.CollectorID != start.Status.CollectorID || last.ConnectionID != first.ConnectionID {
			return fail("receiver_reconnected", nil)
		}
		if last.LastSequence == nil || *last.LastSequence < *first.LastSequence || last.AcceptedRecords < first.AcceptedRecords ||
			last.ReportedDrops != first.ReportedDrops || last.DropCounterDecreases != first.DropCounterDecreases || last.IdentityGapRecords != first.IdentityGapRecords {
			return fail("receiver_loss_or_identity_gap", nil)
		}
		for next <= *last.LastSequence {
			count := int(min(uint64(256), *last.LastSequence-next+1))
			page, err := s.ReadEvents(ctx, first.ConnectionID, next, count)
			if err != nil {
				return fail("receiver_evidence_unavailable", err)
			}
			if len(page) > count {
				return fail("receiver_page_invalid", nil)
			}
			for i, event := range page {
				e, err := telemetry.ReadSecCheckEvidence(event)
				if err != nil || e.Sequence != next+uint64(i) {
					return fail("receiver_sequence_gap", err)
				}
				bytes += len(event.Payload)
			}
			if len(events)+len(page) > maxCommandObservations || bytes > maxCommandObservationBytes {
				return fail("command_evidence_budget_exceeded", nil)
			}
			events = append(events, page...)
			if next > math.MaxUint64-uint64(len(page)) {
				return fail("receiver_sequence_overflow", nil)
			}
			next += uint64(len(page))
			if len(page) < count {
				break
			}
		}
		if len(events) > 0 {
			evidence, err := DeriveSecCheckCommand(s.Receiver, first.ConnectionID, root, request.Command.Command, events)
			if err != nil {
				return fail("command_evidence_invalid", err)
			}
			r.Evidence = &evidence
			if pending != nil {
				marker, seq, clones, err := findRuntimeBarrier(events, *pending)
				if err != nil {
					return fail("runtime_barrier_invalid", err)
				}
				if marker != "" {
					if len(clones) == 0 {
						return fail("clone_checkpoint_unobserved", nil)
					}
					if slices.Equal(evidence.Processes, drainedProcesses) && evidence.RootExecRef != "" && evidence.RootWaitStatus != nil {
						r.State, r.Gaps, r.Error = "sealed", []string{}, ""
						r.Command = &CommandWatermark{Root: root, Drain: drain, Barrier: *pending, BarrierEventRef: marker, BarrierSequence: seq,
							CloneEventRefs: clones, ProcessCount: len(evidence.Processes), EventCount: len(evidence.Events), RootWaitStatus: *evidence.RootWaitStatus,
							Basis: "controlled_birth_clone_closure_taskset_absence_and_committed_barrier"}
						for _, event := range events {
							e, _ := telemetry.ReadSecCheckEvidence(event)
							if e.Context != nil && e.Context.GroupID == pending.Process.PID && e.Context.GroupStartNS == pending.Process.StartNS {
								r.Evidence.BoundaryEvents = append(r.Evidence.BoundaryEvents, event)
							}
						}
						r.Evidence.Watermark = r.Command
						return r
					}
					// Late clone evidence expanded the scope; observe that whole
					// scope and put a new barrier after its actual disappearance.
					pending = nil
				}
			}
			if pending == nil && evidence.RootExecRef != "" && evidence.RootWaitStatus != nil {
				drain, err = s.ObserveProcesses(ctx, evidence.Processes)
				if err != nil {
					return fail("runtime_drain_unavailable", err)
				}
				if drain.Empty && len(drain.Remaining) == 0 && drain.Basis == "runsc_ps_root_taskset" {
					barrier, err := s.Barrier(ctx, request.Command.RunID)
					if err != nil {
						return fail("runtime_barrier_unavailable", err)
					}
					pending = &barrier
					drainedProcesses = append([]SentryProcess(nil), evidence.Processes...)
				}
			}
		}
		select {
		case <-ctx.Done():
			return fail("command_capture_deadline", ctx.Err())
		case <-ticker.C:
		}
	}
}

func findRuntimeBarrier(events []telemetry.EventRecord, barrier RuntimeBarrier) (string, uint64, []string, error) {
	if barrier.Process.PID <= 0 || barrier.Process.StartNS <= 0 || barrier.Marker == "" {
		return "", 0, nil, fmt.Errorf("missing barrier identity")
	}
	var marker string
	var sequence uint64
	clones := []string{}
	for _, event := range events {
		e, err := telemetry.ReadSecCheckEvidence(event)
		if err != nil {
			return "", 0, nil, err
		}
		if e.Context == nil || e.Context.GroupID != barrier.Process.PID || e.Context.GroupStartNS != barrier.Process.StartNS {
			continue
		}
		point, err := telemetry.ReadSecCheckPoint(event)
		if err != nil {
			return "", 0, nil, err
		}
		switch wire.MessageType(point.MessageType) {
		case wire.MessageType_MESSAGE_SENTRY_CLONE:
			clones = append(clones, event.ID)
		case wire.MessageType_MESSAGE_SYSCALL_OPEN:
			details, err := telemetry.ReadSecCheckDetails(event)
			if err != nil {
				return "", 0, nil, err
			}
			if details.Path == barrier.Marker && point.Stage == "result" {
				if marker != "" {
					return "", 0, nil, fmt.Errorf("duplicate runtime barrier")
				}
				marker, sequence = event.ID, e.Sequence
			}
		}
	}
	return marker, sequence, clones, nil
}
