package telemetry

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"time"
)

type auditRuntimeFields struct {
	CoarseClockNS int64  `json:"realtime_coarse_resolution_ns"`
	HostID        string `json:"host_id"`
	BootID        string `json:"boot_id"`
	Instance      string `json:"process_instance_id"`
	Start         string `json:"process_start_ns"`
	Monotonic     string `json:"monotonic_ns"`
	TID           int64  `json:"tid"`
	Thread        string `json:"thread_instance_id"`
	ThreadStart   string `json:"thread_start_ns"`
	OperationID   string `json:"operation_id"`
	Operation     string `json:"operation"`
	Stage         string `json:"observation_stage"`
	SyscallStart  string `json:"syscall_start_ns"`
	SyscallNumber *int64 `json:"syscall_number"`
	Arch          string `json:"sensor_arch"`
	Path          string `json:"path"`
	Comm          string `json:"comm"`
	Result        *int64 `json:"syscall_result"`
	Outcome       string `json:"syscall_outcome"`
	ExitScope     string `json:"exit_scope"`
}

type auditRuntime struct {
	id, etype string
	pid       int64
	at        time.Time
	mono      uint64
	fields    auditRuntimeFields
	context   AuditContextRef
}

type auditOrigin struct {
	host, boot string
	pid        int64
}

type auditLifetime struct {
	id         string
	points     []auditRuntime
	exits      []string
	clockIssue bool
	operations []*auditOperationGroup
}

type auditRuntimeIndex struct {
	lifetimes map[auditOrigin][]*auditLifetime
	unscoped  map[int64][]auditRuntime
	clocks    map[auditOrigin]int64
}

type auditOperationGroup struct {
	view     AuditOperation
	first    auditRuntimeFields
	from, to time.Time
	conflict bool
	refs     []string
	attempts map[string]bool
	results  map[string]bool
}

func indexAuditRuntime(events []auditRuntime) auditRuntimeIndex {
	index := auditRuntimeIndex{lifetimes: map[auditOrigin][]*auditLifetime{}, unscoped: map[int64][]auditRuntime{}, clocks: map[auditOrigin]int64{}}
	type key struct {
		origin auditOrigin
		id     string
	}
	lives := map[key]*auditLifetime{}
	for _, e := range events {
		f := e.fields
		instance := canonicalProcessInstance(f.Instance, e.pid)
		e.mono, _ = strconv.ParseUint(f.Monotonic, 10, 64)
		start, _ := strconv.ParseUint(f.Start, 10, 64)
		if instance == "" || f.HostID == "" || e.at.IsZero() || e.mono == 0 || start == 0 || start > e.mono ||
			instance != fmt.Sprintf("%s:%d:%d", normalizeAuditBoot(f.BootID), e.pid, start) {
			index.unscoped[e.pid] = append(index.unscoped[e.pid], e)
			continue
		}
		k := key{auditOrigin{f.HostID, normalizeAuditBoot(f.BootID), e.pid}, instance}
		if f.CoarseClockNS > 0 && f.CoarseClockNS <= int64(time.Second) {
			if prev := index.clocks[k.origin]; prev == 0 || prev == f.CoarseClockNS {
				index.clocks[k.origin] = f.CoarseClockNS
			} else {
				index.clocks[k.origin] = -1
			}
		}
		life := lives[k]
		if life == nil {
			life = &auditLifetime{id: instance}
			lives[k] = life
			index.lifetimes[k.origin] = append(index.lifetimes[k.origin], life)
		}
		life.points = append(life.points, e)
	}
	for _, life := range lives {
		sort.Slice(life.points, func(i, j int) bool {
			a, b := life.points[i], life.points[j]
			return a.mono < b.mono || (a.mono == b.mono && a.id < b.id)
		})
		ops := map[string]*auditOperationGroup{}
		var exitMono uint64
		for i, e := range life.points {
			if i > 0 && e.at.Before(life.points[i-1].at) && life.points[i-1].at.Sub(e.at) > time.Millisecond {
				life.clockIssue = true
			}
			if exitMono != 0 && e.mono > exitMono {
				life.clockIssue = true // observation after the same lifetime's final exit
			}
			if e.etype == "process_exit" && e.fields.ExitScope == "thread_group" {
				life.exits = append(life.exits, "runtime_event/"+e.id)
				exitMono = e.mono
			}
			if validAuditOperation(e) {
				group := ops[e.fields.OperationID]
				if group == nil {
					group = &auditOperationGroup{first: e.fields, from: e.at, to: e.at, attempts: map[string]bool{}, results: map[string]bool{},
						view: AuditOperation{ID: e.fields.OperationID, ProcessInstance: life.id,
							ThreadInstance: e.fields.Thread, Kind: e.fields.Operation, AttemptState: "not_observed", ResultState: "not_observed"}}
					ops[e.fields.OperationID] = group
				}
				group.add(e)
			}
		}
		for _, op := range ops {
			op.finish()
			life.operations = append(life.operations, op)
		}
		sort.Slice(life.operations, func(i, j int) bool { return life.operations[i].view.ID < life.operations[j].view.ID })
		sort.Strings(life.exits)
	}
	for _, lives := range index.lifetimes {
		sort.Slice(lives, func(i, j int) bool { return lives[i].id < lives[j].id })
	}
	return index
}

func validAuditOperation(e auditRuntime) bool {
	f := e.fields
	thread := canonicalProcessInstance(f.Thread, f.TID)
	start, _ := strconv.ParseUint(f.SyscallStart, 10, 64)
	threadStart, _ := strconv.ParseUint(f.ThreadStart, 10, 64)
	if thread == "" || thread != fmt.Sprintf("%s:%d:%d", normalizeAuditBoot(f.BootID), f.TID, threadStart) ||
		start == 0 || start > e.mono || threadStart > start || f.SyscallNumber == nil || *f.SyscallNumber < 0 ||
		(f.Arch != "arm64" && f.Arch != "amd64") || (f.Operation != "file_open" && f.Operation != "network_connect") {
		return false
	}
	if f.OperationID != fmt.Sprintf("syscall-v1:%s:%d:%s:%d", thread, e.pid, f.Start, start) {
		return false
	}
	switch f.Stage {
	case "attempt":
		return true
	case "result", "attempt_and_result":
		return f.Result != nil
	}
	return false
}

func (op *auditOperationGroup) add(e auditRuntime) {
	f := e.fields
	if f.Path != op.first.Path || f.Comm != op.first.Comm || f.Arch != op.first.Arch ||
		*f.SyscallNumber != *op.first.SyscallNumber || f.Operation != op.first.Operation {
		op.conflict = true
	}
	start, _ := strconv.ParseUint(f.SyscallStart, 10, 64)
	if e.mono-start > math.MaxInt64 {
		op.conflict = true
		return
	}
	from := e.at.Add(-time.Duration(e.mono - start))
	if from.Before(op.from) {
		op.from = from
	}
	if e.at.After(op.to) {
		op.to = e.at
	}
	ref := "runtime_event/" + e.id
	op.refs = append(op.refs, ref)
	if f.Stage == "attempt" || f.Stage == "attempt_and_result" {
		op.attempts[ref] = true
	}
	if f.Stage == "result" || f.Stage == "attempt_and_result" {
		op.results[ref] = true
		if op.view.Result != nil && (*op.view.Result != *f.Result || op.view.Outcome != f.Outcome) {
			op.conflict = true
		}
		op.view.Result, op.view.Outcome = f.Result, f.Outcome
	}
	if e.context.SessionID != "" || e.context.ToolCallID != "" {
		op.view.Context = append(op.view.Context, e.context)
	}
}

func (op *auditOperationGroup) finish() {
	for ref := range op.attempts {
		op.view.AttemptRefs = append(op.view.AttemptRefs, ref)
	}
	for ref := range op.results {
		op.view.ResultRefs = append(op.view.ResultRefs, ref)
	}
	op.view.AttemptCount, op.view.ResultCount = len(op.attempts), len(op.results)
	if op.view.AttemptCount > 0 {
		op.view.AttemptState = "observed"
	}
	if op.view.ResultCount > 0 {
		op.view.ResultState = "observed"
	}
	if op.conflict {
		op.view.AttemptState, op.view.ResultState = "conflicting", "conflicting"
		op.view.Result, op.view.Outcome = nil, ""
	}
	op.view.RefsTruncated = len(op.refs) > maxAuditCandidates || len(op.view.Context) > maxAuditCandidates
	op.refs = auditLimitedRefs(op.refs)
	op.view.AttemptRefs = auditLimitedRefs(op.view.AttemptRefs)
	op.view.ResultRefs = auditLimitedRefs(op.view.ResultRefs)
	sort.Slice(op.view.Context, func(i, j int) bool { return op.view.Context[i].EventID < op.view.Context[j].EventID })
	if len(op.view.Context) > maxAuditCandidates {
		op.view.Context = op.view.Context[:maxAuditCandidates]
	}
}

func auditLimitedRefs(refs []string) []string {
	sort.Strings(refs)
	if len(refs) > maxAuditCandidates {
		return refs[:maxAuditCandidates]
	}
	return refs
}

func auditUnknown(reason string) AuditAssociation {
	return AuditAssociation{Status: "unassociated", Reason: reason}
}

func associateAudit(input auditAssociationInput, index auditRuntimeIndex) AuditAssociationItem {
	a := input.record
	item := AuditAssociationItem{EventID: input.id, Source: a.AuditSource, Mechanism: a.Mechanism, Decision: a.Decision,
		Process: auditUnknown("process_lifetime_not_observed"), Operation: auditUnknown("process_not_associated"), EvidenceScope: "saved_records_only"}
	if a.EvidenceKind != "audit_decision" {
		item.Process, item.Operation = auditUnknown("status_record"), auditUnknown("status_record")
		return item
	}
	if a.HostID == "" || a.BootID == "" || a.AuditPID == nil || *a.AuditPID <= 0 || a.PIDSemantics != "host_thread_group" {
		item.Process = auditUnknown("missing_source_or_process_identity")
		return item
	}
	from, err := time.Parse(time.RFC3339Nano, a.Timestamp)
	if err != nil || a.TimestampPrecisionNS <= 0 || a.TimestampPrecisionNS > int64(time.Second) {
		item.Process = auditUnknown("invalid_audit_time")
		return item
	}
	origin := auditOrigin{a.HostID, normalizeAuditBoot(a.BootID), *a.AuditPID}
	resolution := index.clocks[origin]
	if resolution <= 0 {
		item.Process = auditUnknown("source_clock_resolution_unknown")
		if resolution < 0 {
			item.Process.Reason = "source_clock_resolution_conflict"
		}
		return item
	}
	// Linux syscall audit contexts use CLOCK_REALTIME_COARSE. Header decimal
	// precision alone understates the possible age of that timestamp. The
	// source kernel's measured clock resolution widens the candidate interval;
	// it is never substituted with the importing host's clock or a fixed delay.
	to := from.Add(time.Duration(a.TimestampPrecisionNS + resolution))
	item.TimeWindow = &AuditTimeWindow{from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano),
		a.TimestampPrecisionNS, resolution, "audit_decimal_plus_source_coarse_clock"}
	for _, e := range index.unscoped[*a.AuditPID] {
		if !e.at.IsZero() && !e.at.Before(from) && e.at.Before(to) &&
			(e.fields.HostID == "" || e.fields.HostID == a.HostID) && (e.fields.BootID == "" || normalizeAuditBoot(e.fields.BootID) == a.BootID) {
			item.Process = auditUnknown("runtime_lifetime_incomplete")
			return item
		}
	}
	lives := index.lifetimes[origin]
	var matched []*auditLifetime
	for _, life := range lives {
		refs, ok, clockIssue := life.bracket(from, to)
		if clockIssue {
			item.Process = auditUnknown("runtime_clock_or_lifetime_conflict")
			return item
		}
		if ok {
			matched = append(matched, life)
			item.Process.Candidates = append(item.Process.Candidates, AuditCandidate{life.id, refs})
		}
	}
	item.Process = finishAuditAssociation(item.Process.Candidates, "host_boot_lifetime_bracket", "process_lifetime_not_observed")
	if len(matched) != 1 {
		if len(matched) > 1 {
			item.Operation.Reason = "process_lifetime_ambiguous"
		}
		return item
	}
	life := matched[0]
	item.ProcessExits = auditLimitedRefs(append([]string(nil), life.exits...))
	if reason := auditExecutionCompatibility(a); reason != "" {
		item.Operation = auditUnknown(reason)
		return item
	}
	var candidates []AuditCandidate
	conflict := false
	for _, op := range life.operations {
		if !op.matches(a, from, to) {
			continue
		}
		candidates = append(candidates, AuditCandidate{op.view.ID, op.refs})
		if len(item.Operations) < maxAuditCandidates {
			item.Operations = append(item.Operations, op.view)
		}
		conflict = conflict || op.conflict
	}
	item.Operation = finishAuditAssociation(candidates, "lifetime_syscall_time_candidate", "compatible_operation_not_observed")
	if item.Operation.Status == "inferred" {
		item.Operation.Reason = "shared_call_identity_unavailable"
	}
	if conflict {
		item.Operation.Status, item.Operation.Reason = "ambiguous", "conflicting_operation_records"
	}
	return item
}

// These candidates come from the normal syscall entry/return collector, not
// from seccomp mediation. Suppressed calls never enter that execution path.
// TRACE and USER_NOTIF can replace or skip the call and require mediation
// evidence with a shared call identity, which this collector does not have.
func auditExecutionCompatibility(a AuditRecord) string {
	if a.Mechanism != "seccomp" {
		return ""
	}
	switch a.Decision {
	case "ERRNO", "KILL_PROCESS", "KILL_THREAD", "TRAP":
		return "seccomp_original_syscall_not_executed"
	case "TRACE", "USER_NOTIF":
		return "seccomp_mediation_evidence_unavailable"
	case "LOG", "ALLOW":
		if a.ActionCode == nil {
			return "seccomp_action_unknown"
		}
		want := uint32(0x7ffc0000)
		if a.Decision == "ALLOW" {
			want = 0x7fff0000
		}
		if *a.ActionCode&0xffff0000 != want {
			return "seccomp_action_conflict"
		}
		return ""
	default:
		return "seccomp_action_unknown"
	}
}

func finishAuditAssociation(candidates []AuditCandidate, basis, empty string) AuditAssociation {
	association := AuditAssociation{Basis: basis, CandidateCount: len(candidates)}
	switch len(candidates) {
	case 0:
		return auditUnknown(empty)
	case 1:
		association.Status = "inferred"
	default:
		association.Status, association.Reason = "ambiguous", "multiple_candidates"
	}
	if len(candidates) > maxAuditCandidates {
		candidates, association.CandidatesTruncated = candidates[:maxAuditCandidates], true
	}
	association.Candidates = candidates
	return association
}

// Require observations of the same kernel lifetime on both sides of the
// audit interval. Its recorded decimal precision is an interval, not a point.
// A wall-clock/monotonic disagreement rejects the join instead of extrapolating
// a process lifetime from a PID binding's start time.
func (life *auditLifetime) bracket(from, to time.Time) ([]string, bool, bool) {
	points := life.points
	if len(points) < 2 || !points[0].at.Before(to) || points[len(points)-1].at.Before(from) {
		return nil, false, false
	}
	if life.clockIssue {
		return nil, false, true
	}
	lo, hi := 0, len(points)-1
	for i, e := range points {
		if e.at.Before(from) {
			lo = i
		}
		if !e.at.Before(to) {
			hi = i
			break
		}
	}
	a, b := points[lo], points[hi]
	if a.mono >= b.mono || b.mono-a.mono > math.MaxInt64 {
		return nil, false, true
	}
	delta := b.at.Sub(a.at) - time.Duration(b.mono-a.mono)
	if delta > 2*time.Millisecond || delta < -2*time.Millisecond {
		return nil, false, true
	}
	return []string{"runtime_event/" + a.id, "runtime_event/" + b.id}, true, false
}

func (op *auditOperationGroup) matches(a AuditRecord, from, to time.Time) bool {
	if !op.from.Before(to) || op.to.Before(from) {
		return false
	}
	if a.Comm != "" && op.first.Comm != "" && a.Comm != op.first.Comm {
		return false
	}
	switch a.Mechanism {
	case "seccomp":
		abi := map[string]string{"arm64": "aarch64", "amd64": "x86_64"}[op.first.Arch]
		return a.ABI == abi && a.SyscallNumber != nil && *a.SyscallNumber == *op.first.SyscallNumber
	case "apparmor":
		// No path reconstruction, namespace guessing or substring match. Other
		// AppArmor operation classes can still have a process-level association.
		return a.Operation == "open" && op.view.Kind == "file_open" && path.IsAbs(a.Target) &&
			len(op.first.Path) < 255 && a.Target == op.first.Path
	}
	return false
}
