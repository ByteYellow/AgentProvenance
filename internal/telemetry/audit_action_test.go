package telemetry

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Both calls fit within the same audit timestamp precision. The syscall
// collector only sees the allowed call; proximity must not lend its result to
// the seccomp decision for the other call.
func TestAuditSeccompBlockedActionsNeverBorrowAdjacentResult(t *testing.T) {
	actions := map[string]uint32{"ERRNO": 0x00050001, "KILL_PROCESS": 0x80000000,
		"KILL_THREAD": 0, "TRAP": 0x00030000, "TRACE": 0x7ff00000, "USER_NOTIF": 0x7fc00000}
	for action, code := range actions {
		for _, order := range []string{"allow_then_deny", "deny_then_allow"} {
			for _, variation := range []string{"same_thread", "other_thread", "late", "duplicate", "missing_entry", "missing_result", "thread_reused"} {
				t.Run(action+"/"+order+"/"+variation, func(t *testing.T) {
					a := auditInputFixture(t)
					a.record.Decision, a.record.ActionCode = action, &code
					events := auditRuntimeSet()
					if order == "deny_then_allow" {
						for i := 1; i <= 2; i++ {
							events[i].at = events[i].at.Add(500 * time.Microsecond)
							events[i].fields.Monotonic = fmt.Sprint(events[i].mono + 500000)
							events[i].fields.SyscallStart = "10000600000"
							events[i].fields.OperationID = "syscall-v1:" + events[i].fields.Thread + ":42:1000000000:10000600000"
						}
					}
					switch variation {
					case "other_thread", "thread_reused":
						for i := 1; i <= 2; i++ {
							if variation == "other_thread" {
								events[i].fields.TID = 44
							} else {
								events[i].fields.ThreadStart = "2000000000"
							}
							events[i].fields.Thread = fmt.Sprintf("%s:%d:%s", associationBoot, events[i].fields.TID, events[i].fields.ThreadStart)
							events[i].fields.OperationID = "syscall-v1:" + events[i].fields.Thread + ":42:1000000000:" + events[i].fields.SyscallStart
						}
					case "late":
						events[0], events[3] = events[3], events[0]
					case "duplicate":
						events = append(events, events[1], events[2])
					case "missing_entry":
						events = append(events[:1], events[2:]...)
					case "missing_result":
						events = append(events[:2], events[3:]...)
					}
					got := associateAudit(a, indexAuditRuntime(events))
					if got.Process.Status != "inferred" {
						t.Fatalf("process evidence lost: %+v", got.Process)
					}
					if got.Operation.Status != "unassociated" || len(got.Operations) != 0 || got.Operation.CandidateCount != 0 {
						t.Fatalf("%s borrowed adjacent executed syscall: %+v", action, got)
					}
				})
			}
		}
	}
}

func TestAuditSeccompLOGAndAppArmorRemainCandidateEvidence(t *testing.T) {
	events := auditRuntimeSet()
	nr, result := int64(56), int64(-13)
	for i := 1; i <= 2; i++ {
		events[i].fields.Operation, events[i].fields.SyscallNumber, events[i].fields.Path = "file_open", &nr, "/fixture/secret"
	}
	events[1].etype = "file_open"
	events[2].fields.Result, events[2].fields.Outcome = &result, "failure"
	log := auditInputFixture(t)
	log.record.SyscallNumber = &nr
	aa := log
	aa.id, aa.record.Mechanism, aa.record.Decision, aa.record.Operation, aa.record.Target = "apparmor", "apparmor", "DENIED", "open", "/fixture/secret"
	for _, input := range []auditAssociationInput{log, aa} {
		got := associateAudit(input, indexAuditRuntime(events))
		if got.Operation.Status != "inferred" || len(got.Operations) != 1 || got.Operations[0].Result == nil || *got.Operations[0].Result != -13 {
			t.Fatalf("positive candidate evidence lost: %+v", got)
		}
		if got.Operation.Basis != "lifetime_syscall_time_candidate" || got.Operation.Reason != "shared_call_identity_unavailable" {
			t.Fatalf("time-only association must disclose its basis: %+v", got.Operation)
		}
		if !reflect.DeepEqual(got.Operations[0].ResultRefs, []string{"runtime_event/result"}) {
			t.Fatal("source result ref lost")
		}
	}
}
